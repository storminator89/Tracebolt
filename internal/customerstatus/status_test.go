package customerstatus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/customeradmission"
	"localrmm/internal/customerbudget"
	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
	_ "modernc.org/sqlite"
)

type fixtureClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fixtureClock) read() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fixtureClock) set(v time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.now = v }

type fixtureLease struct {
	check   func() error
	release func()
}

func (l *fixtureLease) Check() error { return l.check() }
func (l *fixtureLease) Release()     { l.release() }
func allow(context.Context, customerclaim.Metadata) (customerpending.AuthorityLease, error) {
	return &fixtureLease{check: func() error { return nil }, release: func() {}}, nil
}

type fixture struct {
	clock  *fixtureClock
	pool   *customerchallenge.Pool
	store  *customerpending.Store
	key    ed25519.PrivateKey
	record customerpending.Record
}

func setup(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	clk := &fixtureClock{now: time.Unix(1790000000, 0).UTC()}
	pool, err := customerchallenge.New(customerchallenge.Binding{ManagerID: "manager_" + strings.Repeat("1", 32), Origin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", IssuerFingerprint: strings.Repeat("a", 64)}, clk.read)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "pending.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if err = customerpending.Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := customerpending.New(db)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := pool.Issue("192.0.2.1", "customer_"+strings.Repeat("2", 32), "profile_"+strings.Repeat("3", 32), "claim_"+strings.Repeat("4", 32))
	if err != nil {
		t.Fatal(err)
	}
	request := "request_" + strings.Repeat("5", 32)
	msg, err := customerclaim.SigningMessage(claim, request, csr, clk.read())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := customerclaim.Encode(claim, request, csr, ed25519.Sign(key, msg), clk.read())
	if err != nil {
		t.Fatal(err)
	}
	admission, err := customeradmission.New(pool, store, clk.read, allow)
	if err != nil {
		t.Fatal(err)
	}
	record, err := admission.Submit(ctx, claim.Challenge, raw)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{clk, pool, store, key, record}
}
func meta(r customerpending.Record) customerclaim.Metadata {
	return customerclaim.Metadata{ManagerID: r.ManagerID, CustomerID: r.CustomerID, InstallerProfileID: r.InstallerProfileID, Origin: r.Origin, AgentOrigin: r.AgentOrigin, IssuerFingerprint: r.IssuerFingerprint, ClaimID: r.ClaimID, RequestID: r.RequestID, KeyFingerprint: r.KeyFingerprint, CSRHash: r.CSRHash, ClaimHash: r.ClaimHash, ComparisonCode: r.ComparisonCode}
}
func (f fixture) request(t *testing.T) (customerclaim.Context, []byte) {
	t.Helper()
	r := f.record
	c, err := f.pool.IssueStatus("192.0.2.1", r.CustomerID, r.InstallerProfileID, r.ClaimID)
	if err != nil {
		t.Fatal(err)
	}
	request := "request_" + strings.Repeat("6", 32)
	msg, err := customerclaim.StatusSigningMessage(c, meta(r), r.PublicKeyDER, request, f.clock.read())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := customerclaim.EncodeStatus(c, meta(r), r.PublicKeyDER, request, ed25519.Sign(f.key, msg), f.clock.read())
	if err != nil {
		t.Fatal(err)
	}
	return c, raw
}

func TestPendingStatusProofAndReplay(t *testing.T) {
	f := setup(t)
	c, raw := f.request(t)
	co, err := New(f.pool, f.store, f.clock.read, allow)
	if err != nil {
		t.Fatal(err)
	}
	var observed customerpending.PendingStatus
	calls := 0
	if err = co.WithStatus(context.Background(), c.Challenge, raw, func(s customerpending.PendingStatus) error { calls++; observed = s; return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || observed.SchemaVersion != "tracebolt.customer-pending-status.v1" || observed.State != "pending" || observed.DeadlineAt != f.record.DeadlineAt {
		t.Fatal("incorrect pending response")
	}
	encoded, _ := json.Marshal(observed)
	if bytes.Contains(encoded, []byte(f.record.CustomerID)) || bytes.Contains(encoded, []byte(f.record.KeyFingerprint)) {
		t.Fatal("private claim details exposed")
	}
	if err = co.WithStatus(context.Background(), c.Challenge, raw, func(customerpending.PendingStatus) error { t.Fatal("replayed proof emitted"); return nil }); !errors.Is(err, customerchallenge.ErrUnavailable) {
		t.Fatalf("replay: %v", err)
	}
}

func TestBadProofMissingClaimAndWrongPurposeNeverEmit(t *testing.T) {
	f := setup(t)
	co, _ := New(f.pool, f.store, f.clock.read, allow)
	for _, tc := range []string{"bad proof", "changed claim", "claim purpose"} {
		t.Run(tc, func(t *testing.T) {
			c, raw := f.request(t)
			if tc == "bad proof" {
				var m map[string]string
				if err := json.Unmarshal(raw, &m); err != nil {
					t.Fatal(err)
				}
				m["proof"] = base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64))
				raw, _ = json.Marshal(m)
			}
			if tc == "changed claim" {
				var err error
				c, err = f.pool.IssueStatus("192.0.2.1", f.record.CustomerID, f.record.InstallerProfileID, "claim_"+strings.Repeat("9", 32))
				if err != nil {
					t.Fatal(err)
				}
			}
			if tc == "claim purpose" {
				var err error
				c, err = f.pool.Issue("192.0.2.1", f.record.CustomerID, f.record.InstallerProfileID, f.record.ClaimID)
				if err != nil {
					t.Fatal(err)
				}
			}
			err := co.WithStatus(context.Background(), c.Challenge, raw, func(customerpending.PendingStatus) error { t.Fatal("unverified response"); return nil })
			if err == nil {
				t.Fatal("unverified status succeeded")
			}
			if _, err = f.pool.TakeStatus(c.Challenge); !errors.Is(err, customerchallenge.ErrUnavailable) {
				t.Fatalf("challenge not consumed: %v", err)
			}
		})
	}
}

func TestGuardLossExpiryAndCancellationNeverEmit(t *testing.T) {
	for _, tc := range []string{"guard", "deadline", "cancel"} {
		t.Run(tc, func(t *testing.T) {
			f := setup(t)
			c, raw := f.request(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			guardLost := errors.New("guard lost")
			acquire := func(context.Context, customerclaim.Metadata) (customerpending.AuthorityLease, error) {
				return &fixtureLease{check: func() error {
					calls++
					if calls == 2 {
						switch tc {
						case "guard":
							return guardLost
						case "deadline":
							f.clock.set(time.Unix(c.ExpiresAt, 0))
						case "cancel":
							cancel()
						}
					}
					return nil
				}, release: func() {}}, nil
			}
			co, _ := New(f.pool, f.store, f.clock.read, acquire)
			err := co.WithStatus(ctx, c.Challenge, raw, func(customerpending.PendingStatus) error { t.Fatal("stale response"); return nil })
			if err == nil {
				t.Fatal("invalid state accepted")
			}
		})
	}
}

func TestConcurrentSameChallengeAndPanicRelease(t *testing.T) {
	f := setup(t)
	co, _ := New(f.pool, f.store, f.clock.read, allow)
	c, raw := f.request(t)
	var wg sync.WaitGroup
	wg.Add(2)
	success := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			err := co.WithStatus(context.Background(), c.Challenge, raw, func(customerpending.PendingStatus) error { return nil })
			success <- err == nil
		}()
	}
	wg.Wait()
	close(success)
	count := 0
	for v := range success {
		if v {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("successful status count %d", count)
	}
	c, raw = f.request(t)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected panic")
			}
		}()
		_ = co.WithStatus(context.Background(), c.Challenge, raw, func(customerpending.PendingStatus) error { panic("fixture") })
	}()
	c, raw = f.request(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := co.WithStatus(ctx, c.Challenge, raw, func(customerpending.PendingStatus) error { return nil }); err != nil {
		t.Fatalf("panic retained lock: %v", err)
	}
}

func TestBusyDoesNotConsumeChallenge(t *testing.T) {
	f := setup(t)
	co, _ := New(f.pool, f.store, f.clock.read, allow)
	c, raw := f.request(t)
	one, err := co.budget.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	two, err := co.budget.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := co.WithStatus(context.Background(), c.Challenge, raw, func(customerpending.PendingStatus) error {
		t.Fatal("busy request emitted status")
		return nil
	}); !errors.Is(err, ErrBusy) {
		t.Fatalf("expected busy, got %v", err)
	}
	one.Release()
	two.Release()
	if err := co.WithStatus(context.Background(), c.Challenge, raw, func(customerpending.PendingStatus) error { return nil }); err != nil {
		t.Fatalf("busy status consumed challenge: %v", err)
	}
}

func TestGuardLossImmediatelyBeforeEmission(t *testing.T) {
	f := setup(t)
	c, raw := f.request(t)
	checks := 0
	lost := errors.New("guard lost")
	acquire := func(context.Context, customerclaim.Metadata) (customerpending.AuthorityLease, error) {
		return &fixtureLease{check: func() error {
			checks++
			if checks == 3 {
				return lost
			}
			return nil
		}, release: func() {}}, nil
	}
	co, _ := New(f.pool, f.store, f.clock.read, acquire)
	err := co.WithStatus(context.Background(), c.Challenge, raw, func(customerpending.PendingStatus) error {
		t.Fatal("response emitted after final authority loss")
		return nil
	})
	if !errors.Is(err, lost) {
		t.Fatalf("expected guard loss, got %v", err)
	}
}

func TestAdmissionAndStatusShareProofBudget(t *testing.T) {
	for _, occupied := range []string{"admission", "status"} {
		t.Run(occupied, func(t *testing.T) {
			f := setup(t)
			budget := customerbudget.New()
			hold, err := budget.Acquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{})
			proceed := make(chan struct{})
			acquire := allow
			if occupied == "admission" {
				acquire = func(context.Context, customerclaim.Metadata) (customerpending.AuthorityLease, error) {
					close(entered)
					<-proceed
					return &fixtureLease{check: func() error { return nil }, release: func() {}}, nil
				}
			}
			admission, err := customeradmission.NewWithBudget(f.pool, f.store, f.clock.read, acquire, budget)
			if err != nil {
				t.Fatal(err)
			}
			status, err := NewWithBudget(f.pool, f.store, f.clock.read, allow, budget)
			if err != nil {
				t.Fatal(err)
			}
			claim, err := f.pool.Issue("192.0.2.1", f.record.CustomerID, f.record.InstallerProfileID, "claim_"+strings.Repeat("7", 32))
			if err != nil {
				t.Fatal(err)
			}
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, f.key)
			if err != nil {
				t.Fatal(err)
			}
			request := "request_" + strings.Repeat("8", 32)
			message, err := customerclaim.SigningMessage(claim, request, csr, f.clock.read())
			if err != nil {
				t.Fatal(err)
			}
			claimRaw, err := customerclaim.Encode(claim, request, csr, ed25519.Sign(f.key, message), f.clock.read())
			if err != nil {
				t.Fatal(err)
			}
			statusChallenge, statusRaw := f.request(t)
			result := make(chan error, 1)
			if occupied == "admission" {
				go func() { _, err := admission.Submit(context.Background(), claim.Challenge, claimRaw); result <- err }()
			} else {
				go func() {
					result <- status.WithStatus(context.Background(), statusChallenge.Challenge, statusRaw, func(customerpending.PendingStatus) error { close(entered); <-proceed; return nil })
				}()
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("occupied proof did not reach hold")
			}
			if occupied == "admission" {
				if err := status.WithStatus(context.Background(), statusChallenge.Challenge, statusRaw, func(customerpending.PendingStatus) error { return nil }); !errors.Is(err, ErrBusy) {
					t.Fatalf("status should be busy: %v", err)
				}
			} else {
				if _, err := admission.Submit(context.Background(), claim.Challenge, claimRaw); !errors.Is(err, customeradmission.ErrBusy) {
					t.Fatalf("admission should be busy: %v", err)
				}
			}
			hold.Release()
			close(proceed)
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if occupied == "admission" {
				if err := status.WithStatus(context.Background(), statusChallenge.Challenge, statusRaw, func(customerpending.PendingStatus) error { return nil }); err != nil {
					t.Fatalf("busy status consumed challenge: %v", err)
				}
			} else {
				if _, err := admission.Submit(context.Background(), claim.Challenge, claimRaw); err != nil {
					t.Fatalf("busy admission consumed challenge: %v", err)
				}
			}
			if budget.InUse() != 0 {
				t.Fatal("proof slot leaked")
			}
		})
	}
}

func TestSharedBudgetConstructorFailsClosed(t *testing.T) {
	f := setup(t)
	if _, err := NewWithBudget(f.pool, f.store, f.clock.read, allow, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil status budget accepted")
	}
	if _, err := customeradmission.NewWithBudget(f.pool, f.store, f.clock.read, allow, &customerbudget.Budget{}); !errors.Is(err, customeradmission.ErrInvalid) {
		t.Fatal("zero admission budget accepted")
	}
}

func TestCancelledStatusDoesNotConsumeChallengeOrBudget(t *testing.T) {
	f := setup(t)
	budget := customerbudget.New()
	co, err := NewWithBudget(f.pool, f.store, f.clock.read, allow, budget)
	if err != nil {
		t.Fatal(err)
	}
	c, raw := f.request(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = co.WithStatus(ctx, c.Challenge, raw, func(customerpending.PendingStatus) error { t.Fatal("cancelled request emitted"); return nil })
	if !errors.Is(err, context.Canceled) || budget.InUse() != 0 {
		t.Fatal("cancelled status reserved budget")
	}
	if err = co.WithStatus(context.Background(), c.Challenge, raw, func(customerpending.PendingStatus) error { return nil }); err != nil {
		t.Fatalf("cancelled status consumed challenge: %v", err)
	}
}
