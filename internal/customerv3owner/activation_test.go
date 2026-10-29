package customerv3owner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"localrmm/internal/customerbudget"
	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerissuance"
	"localrmm/internal/customerpending"
	"localrmm/internal/customerproofdomain"
	"localrmm/internal/customerv3proof"
)

type activationFixture struct {
	f      *fixture
	pool   *customerchallenge.Pool
	budget *customerbudget.Budget
	intent customerissuance.Intent
	cert   CertificateRecord
}

func newActivationFixture(t *testing.T, driver string) *activationFixture {
	t.Helper()
	f := newFixture(t, driver)
	req, proof := f.certificateFixture(t)
	cert, e := f.commitCertificate(context.Background(), req, proof)
	if e != nil {
		t.Fatal(e)
	}
	rows, e := f.store.Records(context.Background())
	if e != nil || len(rows) != 1 {
		t.Fatal(e)
	}
	p := rows[0].Approval.Candidate.Pending
	pool, e := customerchallenge.New(customerchallenge.Binding{ManagerID: p.ManagerID, Origin: p.Origin, AgentOrigin: p.AgentOrigin, IssuerFingerprint: p.IssuerFingerprint}, f.clock)
	if e != nil {
		t.Fatal(e)
	}
	return &activationFixture{f, pool, customerbudget.New(), rows[0], cert}
}
func (a *activationFixture) request(t *testing.T, n int, activation bool) ActivationRequest {
	t.Helper()
	p := a.intent.Approval.Candidate.Pending
	var cErr error
	challenge, err := a.pool.IssueActivationV3("192.0.2.1", p.CustomerID, p.InstallerProfileID, p.ClaimID)
	cErr = err
	if !activation {
		challenge, cErr = a.pool.IssueCredentialV3("192.0.2.1", p.CustomerID, p.InstallerProfileID, p.ClaimID)
	}
	if cErr != nil {
		t.Fatal(cErr)
	}
	req := id("request", n)
	msg, err := customerv3proof.SigningMessage(a.intent, customerv3proof.Activation, challenge, req, a.cert.CertificateHash, a.f.now)
	if err != nil {
		t.Fatal(err)
	}
	return ActivationRequest{ClaimID: p.ClaimID, IntentID: a.intent.IntentID, IntentDigest: a.cert.IntentDigest, RequestID: req, Nonce: challenge.Challenge, Signature: ed25519.Sign(a.f.deviceKey, msg)}
}
func (a *activationFixture) activate(ctx context.Context, r ActivationRequest) (ActivationRecord, error) {
	f := a.f
	return f.store.Activate(ctx, f.pending, a.pool, a.budget, r, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage)
}

func TestActivationRetainsExactOnceAndNoProof(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	r := a.request(t, 101, true)
	a.f.revision++
	a.f.sessionEnded = true
	out, e := a.activate(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	if out.IntentDigest != r.IntentDigest || out.CertificateHash != a.cert.CertificateHash || out.RequestID != r.RequestID || out.DeviceID != a.intent.Approval.Candidate.DeviceID {
		t.Fatal("identity not retained")
	}
	rows, e := a.f.store.ActivationRecords(context.Background())
	if e != nil || len(rows) != 1 || rows[0] != out {
		t.Fatal("activation not retained", e)
	}
	raw, e := json.Marshal(rows[0])
	if e != nil || bytes.Contains(raw, []byte(r.Nonce)) || bytes.Contains(raw, r.Signature) {
		t.Fatal("proof material stored")
	}
	if _, e = a.activate(context.Background(), r); e == nil {
		t.Fatal("same challenge replayed")
	}
	second := a.request(t, 102, true)
	if _, e = a.activate(context.Background(), second); !errors.Is(e, ErrConflict) {
		t.Fatal("activation repeated", e)
	}
}

func TestActivationRejectsBadProofAndGuards(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*activationFixture, *ActivationRequest)
	}{
		{"signature", func(_ *activationFixture, r *ActivationRequest) { r.Signature[0] ^= 1 }},
		{"claim", func(_ *activationFixture, r *ActivationRequest) { r.ClaimID = id("claim", 99) }},
		{"intent", func(_ *activationFixture, r *ActivationRequest) { r.IntentID = id("intent", 99) }},
		{"digest", func(_ *activationFixture, r *ActivationRequest) {
			r.IntentDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{"revocation", func(a *activationFixture, _ *ActivationRequest) { a.f.issuanceRevoked = true }},
		{"issuer", func(a *activationFixture, _ *ActivationRequest) { a.f.issuerRevoked = true }},
		{"identity", func(a *activationFixture, _ *ActivationRequest) { a.f.allowed = false }},
		{"expired", func(a *activationFixture, _ *ActivationRequest) {
			a.f.now = a.f.now.Add(customerpending.PendingLifetime)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newActivationFixture(t, "sqlite")
			r := a.request(t, 111, true)
			tc.mutate(a, &r)
			if _, e := a.activate(context.Background(), r); e == nil {
				t.Fatal("invalid activation accepted")
			}
			rows, e := a.f.store.ActivationRecords(context.Background())
			if e != nil || len(rows) != 0 {
				t.Fatal("failed activation retained", e)
			}
		})
	}
	a := newActivationFixture(t, "sqlite")
	r := a.request(t, 112, false)
	if _, e := a.activate(context.Background(), r); e == nil {
		t.Fatal("credential challenge accepted for activation")
	}
}

func TestActivationBudgetBusyDoesNotConsume(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	r := a.request(t, 113, true)
	one, e := a.budget.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	two, e := a.budget.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.activate(context.Background(), r); !errors.Is(e, customerbudget.ErrBusy) {
		t.Fatal("expected busy", e)
	}
	one.Release()
	two.Release()
	if _, e = a.activate(context.Background(), r); e != nil {
		t.Fatal("busy consumed challenge", e)
	}
	if a.budget.InUse() != 0 {
		t.Fatal("slot leaked")
	}
}

func TestActivationConcurrentAndUncertain(t *testing.T) {
	t.Run("parallel", func(t *testing.T) {
		a := newActivationFixture(t, "sqlite")
		r1, r2 := a.request(t, 114, true), a.request(t, 115, true)
		results := make(chan error, 2)
		var wg sync.WaitGroup
		for _, r := range []ActivationRequest{r1, r2} {
			wg.Add(1)
			go func(r ActivationRequest) { defer wg.Done(); _, e := a.activate(context.Background(), r); results <- e }(r)
		}
		wg.Wait()
		close(results)
		ok, conflict := 0, 0
		for e := range results {
			if e == nil {
				ok++
			} else if errors.Is(e, ErrConflict) {
				conflict++
			} else {
				t.Fatal(e)
			}
		}
		if ok != 1 || conflict != 1 {
			t.Fatal(ok, conflict)
		}
		rows, e := a.f.store.ActivationRecords(context.Background())
		if e != nil || len(rows) != 1 {
			t.Fatal(e)
		}
	})
	for _, late := range []bool{false, true} {
		t.Run(fmt.Sprintf("late=%v", late), func(t *testing.T) {
			d := &lostDriver{}
			name := fmt.Sprintf("customer-v3-activation-%d", driverSequence.Add(1))
			sql.Register(name, d)
			a := newActivationFixture(t, name)
			r := a.request(t, 116, true)
			ctx := context.Background()
			if late {
				d.delayCommit.Store(true)
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
				defer cancel()
			} else {
				d.fail.Store(true)
			}
			if _, e := a.activate(ctx, r); !errors.Is(e, ErrUncertain) {
				t.Fatal("commit falsely confirmed", e)
			}
			rows, e := a.f.store.ActivationRecords(context.Background())
			if e != nil || len(rows) != 1 {
				t.Fatal("cannot reconcile", e)
			}
			r2 := a.request(t, 117, true)
			if _, e = a.activate(context.Background(), r2); !errors.Is(e, ErrConflict) {
				t.Fatal("repeated after uncertainty", e)
			}
		})
	}
}

func TestActivationGuardPanicAndAlteredSchema(t *testing.T) {
	for _, tc := range []struct {
		name      string
		guard     func(*int) StorageGuard
		want      error
		persisted bool
	}{
		{"guard loss", func(n *int) StorageGuard {
			return func(context.Context) error {
				*n++
				if *n >= 2 {
					return errors.New("storage authority lost")
				}
				return nil
			}
		}, nil, false},
		{"panic after commit", func(n *int) StorageGuard {
			return func(context.Context) error {
				*n++
				if *n >= 6 {
					panic("fixture guard panic")
				}
				return nil
			}
		}, ErrUncertain, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newActivationFixture(t, "sqlite")
			r := a.request(t, 118, true)
			calls := 0
			f := a.f
			_, err := f.store.Activate(context.Background(), f.pending, a.pool, a.budget, r, f.issuer, f.root, f.clock, f.original, f.issuance, tc.guard(&calls))
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatal("guard failure not handled", err, calls)
			}
			if a.budget.InUse() != 0 {
				t.Fatal("budget leaked")
			}
			rows, err := f.store.ActivationRecords(context.Background())
			if err != nil || (len(rows) == 1) != tc.persisted {
				t.Fatal("wrong retained state", err, calls)
			}
		})
	}
	a := newActivationFixture(t, "sqlite")
	r := a.request(t, 119, true)
	if _, e := a.f.db.Exec(`ALTER TABLE customer_v3_activations ADD COLUMN extra TEXT`); e != nil {
		t.Fatal(e)
	}
	if _, e := a.activate(context.Background(), r); !errors.Is(e, ErrStorage) {
		t.Fatal("altered schema accepted", e)
	}
}

func TestActivationBeginPanicDiscardsConnection(t *testing.T) {
	d := &lostDriver{}
	name := fmt.Sprintf("customer-v3-activation-begin-%d", driverSequence.Add(1))
	sql.Register(name, d)
	a := newActivationFixture(t, name)
	r := a.request(t, 120, true)
	before := d.closes.Load()
	d.panicBegin.Store(true)
	if _, err := a.activate(context.Background(), r); !errors.Is(err, ErrInvalid) {
		t.Fatal("panic not fail-closed", err)
	}
	if d.closes.Load() <= before || a.budget.InUse() != 0 {
		t.Fatal("connection or budget leaked")
	}
	second := a.request(t, 121, true)
	if _, err := a.activate(context.Background(), second); err != nil {
		t.Fatal("replacement connection failed", err)
	}
}

func TestActivationSharesBudgetWithProofDomain(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	r := a.request(t, 122, true)
	p := a.intent.Approval.Candidate.Pending
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	domain, err := customerproofdomain.NewWithBudget(a.pool, a.f.pending, a.f.clock, func(ctx context.Context, m customerclaim.Metadata) (customerpending.AuthorityLease, error) {
		return a.f.original(ctx, m, a.f.managerDigest)
	}, a.budget)
	if err != nil {
		t.Fatal(err)
	}
	status, err := a.pool.IssueStatus("192.0.2.1", p.CustomerID, p.InstallerProfileID, p.ClaimID)
	if err != nil {
		t.Fatal(err)
	}
	m := customerclaim.Metadata{ManagerID: p.ManagerID, CustomerID: p.CustomerID, InstallerProfileID: p.InstallerProfileID, Origin: p.Origin, AgentOrigin: p.AgentOrigin, IssuerFingerprint: p.IssuerFingerprint, ClaimID: p.ClaimID, RequestID: p.RequestID, KeyFingerprint: p.KeyFingerprint, CSRHash: p.CSRHash, ClaimHash: p.ClaimHash, ComparisonCode: p.ComparisonCode}
	statusRequest := id("request", 123)
	msg, err := customerclaim.StatusSigningMessage(status, m, p.PublicKeyDER, statusRequest, a.f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := customerclaim.EncodeStatus(status, m, p.PublicKeyDER, statusRequest, ed25519.Sign(a.f.deviceKey, msg), a.f.now)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- domain.WithPendingStatus(ctx, status.Challenge, raw, func(customerpending.PendingStatus) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-entered:
	case err = <-done:
		t.Fatal("status failed", err)
	case <-ctx.Done():
		t.Fatal("status timed out")
	}
	reserved, err := a.budget.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.activate(ctx, r); !errors.Is(err, customerbudget.ErrBusy) {
		reserved.Release()
		close(release)
		t.Fatal("activation bypassed shared limit", err)
	}
	reserved.Release()
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if _, err = a.activate(ctx, r); err != nil {
		t.Fatal("busy consumed activation challenge", err)
	}
}

func TestActivationRejectsSignatureByDifferentDeviceKey(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	r := a.request(t, 124, true)
	p := a.intent.Approval.Candidate.Pending
	challenge := customerclaim.Context{ManagerID: p.ManagerID, CustomerID: p.CustomerID, InstallerProfileID: p.InstallerProfileID, ClaimID: p.ClaimID, Origin: p.Origin, AgentOrigin: p.AgentOrigin, IssuerFingerprint: p.IssuerFingerprint, Challenge: r.Nonce, ExpiresAt: a.f.now.Unix() + int64(customerclaim.MaxChallengeLifetime/time.Second)}
	msg, err := customerv3proof.SigningMessage(a.intent, customerv3proof.Activation, challenge, r.RequestID, a.cert.CertificateHash, a.f.now)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = ed25519.Sign(other, msg)
	if _, err = a.activate(context.Background(), r); err == nil {
		t.Fatal("foreign key accepted")
	}
}

func TestActivationFinalAuthorityLossFailsClosed(t *testing.T) {
	for _, kind := range []string{"customer", "issuer"} {
		t.Run(kind, func(t *testing.T) {
			a := newActivationFixture(t, "sqlite")
			r := a.request(t, 125, true)
			f := a.f
			checks := 0
			original := f.original
			issuance := f.issuance
			if kind == "customer" {
				original = func(ctx context.Context, m customerclaim.Metadata, digest string) (customerpending.AuthorityLease, error) {
					inner, err := f.original(ctx, m, digest)
					if err != nil {
						return nil, err
					}
					return lease{check: func() error {
						checks++
						if checks >= 6 {
							return errors.New("customer lease lost")
						}
						return inner.Check()
					}, release: inner.Release}, nil
				}
			}
			if kind == "issuer" {
				issuance = func(ctx context.Context, i customerissuance.Intent, digest string) (IssuanceAuthorityLease, error) {
					inner, err := f.issuance(ctx, i, digest)
					if err != nil {
						return nil, err
					}
					return lease{check: func() error {
						checks++
						if checks >= 4 {
							return errors.New("issuer lease lost")
						}
						return inner.Check()
					}, release: inner.Release}, nil
				}
			}
			_, err := f.store.Activate(context.Background(), f.pending, a.pool, a.budget, r, f.issuer, f.root, f.clock, original, issuance, f.storage)
			if err == nil {
				t.Fatal("lost authority committed")
			}
			if kind == "customer" && checks < 6 || kind == "issuer" && checks < 4 {
				t.Fatal("final guard not reached", checks)
			}
			rows, err := f.store.ActivationRecords(context.Background())
			if err != nil || len(rows) != 0 {
				t.Fatal("lost authority retained activation", err)
			}
		})
	}
}

func TestActivationHoldsLeasesAcrossCommit(t *testing.T) {
	d := &lostDriver{}
	name := fmt.Sprintf("customer-v3-activation-lease-%d", driverSequence.Add(1))
	sql.Register(name, d)
	a := newActivationFixture(t, name)
	r := a.request(t, 126, true)
	f := a.f
	originalReleased, issuerReleased, commitHeld := false, false, false
	original := func(ctx context.Context, m customerclaim.Metadata, digest string) (customerpending.AuthorityLease, error) {
		inner, err := f.original(ctx, m, digest)
		if err != nil {
			return nil, err
		}
		return lease{check: inner.Check, release: func() { originalReleased = true; inner.Release() }}, nil
	}
	issuance := func(ctx context.Context, i customerissuance.Intent, digest string) (IssuanceAuthorityLease, error) {
		inner, err := f.issuance(ctx, i, digest)
		if err != nil {
			return nil, err
		}
		return lease{check: inner.Check, release: func() { issuerReleased = true; inner.Release() }}, nil
	}
	d.onCommit = func() { commitHeld = !originalReleased && !issuerReleased }
	if _, err := f.store.Activate(context.Background(), f.pending, a.pool, a.budget, r, f.issuer, f.root, f.clock, original, issuance, f.storage); err != nil {
		t.Fatal(err)
	}
	if !commitHeld || !originalReleased || !issuerReleased {
		t.Fatal("lease lifetime did not cover commit")
	}
}
