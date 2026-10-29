package customeradmission

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
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/customerbudget"
	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
	_ "modernc.org/sqlite"
)

type fixtureLease struct {
	check   func() error
	release func()
}

func (l fixtureLease) Check() error { return l.check() }
func (l fixtureLease) Release()     { l.release() }
func fixtureAuthority(check func() error) customerpending.AcquireAuthority {
	return func(context.Context, customerclaim.Metadata) (customerpending.AuthorityLease, error) {
		return fixtureLease{check, func() {}}, nil
	}
}

type fixture struct {
	pool  *customerchallenge.Pool
	store *customerpending.Store
	now   time.Time
	key   ed25519.PrivateKey
	csr   []byte
}

func setup(t *testing.T) fixture {
	t.Helper()
	now := time.Unix(1790000000, 0).UTC()
	b := customerchallenge.Binding{ManagerID: "manager_" + strings.Repeat("1", 32), Origin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", IssuerFingerprint: strings.Repeat("a", 64)}
	pool, err := customerchallenge.New(b, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "pending.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if err = customerpending.Initialize(context.Background(), db); err != nil {
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
	return fixture{pool, store, now, key, csr}
}
func (f fixture) request(t *testing.T, n int) (customerclaim.Context, []byte) {
	t.Helper()
	id := fmt.Sprintf("claim_%032x", n)
	c, err := f.pool.Issue("192.0.2.1", "customer_"+strings.Repeat("2", 32), "profile_"+strings.Repeat("3", 32), id)
	if err != nil {
		t.Fatal(err)
	}
	request := fmt.Sprintf("request_%032x", n)
	message, err := customerclaim.SigningMessage(c, request, f.csr, f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := customerclaim.Encode(c, request, f.csr, ed25519.Sign(f.key, message), f.now)
	if err != nil {
		t.Fatal(err)
	}
	return c, raw
}

func TestChallengeProofPendingAndFreshRetry(t *testing.T) {
	f := setup(t)
	co, err := New(f.pool, f.store, func() time.Time { return f.now }, fixtureAuthority(func() error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	c, raw := f.request(t, 1)
	one, err := co.Submit(context.Background(), c.Challenge, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = co.Submit(context.Background(), c.Challenge, raw); !errors.Is(err, customerchallenge.ErrUnavailable) {
		t.Fatalf("challenge replay accepted: %v", err)
	}
	second, raw2 := f.request(t, 1)
	two, err := co.Submit(context.Background(), second.Challenge, raw2)
	if err != nil || two.ClaimHash != one.ClaimHash || two.CreatedAt != one.CreatedAt || two.DeadlineAt != one.DeadlineAt {
		t.Fatalf("retry: %v", err)
	}
	records, err := f.store.Records(context.Background())
	if err != nil || len(records) != 1 {
		t.Fatalf("unexpected retained records: %v", err)
	}
}

func TestSharedBudgetCancellationAndPanicRelease(t *testing.T) {
	f := setup(t)
	budget := customerbudget.New()
	co, err := NewWithBudget(f.pool, f.store, func() time.Time { return f.now }, fixtureAuthority(func() error { return nil }), budget)
	if err != nil {
		t.Fatal(err)
	}
	c, raw := f.request(t, 44)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = co.Submit(ctx, c.Challenge, raw); !errors.Is(err, context.Canceled) || budget.InUse() != 0 {
		t.Fatal("cancelled claim held budget")
	}
	if _, err = co.Submit(context.Background(), c.Challenge, raw); err != nil {
		t.Fatalf("cancelled claim consumed challenge: %v", err)
	}
	panicAcquire := func(context.Context, customerclaim.Metadata) (customerpending.AuthorityLease, error) {
		panic("fixture")
	}
	co, err = NewWithBudget(f.pool, f.store, func() time.Time { return f.now }, panicAcquire, budget)
	if err != nil {
		t.Fatal(err)
	}
	c, raw = f.request(t, 45)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected panic")
			}
		}()
		_, _ = co.Submit(context.Background(), c.Challenge, raw)
	}()
	if budget.InUse() != 0 {
		t.Fatal("panic held shared budget")
	}
	co, _ = NewWithBudget(f.pool, f.store, func() time.Time { return f.now }, fixtureAuthority(func() error { return nil }), budget)
	c, raw = f.request(t, 45)
	if _, err = co.Submit(context.Background(), c.Challenge, raw); err != nil {
		t.Fatalf("panic retained admission lock: %v", err)
	}
}

func TestInvalidProofAndLeaseLossNeverCommit(t *testing.T) {
	f := setup(t)
	co, _ := New(f.pool, f.store, func() time.Time { return f.now }, fixtureAuthority(func() error { return nil }))
	c, raw := f.request(t, 1)
	var object map[string]string
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["proof"] = base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, ed25519.SignatureSize))
	bad, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := co.Submit(context.Background(), c.Challenge, bad); !errors.Is(err, customerclaim.ErrProof) {
		t.Fatalf("invalid signature accepted: %v", err)
	}
	if _, err := co.Submit(context.Background(), c.Challenge, raw); !errors.Is(err, customerchallenge.ErrUnavailable) {
		t.Fatalf("invalid proof left challenge usable: %v", err)
	}
	c, raw = f.request(t, 1)
	calls := 0
	lost := errors.New("lease lost")
	co, _ = New(f.pool, f.store, func() time.Time { return f.now }, fixtureAuthority(func() error {
		calls++
		if calls == 2 {
			return lost
		}
		return nil
	}))
	if _, err := co.Submit(context.Background(), c.Challenge, raw); !errors.Is(err, lost) {
		t.Fatalf("lost lease accepted: %v", err)
	}
	rows, err := f.store.Records(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatalf("claim committed on lost lease: %v", err)
	}
}

func TestConcurrentProofsBoundedAndBusyDoesNotConsume(t *testing.T) {
	f := setup(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	authority := func(context.Context, customerclaim.Metadata) (customerpending.AuthorityLease, error) {
		once.Do(func() { close(entered); <-release })
		return fixtureLease{func() error { return nil }, func() {}}, nil
	}
	co, _ := New(f.pool, f.store, func() time.Time { return f.now }, authority)
	c1, r1 := f.request(t, 1)
	c2, r2 := f.request(t, 2)
	c3, r3 := f.request(t, 3)
	errs := make(chan error, 2)
	go func() { _, err := co.Submit(context.Background(), c1.Challenge, r1); errs <- err }()
	<-entered
	go func() { _, err := co.Submit(context.Background(), c2.Challenge, r2); errs <- err }()
	deadline := time.Now().Add(2 * time.Second)
	for co.budget.InUse() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if co.budget.InUse() != 2 {
		close(release)
		t.Fatal("second proof did not enter")
	}
	if _, err := co.Submit(context.Background(), c3.Challenge, r3); !errors.Is(err, ErrBusy) {
		close(release)
		t.Fatalf("proof limit: %v", err)
	}
	if _, err := f.pool.Take(c3.Challenge); err != nil {
		close(release)
		t.Fatalf("busy consumed challenge: %v", err)
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	rows, err := f.store.Records(context.Background())
	if err != nil || len(rows) != 2 {
		t.Fatalf("unexpected pending records: %v", err)
	}
}

func TestClockRegressionConsumesChallengeWithoutCommit(t *testing.T) {
	f := setup(t)
	calls := 0
	clock := func() time.Time {
		calls++
		if calls > 1 {
			return f.now.Add(-time.Second)
		}
		return f.now
	}
	co, _ := New(f.pool, f.store, clock, fixtureAuthority(func() error { return nil }))
	c, raw := f.request(t, 1)
	if _, err := co.Submit(context.Background(), c.Challenge, raw); !errors.Is(err, ErrClock) {
		t.Fatalf("regression accepted: %v", err)
	}
	if _, err := f.pool.Take(c.Challenge); !errors.Is(err, customerchallenge.ErrUnavailable) {
		t.Fatalf("challenge still usable: %v", err)
	}
}

func TestCompetingSubmissionsConsumeChallengeOnce(t *testing.T) {
	f := setup(t)
	co, _ := New(f.pool, f.store, func() time.Time { return f.now }, fixtureAuthority(func() error { return nil }))
	c, raw := f.request(t, 1)
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { <-start; _, err := co.Submit(context.Background(), c.Challenge, raw); results <- err }()
	}
	close(start)
	one, two := <-results, <-results
	if !(one == nil && errors.Is(two, customerchallenge.ErrUnavailable) || two == nil && errors.Is(one, customerchallenge.ErrUnavailable)) {
		t.Fatalf("expected exactly one accepted proof: %v / %v", one, two)
	}
	rows, err := f.store.Records(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatalf("duplicate pending records: %v", err)
	}
}

func TestProofExpiredAfterTakeIsNotPersisted(t *testing.T) {
	f := setup(t)
	calls := 0
	clock := func() time.Time {
		calls++
		if calls == 1 {
			return f.now
		}
		return f.now.Add(60 * time.Second)
	}
	co, _ := New(f.pool, f.store, clock, fixtureAuthority(func() error { return nil }))
	c, raw := f.request(t, 1)
	if _, err := co.Submit(context.Background(), c.Challenge, raw); err == nil {
		t.Fatal("expired proof accepted")
	}
	if _, err := f.pool.Take(c.Challenge); !errors.Is(err, customerchallenge.ErrUnavailable) {
		t.Fatalf("challenge usable after expiry: %v", err)
	}
	rows, err := f.store.Records(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatalf("expired proof persisted: %v", err)
	}
}
