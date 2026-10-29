package customerapprovalstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/customerapproval"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
	"modernc.org/sqlite"
)

type testLease struct{ guard func() error }

func (l testLease) Check() error { return l.guard() }
func (testLease) Release()       {}

type observedLease struct {
	check   func() error
	release func()
}

func (l observedLease) Check() error { return l.check() }
func (l observedLease) Release()     { l.release() }

// The wrapped SQLite driver simulates a committed write whose acknowledgement
// is lost. It is test-only and does not generate artificial production retries.
type lostCommitDriver struct {
	fail, panicBegin, panicRollback atomic.Bool
	closes                          atomic.Int32
}

var lostCommitDriverSequence atomic.Uint64

func (d *lostCommitDriver) Open(name string) (driver.Conn, error) {
	c, err := (&sqlite.Driver{}).Open(name)
	if err != nil {
		return nil, err
	}
	return &lostCommitConn{Conn: c, owner: d}, nil
}

type lostCommitConn struct {
	driver.Conn
	owner *lostCommitDriver
}

func (c *lostCommitConn) Close() error { c.owner.closes.Add(1); return c.Conn.Close() }

func (c *lostCommitConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	e, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	r, err := e.ExecContext(ctx, q, args)
	if err == nil && (q == `BEGIN IMMEDIATE` || q == `BEGIN`) && c.owner.panicBegin.CompareAndSwap(true, false) {
		panic("test BEGIN panic after execution")
	}
	if err == nil && q == `ROLLBACK` && c.owner.panicRollback.CompareAndSwap(true, false) {
		panic("test ROLLBACK panic after execution")
	}
	if err == nil && q == `COMMIT` && c.owner.fail.CompareAndSwap(true, false) {
		return nil, errors.New("commit acknowledgement lost")
	}
	return r, err
}
func (c *lostCommitConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	e, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return e.QueryContext(ctx, q, args)
}

type fixture struct {
	pending    *customerpending.Store
	store      *Store
	db         *sql.DB
	clock      *time.Time
	allow      bool
	guardCalls int
}

func database(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, e := sql.Open("sqlite", filepath.Join(t.TempDir(), name))
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(1790000000, 0).UTC()
	pd := database(t, "pending.db")
	if err := customerpending.Initialize(ctx, pd); err != nil {
		t.Fatal(err)
	}
	p, err := customerpending.New(pd)
	if err != nil {
		t.Fatal(err)
	}
	db := database(t, "approvals.db")
	manager := "manager_" + strings.Repeat("1", 32)
	digest := strings.Repeat("b", 64)
	if err = Initialize(ctx, db, manager, digest); err != nil {
		t.Fatal(err)
	}
	s, err := New(db, manager, digest)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{pending: p, store: s, db: db, clock: &now, allow: true}
}
func (f *fixture) time() time.Time { return *f.clock }
func (f *fixture) authority(_ context.Context, _ customerclaim.Metadata, digest string, revision uint64) (customerpending.AuthorityLease, error) {
	if digest != strings.Repeat("b", 64) || revision != 3 {
		return nil, ErrInvalid
	}
	return testLease{func() error {
		if !f.allow {
			return errors.New("revoked")
		}
		return nil
	}}, nil
}
func (f *fixture) session(ctx context.Context, _ Actor) error {
	f.guardCalls++
	if !f.allow {
		return errors.New("revoked")
	}
	return ctx.Err()
}
func (f *fixture) claim(t *testing.T, key ed25519.PrivateKey, n int) customerpending.ReviewExpectation {
	t.Helper()
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if e != nil {
		t.Fatal(e)
	}
	c := customerclaim.Context{ManagerID: "manager_" + strings.Repeat("1", 32), CustomerID: "customer_" + strings.Repeat("2", 32), InstallerProfileID: "profile_" + strings.Repeat("3", 32), Origin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", IssuerFingerprint: strings.Repeat("a", 64), ClaimID: fmt.Sprintf("claim_%032x", n), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(n)}, 32)), ExpiresAt: f.time().Unix() + 60}
	req := fmt.Sprintf("request_%032x", n)
	msg, e := customerclaim.SigningMessage(c, req, csr, f.time())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := customerclaim.Encode(c, req, csr, ed25519.Sign(key, msg), f.time())
	if e != nil {
		t.Fatal(e)
	}
	proof, e := customerclaim.Verify(raw, c, f.time())
	if e != nil {
		t.Fatal(e)
	}
	r, e := f.pending.Accept(context.Background(), proof, f.time, func(context.Context, customerclaim.Metadata) (customerpending.AuthorityLease, error) {
		return testLease{func() error { return nil }}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return customerpending.ReviewExpectation{ManagerID: r.ManagerID, CustomerID: r.CustomerID, InstallerProfileID: r.InstallerProfileID, ClaimID: r.ClaimID, ClaimHash: r.ClaimHash, KeyFingerprint: r.KeyFingerprint, ManagerDigest: strings.Repeat("b", 64), CustomerRevision: 3, DeadlineAt: r.DeadlineAt}
}
func decision(n int) customerapproval.Decision {
	return customerapproval.Decision{OperationID: fmt.Sprintf("request_%032x", n+100), DeviceID: fmt.Sprintf("agent_%032x", n+100), Acknowledged: true, FingerprintCompared: true}
}
func (f *fixture) approve(e customerpending.ReviewExpectation, d customerapproval.Decision, a Actor) (Record, error) {
	return f.store.Approve(context.Background(), f.pending, e, d, a, f.time, f.authority, f.session)
}
func key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return k
}

func TestBeginPanicDiscardsConnectionForEveryEntryPoint(t *testing.T) {
	for _, path := range []string{"initialize", "approve", "records"} {
		t.Run(path, func(t *testing.T) {
			d := &lostCommitDriver{}
			name := fmt.Sprintf("approval-panic-begin-%d", lostCommitDriverSequence.Add(1))
			sql.Register(name, d)
			db, err := sql.Open(name, filepath.Join(t.TempDir(), "approvals.db"))
			if err != nil {
				t.Fatal(err)
			}
			db.SetMaxOpenConns(1)
			defer db.Close()
			manager := "manager_" + strings.Repeat("1", 32)
			digest := strings.Repeat("b", 64)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if path != "initialize" {
				if err = Initialize(ctx, db, manager, digest); err != nil {
					t.Fatal(err)
				}
			}
			f := newFixture(t)
			f.store, err = New(db, manager, digest)
			if err != nil {
				t.Fatal(err)
			}
			var expected customerpending.ReviewExpectation
			if path == "approve" {
				expected = f.claim(t, key(t), 91)
			}
			closed := d.closes.Load()
			d.panicBegin.Store(true)
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				switch path {
				case "initialize":
					_ = Initialize(ctx, db, manager, digest)
				case "approve":
					_, _ = f.store.Approve(ctx, f.pending, expected, decision(91), Actor{Mode: "shared"}, f.time, f.authority, f.session)
				case "records":
					_, _ = f.store.Records(ctx)
				}
			}()
			if !panicked {
				t.Fatal("expected injected panic")
			}
			if d.closes.Load() <= closed {
				t.Fatal("connection returned to pool after uncertain begin")
			}
			if path == "initialize" {
				if err = Initialize(ctx, db, manager, digest); err != nil {
					t.Fatal("fresh connection did not initialize", err)
				}
			}
			rows, err := f.store.Records(ctx)
			if err != nil || len(rows) != 0 {
				t.Fatal("next connection unavailable or phantom record", err)
			}
			if path == "approve" {
				if _, err = f.store.Approve(ctx, f.pending, expected, decision(91), Actor{Mode: "shared"}, f.time, f.authority, f.session); err != nil {
					t.Fatal("next approval failed", err)
				}
			}
		})
	}
}

func TestRollbackPanicStillReleasesPendingReview(t *testing.T) {
	d := &lostCommitDriver{}
	name := fmt.Sprintf("approval-panic-rollback-%d", lostCommitDriverSequence.Add(1))
	sql.Register(name, d)
	db, err := sql.Open(name, filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	f := newFixture(t)
	manager := "manager_" + strings.Repeat("1", 32)
	digest := strings.Repeat("b", 64)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = Initialize(ctx, db, manager, digest); err != nil {
		t.Fatal(err)
	}
	f.store, err = New(db, manager, digest)
	if err != nil {
		t.Fatal(err)
	}
	expected := f.claim(t, key(t), 92)
	prior := d.closes.Load()
	d.panicRollback.Store(true)
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		_, _ = f.store.Approve(ctx, f.pending, expected, decision(92), Actor{Mode: "shared"}, f.time, f.authority, func(context.Context, Actor) error { return errors.New("stop before commit") })
	}()
	if !panicked {
		t.Fatal("expected rollback panic")
	}
	if d.closes.Load() <= prior {
		t.Fatal("panicking rollback connection was not discarded")
	}
	lease, err := f.pending.AcquireReview(ctx, expected, f.time, f.authority)
	if err != nil {
		t.Fatal("pending review lease remained held", err)
	}
	lease.Release()
	rows, err := f.store.Records(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatal("rollback left data or locked connection", err)
	}
	if _, err = f.store.Approve(ctx, f.pending, expected, decision(92), Actor{Mode: "shared"}, f.time, f.authority, f.session); err != nil {
		t.Fatal("next approval failed", err)
	}
}

func TestBindingReopenAndNoReplay(t *testing.T) {
	f := newFixture(t)
	e := f.claim(t, key(t), 1)
	d := decision(1)
	actor := Actor{Mode: "named", ID: "operator_" + strings.Repeat("7", 32)}
	r, err := f.approve(e, d, actor)
	if err != nil || r.Actor != actor || r.Candidate.Pending.ClaimHash != e.ClaimHash || r.Candidate.DeviceID != d.DeviceID || r.Candidate.CustomerRevision != e.CustomerRevision {
		t.Fatalf("binding: %v", err)
	}
	if _, err = f.approve(e, d, actor); !errors.Is(err, ErrConflict) {
		t.Fatalf("replay: %v", err)
	}
	other, _ := New(f.db, e.ManagerID, e.ManagerDigest)
	rows, err := other.Records(context.Background())
	if err != nil || len(rows) != 1 || rows[0].Actor != actor {
		t.Fatalf("reopen: %v", err)
	}
	if err = Initialize(context.Background(), f.db, e.ManagerID, e.ManagerDigest); err == nil {
		t.Fatal("reinitialized used domain")
	}
}

func TestSameKeyOperationOrDeviceCannotBeReused(t *testing.T) {
	for _, scenario := range []string{"key", "operation", "device"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			k1 := key(t)
			e1 := f.claim(t, k1, 1)
			d1 := decision(1)
			if _, err := f.approve(e1, d1, Actor{Mode: "shared"}); err != nil {
				t.Fatal(err)
			}
			k2 := key(t)
			if scenario == "key" {
				k2 = k1
			}
			e2 := f.claim(t, k2, 2)
			d2 := decision(2)
			if scenario == "operation" {
				d2.OperationID = d1.OperationID
			}
			if scenario == "device" {
				d2.DeviceID = d1.DeviceID
			}
			if _, err := f.approve(e2, d2, Actor{Mode: "shared"}); !errors.Is(err, ErrConflict) {
				t.Fatalf("reuse accepted: %v", err)
			}
			rows, err := f.store.Records(context.Background())
			if err != nil || len(rows) != 1 {
				t.Fatal("unexpected retained count")
			}
		})
	}
}

func TestConsentConflictExpiryGuardAndPanicNeverCommit(t *testing.T) {
	for _, scenario := range []string{"consent", "fingerprint", "actor", "review", "guard", "deadline", "panic"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			e := f.claim(t, key(t), 1)
			d := decision(1)
			actor := Actor{Mode: "shared"}
			guard := f.session
			switch scenario {
			case "consent":
				d.Acknowledged = false
			case "fingerprint":
				d.FingerprintCompared = false
			case "actor":
				actor.ID = "operator_" + strings.Repeat("a", 32)
			case "review":
				e.CustomerRevision++
			case "guard":
				f.allow = false
			case "deadline":
				*f.clock = time.Unix(e.DeadlineAt, 0)
			case "panic":
				guard = func(context.Context, Actor) error { panic("test guard") }
			}
			func() {
				defer func() {
					if scenario == "panic" && recover() == nil {
						t.Error("missing panic")
					}
				}()
				_, err := f.store.Approve(context.Background(), f.pending, e, d, actor, f.time, f.authority, guard)
				if scenario != "panic" && err == nil {
					t.Error("invalid approval accepted")
				}
			}()
			f.allow = true
			rows, err := f.store.Records(context.Background())
			if err != nil || len(rows) != 0 {
				t.Fatalf("leaked committed state: %v", err)
			}
		})
	}
}

func TestConcurrentApprovalsForSameClaimCommitOnce(t *testing.T) {
	f := newFixture(t)
	e := f.claim(t, key(t), 1)
	var mu sync.Mutex
	wins := 0
	var wg sync.WaitGroup
	// Independent callbacks avoid races in fixture counters.
	for i := 1; i <= 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := f.store.Approve(context.Background(), f.pending, e, decision(i), Actor{Mode: "shared"}, f.time, f.authority, func(context.Context, Actor) error { return nil })
			if err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("unexpected result %v", err)
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("commits %d", wins)
	}
	rows, err := f.store.Records(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatal("wrong retained state")
	}
}

func TestLateGuardOrClockFailureRollsBack(t *testing.T) {
	for _, scenario := range []string{"guard", "clock", "panic"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			e := f.claim(t, key(t), 1)
			calls := 0
			guard := func(context.Context, Actor) error {
				calls++
				if calls == 2 {
					switch scenario {
					case "guard":
						return errors.New("session expired")
					case "clock":
						*f.clock = time.Unix(e.DeadlineAt, 0)
					case "panic":
						panic("guard panic after insert")
					}
				}
				return nil
			}
			func() {
				defer func() {
					if scenario == "panic" && recover() == nil {
						t.Error("missing panic")
					}
				}()
				_, err := f.store.Approve(context.Background(), f.pending, e, decision(1), Actor{Mode: "shared"}, f.time, f.authority, guard)
				if scenario != "panic" && err == nil {
					t.Error("late failure committed")
				}
			}()
			if calls != 2 {
				t.Fatal("did not exercise guard after insert")
			}
			rows, err := f.store.Records(context.Background())
			if err != nil || len(rows) != 0 {
				t.Fatalf("rollback failed: %v", err)
			}
			if scenario == "clock" {
				*f.clock = time.Unix(1790000000, 0).UTC()
			}
			if _, err := f.approve(e, decision(1), Actor{Mode: "shared"}); err != nil {
				t.Fatalf("leases not released: %v", err)
			}
		})
	}
}

func TestRejectSchemaDamageAndRecordLoss(t *testing.T) {
	for _, scenario := range []string{"schema", "loss", "meta"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			e := f.claim(t, key(t), 1)
			if _, err := f.approve(e, decision(1), Actor{Mode: "shared"}); err != nil {
				t.Fatal(err)
			}
			var query string
			switch scenario {
			case "schema":
				query = `CREATE TABLE unexpected (id INTEGER)`
			case "loss":
				query = `DELETE FROM customer_approval_records`
			case "meta":
				query = `DELETE FROM customer_approval_meta`
			}
			if _, err := f.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.Records(context.Background()); !errors.Is(err, ErrStorage) {
				t.Fatalf("damaged state accepted: %v", err)
			}
		})
	}
}

func TestApprovalHoldsPendingReviewThroughWrite(t *testing.T) {
	f := newFixture(t)
	e := f.claim(t, key(t), 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	guardCalls := 0
	guard := func(context.Context, Actor) error {
		guardCalls++
		if guardCalls == 2 {
			close(entered)
			<-release
		}
		return nil
	}
	go func() {
		_, err := f.store.Approve(context.Background(), f.pending, e, decision(1), Actor{Mode: "shared"}, f.time, f.authority, guard)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("approval did not reach precommit guard")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if lease, err := f.pending.AcquireReview(ctx, e, f.time, f.authority); err == nil {
		lease.Release()
		close(release)
		t.Fatal("pending review escaped concurrent approval lock")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	lease, err := f.pending.AcquireReview(context.Background(), e, f.time, f.authority)
	if err != nil {
		t.Fatalf("pending review remained locked after commit: %v", err)
	}
	lease.Release()
}

func TestReviewAuthorityReleasedOnlyAfterCommittedRowVisible(t *testing.T) {
	f := newFixture(t)
	e := f.claim(t, key(t), 1)
	var seq int
	var name, path string
	if err := f.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	observer, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	observed := -1
	acquire := func(context.Context, customerclaim.Metadata, string, uint64) (customerpending.AuthorityLease, error) {
		return observedLease{check: func() error { return nil }, release: func() {
			if err := observer.QueryRow(`SELECT count(*) FROM customer_approval_records`).Scan(&observed); err != nil {
				t.Errorf("observe after release: %v", err)
			}
		}}, nil
	}
	if _, err = f.store.Approve(context.Background(), f.pending, e, decision(1), Actor{Mode: "shared"}, f.time, acquire, func(context.Context, Actor) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if observed != 1 {
		t.Fatalf("review authority released before commit: observed %d", observed)
	}
}

func TestUnknownCommitIsReconciledWithoutRetry(t *testing.T) {
	f := newFixture(t)
	e := f.claim(t, key(t), 1)
	d := &lostCommitDriver{}
	driverName := fmt.Sprintf("customer_approval_lost_commit_test_%d", lostCommitDriverSequence.Add(1))
	sql.Register(driverName, d)
	db, err := sql.Open(driverName, filepath.Join(t.TempDir(), "loss.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err = Initialize(context.Background(), db, e.ManagerID, e.ManagerDigest); err != nil {
		t.Fatal(err)
	}
	s, err := New(db, e.ManagerID, e.ManagerDigest)
	if err != nil {
		t.Fatal(err)
	}
	d.fail.Store(true)
	if _, err = s.Approve(context.Background(), f.pending, e, decision(1), Actor{Mode: "shared"}, f.time, f.authority, func(context.Context, Actor) error { return nil }); !errors.Is(err, ErrStorage) {
		t.Fatalf("uncertain commit did not fail closed: %v", err)
	}
	rows, err := s.Records(context.Background())
	if err != nil || len(rows) != 1 || rows[0].Candidate.Pending.ClaimID != e.ClaimID {
		t.Fatalf("could not reconcile committed record: %v", err)
	}
	if _, err = s.Approve(context.Background(), f.pending, e, decision(1), Actor{Mode: "shared"}, f.time, f.authority, func(context.Context, Actor) error { return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate after uncertainty accepted: %v", err)
	}
}
