package customerv3owner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/customerapproval"
	"localrmm/internal/customerapprovalstore"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
	"modernc.org/sqlite"
)

type lease struct {
	check   func() error
	release func()
}

func (l lease) Check() error { return l.check() }
func (l lease) Release() {
	if l.release != nil {
		l.release()
	}
}

// The fixture driver injects ambiguous or panicking transaction edges.
type lostDriver struct {
	fail, panicBegin, delayCommit atomic.Bool
	opens, closes                 atomic.Int32
	onCommit                      func()
}

var driverSequence atomic.Uint64

func (d *lostDriver) Open(name string) (driver.Conn, error) {
	d.opens.Add(1)
	c, e := (&sqlite.Driver{}).Open(name)
	if e != nil {
		return nil, e
	}
	return &lostConn{Conn: c, owner: d}, nil
}

type lostConn struct {
	driver.Conn
	owner *lostDriver
}

func (c *lostConn) Close() error { c.owner.closes.Add(1); return c.Conn.Close() }

func (c *lostConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	x, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	if q == `COMMIT` && c.owner.onCommit != nil {
		c.owner.onCommit()
	}
	r, e := x.ExecContext(ctx, q, args)
	if e == nil && (q == `BEGIN IMMEDIATE` || q == `BEGIN`) && c.owner.panicBegin.CompareAndSwap(true, false) {
		panic("fixture BEGIN panic after execution")
	}
	if e == nil && q == `COMMIT` && c.owner.delayCommit.CompareAndSwap(true, false) {
		time.Sleep(700 * time.Millisecond)
	}
	if e == nil && q == `COMMIT` && c.owner.fail.CompareAndSwap(true, false) {
		return nil, errors.New("lost commit acknowledgement")
	}
	return r, e
}
func (c *lostConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	x, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return x.QueryContext(ctx, q, args)
}

func id(prefix string, n int) string { return fmt.Sprintf("%s_%032x", prefix, n) }
func database(t *testing.T, driverName string) *sql.DB {
	t.Helper()
	db, e := sql.Open(driverName, filepath.Join(t.TempDir(), "fixture.db"))
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

type fixture struct {
	pending                                      *customerpending.Store
	pendingDB                                    *sql.DB
	store                                        *Store
	db                                           *sql.DB
	now                                          time.Time
	issuer, root                                 []byte
	issuerKey                                    ed25519.PrivateKey
	deviceKey                                    ed25519.PrivateKey
	issuerCert                                   *x509.Certificate
	manager, managerDigest                       string
	revision                                     uint64
	allowed                                      bool
	sessionEnded, issuanceRevoked, issuerRevoked bool
	sessionCalls, issuerCalls                    int
}

func newFixture(t *testing.T, driverName string) *fixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rpub, rkey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ipub, ikey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("fixture-root")}
	rawRoot, e := x509.CreateCertificate(rand.Reader, root, root, rpub, rkey)
	if e != nil {
		t.Fatal(e)
	}
	root, e = x509.ParseCertificate(rawRoot)
	if e != nil {
		t.Fatal(e)
	}
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("fixture-issuer")}
	rawIssuer, e := x509.CreateCertificate(rand.Reader, it, root, ipub, rkey)
	if e != nil {
		t.Fatal(e)
	}
	issuerCert, e := x509.ParseCertificate(rawIssuer)
	if e != nil {
		t.Fatal(e)
	}
	pdb := database(t, "sqlite")
	if e = customerpending.Initialize(context.Background(), pdb); e != nil {
		t.Fatal(e)
	}
	pending, e := customerpending.New(pdb)
	if e != nil {
		t.Fatal(e)
	}
	db := database(t, driverName)
	manager := id("manager", 1)
	digest := strings.Repeat("b", 64)
	if e = Initialize(context.Background(), db, manager, digest); e != nil {
		t.Fatal(e)
	}
	store, e := New(db, manager, digest)
	if e != nil {
		t.Fatal(e)
	}
	return &fixture{pending: pending, pendingDB: pdb, store: store, db: db, now: now, issuer: rawIssuer, root: rawRoot, issuerKey: ikey, issuerCert: issuerCert, manager: manager, managerDigest: digest, revision: 3, allowed: true}
}
func (f *fixture) clock() time.Time { return f.now }
func (f *fixture) acquire(_ context.Context, _ customerclaim.Metadata, digest string, revision uint64) (customerpending.AuthorityLease, error) {
	if digest != f.managerDigest || revision != f.revision {
		return nil, ErrConflict
	}
	return lease{check: func() error {
		if !f.allowed {
			return errors.New("authority revoked")
		}
		return nil
	}}, nil
}
func (f *fixture) session(ctx context.Context, _ customerapprovalstore.Actor) error {
	f.sessionCalls++
	if !f.allowed || f.sessionEnded {
		return errors.New("session revoked")
	}
	return ctx.Err()
}
func (f *fixture) issuerGuard(ctx context.Context, _ string) error {
	f.issuerCalls++
	if !f.allowed || f.issuerRevoked {
		return errors.New("issuer revoked")
	}
	return ctx.Err()
}
func (f *fixture) live(ctx context.Context, actor customerapprovalstore.Actor, fingerprint string) (LiveAuthorityLease, error) {
	h := sha256.Sum256(f.issuer)
	if actor.Mode != "shared" || actor.ID != "" || fingerprint != hex.EncodeToString(h[:]) {
		return nil, ErrInvalid
	}
	return lease{check: func() error {
		if err := f.session(ctx, actor); err != nil {
			return err
		}
		return f.issuerGuard(ctx, fingerprint)
	}}, nil
}
func (f *fixture) storage(ctx context.Context) error { return ctx.Err() }

func (f *fixture) claim(t *testing.T, key ed25519.PrivateKey, n int) customerpending.ReviewExpectation {
	t.Helper()
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "not copied"}}, key)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(f.issuer)
	c := customerclaim.Context{ManagerID: f.manager, CustomerID: id("customer", 2), InstallerProfileID: id("profile", 3), Origin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", IssuerFingerprint: hex.EncodeToString(h[:]), ClaimID: id("claim", n), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(n)}, 32)), ExpiresAt: f.now.Unix() + 60}
	req := id("request", n)
	msg, e := customerclaim.SigningMessage(c, req, csr, f.now)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := customerclaim.Encode(c, req, csr, ed25519.Sign(key, msg), f.now)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := customerclaim.Verify(raw, c, f.now)
	if e != nil {
		t.Fatal(e)
	}
	r, e := f.pending.Accept(context.Background(), proof, f.clock, func(context.Context, customerclaim.Metadata) (customerpending.AuthorityLease, error) {
		return lease{check: func() error { return nil }}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return customerpending.ReviewExpectation{ManagerID: r.ManagerID, CustomerID: r.CustomerID, InstallerProfileID: r.InstallerProfileID, ClaimID: r.ClaimID, ClaimHash: r.ClaimHash, KeyFingerprint: r.KeyFingerprint, ManagerDigest: f.managerDigest, CustomerRevision: f.revision, DeadlineAt: r.DeadlineAt}
}
func request(e customerpending.ReviewExpectation, n int) Request {
	return Request{Expected: e, Decision: customerapproval.Decision{OperationID: id("request", n+100), DeviceID: id("agent", n+100), Acknowledged: true, FingerprintCompared: true}, Actor: customerapprovalstore.Actor{Mode: "shared"}, IntentID: id("intent", n+100), SerialHex: fmt.Sprintf("%032x", n+100), Lifetime: time.Hour}
}
func (f *fixture) commit(r Request) error {
	_, e := f.store.Commit(context.Background(), f.pending, r, f.issuer, f.root, f.clock, f.acquire, f.live, f.storage)
	return e
}

func TestApprovalAndIntentAreOneRetainedCommit(t *testing.T) {
	f := newFixture(t, "sqlite")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	expect := f.claim(t, key, 1)
	r := request(expect, 1)
	i, e := f.store.Commit(context.Background(), f.pending, r, f.issuer, f.root, f.clock, f.acquire, f.live, f.storage)
	if e != nil {
		t.Fatal(e)
	}
	if i.Approval.Candidate.Pending.ClaimID != expect.ClaimID || i.Approval.Candidate.Pending.CustomerID != expect.CustomerID || i.Approval.Candidate.DeviceID != r.Decision.DeviceID || i.Approval.Actor.Mode != "shared" {
		t.Fatal("approval/intent binding lost")
	}
	rows, e := f.store.Records(context.Background())
	if e != nil || len(rows) != 1 || rows[0].IntentID != r.IntentID {
		t.Fatal("commit not retained", e)
	}
	if e = f.commit(r); !errors.Is(e, ErrConflict) {
		t.Fatal("replayed approval accepted", e)
	}
}

func TestRevisionGuardIssuerAndSchemaFailClosed(t *testing.T) {
	for _, mode := range []string{"revision", "session", "issuer", "no-consent", "expired", "wrong-issuer", "schema"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, "sqlite")
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			req := request(f.claim(t, key, 2), 2)
			switch mode {
			case "revision":
				f.revision++
			case "session":
				f.allowed = false
			case "no-consent":
				req.Decision.Acknowledged = false
			case "expired":
				f.now = time.Unix(req.Expected.DeadlineAt, 0)
			case "wrong-issuer":
				f.issuer = bytes.Clone(f.root)
			case "schema":
				if _, e := f.db.Exec(`CREATE TABLE extra(value TEXT)`); e != nil {
					t.Fatal(e)
				}
			}
			live := f.live
			if mode == "issuer" {
				live = func(context.Context, customerapprovalstore.Actor, string) (LiveAuthorityLease, error) {
					return lease{check: func() error { return errors.New("revoked") }}, nil
				}
			}
			if _, e := f.store.Commit(context.Background(), f.pending, req, f.issuer, f.root, f.clock, f.acquire, live, f.storage); e == nil {
				t.Fatal("invalid authority accepted")
			}
			if mode != "schema" {
				rows, e := f.store.Records(context.Background())
				if e != nil || len(rows) != 0 {
					t.Fatal("failed transaction retained", e)
				}
			}
		})
	}
}

func TestConcurrentSameKeyAndUniqueSerialFence(t *testing.T) {
	f := newFixture(t, "sqlite")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	a := request(f.claim(t, key, 3), 3)
	b := request(f.claim(t, key, 4), 4)
	var wg sync.WaitGroup
	out := make(chan error, 2)
	for _, r := range []Request{a, b} {
		wg.Add(1)
		go func(r Request) { defer wg.Done(); out <- f.commit(r) }(r)
	}
	wg.Wait()
	close(out)
	wins, conflicts := 0, 0
	for e := range out {
		if e == nil {
			wins++
		} else if errors.Is(e, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("duplicate key not fenced", wins, conflicts)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	third := request(f.claim(t, other, 5), 5)
	rows, e := f.store.Records(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	third.SerialHex = rows[0].SerialHex
	if e = f.commit(third); !errors.Is(e, ErrConflict) {
		t.Fatal("duplicate serial accepted", e)
	}
}

func TestLostCommitAcknowledgementRequiresReconciliation(t *testing.T) {
	d := &lostDriver{}
	name := fmt.Sprintf("customer-v3-lost-%d", driverSequence.Add(1))
	sql.Register(name, d)
	f := newFixture(t, name)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	req := request(f.claim(t, key, 6), 6)
	d.fail.Store(true)
	if e := f.commit(req); !errors.Is(e, ErrUncertain) {
		t.Fatal("lost acknowledgement not uncertain", e)
	}
	rows, e := f.store.Records(context.Background())
	if e != nil || len(rows) != 1 || rows[0].IntentID != req.IntentID {
		t.Fatal("committed binding unavailable for reconciliation", e)
	}
	if e = f.commit(req); !errors.Is(e, ErrConflict) {
		t.Fatal("uncertain operation replayed", e)
	}
}

func TestPanicAfterBeginDiscardsConnection(t *testing.T) {
	d := &lostDriver{}
	name := fmt.Sprintf("customer-v3-begin-panic-%d", driverSequence.Add(1))
	sql.Register(name, d)
	f := newFixture(t, name)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	req := request(f.claim(t, key, 20), 20)
	opensBefore, closesBefore := d.opens.Load(), d.closes.Load()
	d.panicBegin.Store(true)
	if err := f.commit(req); !errors.Is(err, ErrInvalid) {
		t.Fatal("BEGIN panic not failed closed", err)
	}
	if d.closes.Load() <= closesBefore {
		t.Fatal("unknown BEGIN connection was not discarded")
	}
	rows, err := f.store.Records(context.Background())
	if err != nil || len(rows) != 0 || d.opens.Load() <= opensBefore {
		t.Fatal("new connection did not recover", err)
	}
	if err = f.commit(req); err != nil {
		t.Fatal("discarded connection retained lock", err)
	}
}

func TestPanicAfterReadBeginDiscardsConnection(t *testing.T) {
	d := &lostDriver{}
	name := fmt.Sprintf("customer-v3-read-panic-%d", driverSequence.Add(1))
	sql.Register(name, d)
	f := newFixture(t, name)
	opensBefore, closesBefore := d.opens.Load(), d.closes.Load()
	d.panicBegin.Store(true)
	if _, err := f.store.Records(context.Background()); !errors.Is(err, ErrStorage) {
		t.Fatal("read BEGIN panic not failed closed", err)
	}
	if d.closes.Load() <= closesBefore {
		t.Fatal("read connection not discarded")
	}
	if rows, err := f.store.Records(context.Background()); err != nil || len(rows) != 0 || d.opens.Load() <= opensBefore {
		t.Fatal("read did not reopen", err)
	}
}

func TestPanicAfterInitializeBeginDiscardsConnection(t *testing.T) {
	d := &lostDriver{}
	name := fmt.Sprintf("customer-v3-init-panic-%d", driverSequence.Add(1))
	sql.Register(name, d)
	db := database(t, name)
	d.panicBegin.Store(true)
	if err := Initialize(context.Background(), db, id("manager", 1), strings.Repeat("b", 64)); !errors.Is(err, ErrStorage) {
		t.Fatal("init BEGIN panic not failed closed", err)
	}
	if d.closes.Load() == 0 {
		t.Fatal("init connection not discarded")
	}
	if err := Initialize(context.Background(), db, id("manager", 1), strings.Repeat("b", 64)); err != nil {
		t.Fatal("init did not reopen cleanly", err)
	}
}

func TestLateSuccessfulCommitIsUncertain(t *testing.T) {
	d := &lostDriver{}
	name := fmt.Sprintf("customer-v3-late-commit-%d", driverSequence.Add(1))
	sql.Register(name, d)
	f := newFixture(t, name)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	req := request(f.claim(t, key, 21), 21)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	d.delayCommit.Store(true)
	_, err := f.store.Commit(ctx, f.pending, req, f.issuer, f.root, f.clock, f.acquire, f.live, f.storage)
	if !errors.Is(err, ErrUncertain) {
		t.Fatal("late successful commit acknowledged", err)
	}
	rows, err := f.store.Records(context.Background())
	if err != nil || len(rows) != 1 || rows[0].IntentID != req.IntentID {
		t.Fatal("late commit not available for reconciliation", err)
	}
	if err = f.commit(req); !errors.Is(err, ErrConflict) {
		t.Fatal("late commit replayed", err)
	}
}

func TestPostCommitGuardOrClockLossIsUncertain(t *testing.T) {
	for _, mode := range []string{"storage", "clock"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, "sqlite")
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			req := request(f.claim(t, key, 22), 22)
			calls := 0
			guard := func(context.Context) error {
				calls++
				if calls == 3 {
					if mode == "storage" {
						return errors.New("lost storage identity")
					}
					f.now = time.Unix(req.Expected.DeadlineAt, 0).UTC()
				}
				return nil
			}
			_, err := f.store.Commit(context.Background(), f.pending, req, f.issuer, f.root, f.clock, f.acquire, f.live, guard)
			if !errors.Is(err, ErrUncertain) {
				t.Fatal("post-commit loss acknowledged", err)
			}
			rows, err := f.store.Records(context.Background())
			if err != nil || len(rows) != 1 || rows[0].IntentID != req.IntentID {
				t.Fatal("committed intent unavailable for reconciliation", err)
			}
		})
	}
}

func TestReviewLeaseIsHeldUntilAfterCommit(t *testing.T) {
	f := newFixture(t, "sqlite")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	req := request(f.claim(t, key, 7), 7)
	released, committedAtRelease := false, false
	acquire := func(_ context.Context, _ customerclaim.Metadata, digest string, rev uint64) (customerpending.AuthorityLease, error) {
		if digest != f.managerDigest || rev != f.revision {
			return nil, ErrConflict
		}
		return lease{check: func() error { return nil }, release: func() {
			released = true
			rows, err := f.store.Records(context.Background())
			committedAtRelease = err == nil && len(rows) == 1 && rows[0].IntentID == req.IntentID
		}}, nil
	}
	liveReleased, liveCommit := false, false
	live := func(ctx context.Context, actor customerapprovalstore.Actor, fingerprint string) (LiveAuthorityLease, error) {
		inner, err := f.live(ctx, actor, fingerprint)
		if err != nil {
			return nil, err
		}
		return lease{check: inner.Check, release: func() {
			liveReleased = true
			rows, e := f.store.Records(context.Background())
			liveCommit = e == nil && len(rows) == 1 && rows[0].IntentID == req.IntentID
			inner.Release()
		}}, nil
	}
	_, err := f.store.Commit(context.Background(), f.pending, req, f.issuer, f.root, f.clock, acquire, live, f.storage)
	if err != nil || !released || !committedAtRelease || !liveReleased || !liveCommit || f.sessionCalls < 2 || f.issuerCalls < 2 {
		t.Fatal("lease not held through commit", err)
	}
}

func TestStorageGuardBeforeLockAndBeforeCommit(t *testing.T) {
	for _, mode := range []string{"before-lock", "before-commit"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, "sqlite")
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			req := request(f.claim(t, key, 14), 14)
			calls := 0
			blocked := errors.New("storage identity unavailable")
			if mode == "before-lock" {
				if err := f.db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			guard := func(context.Context) error {
				calls++
				if mode == "before-lock" || calls == 2 {
					return blocked
				}
				return nil
			}
			_, err := f.store.Commit(context.Background(), f.pending, req, f.issuer, f.root, f.clock, f.acquire, f.live, guard)
			if !errors.Is(err, blocked) {
				t.Fatal("storage guard not enforced", err)
			}
			if mode == "before-lock" {
				if calls != 1 || f.sessionCalls != 0 || f.issuerCalls != 0 {
					t.Fatal("work occurred before storage guard")
				}
			} else {
				if calls != 2 {
					t.Fatal("final storage guard missing", calls)
				}
				rows, e := f.store.Records(context.Background())
				if e != nil || len(rows) != 0 {
					t.Fatal("unsafe storage committed", e)
				}
				if e = f.commit(req); e != nil {
					t.Fatal("failed guard left locks or state", e)
				}
			}
		})
	}
}

func TestFinalGuardCannotOutliveReviewLease(t *testing.T) {
	f := newFixture(t, "sqlite")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	req := request(f.claim(t, key, 16), 16)
	calls := 0
	guard := func(context.Context) error {
		calls++
		if calls == 2 {
			f.now = f.now.Add(customerpending.MaxReviewLease)
		}
		return nil
	}
	_, err := f.store.Commit(context.Background(), f.pending, req, f.issuer, f.root, f.clock, f.acquire, f.live, guard)
	if !errors.Is(err, ErrInvalid) {
		t.Fatal("expired review lease committed", err)
	}
	rows, err := f.store.Records(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatal("expired review retained", err)
	}
}

func TestLateGuardAndClockLossRollBack(t *testing.T) {
	for _, mode := range []string{"session", "issuer", "clock"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, "sqlite")
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			req := request(f.claim(t, key, 8), 8)
			count := 0
			session := func(ctx context.Context, actor customerapprovalstore.Actor) error {
				count++
				if count == 2 && mode == "session" {
					return errors.New("session ended")
				}
				if count == 2 && mode == "clock" {
					f.now = time.Unix(req.Expected.DeadlineAt, 0).UTC()
				}
				return ctx.Err()
			}
			live := func(ctx context.Context, actor customerapprovalstore.Actor, fingerprint string) (LiveAuthorityLease, error) {
				return lease{check: func() error {
					if err := session(ctx, actor); err != nil {
						return err
					}
					if mode == "issuer" {
						return errors.New("issuer ended")
					}
					return f.issuerGuard(ctx, fingerprint)
				}}, nil
			}
			_, err := f.store.Commit(context.Background(), f.pending, req, f.issuer, f.root, f.clock, f.acquire, live, f.storage)
			if err == nil {
				t.Fatal("lost authority accepted")
			}
			rows, err := f.store.Records(context.Background())
			if err != nil || len(rows) != 0 {
				t.Fatal("lost authority committed", err)
			}
		})
	}
}

func TestEveryManagerSelectedIdentityIsUnique(t *testing.T) {
	for _, field := range []string{"device", "operation", "intent", "serial"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t, "sqlite")
			_, firstKey, _ := ed25519.GenerateKey(rand.Reader)
			first := request(f.claim(t, firstKey, 9), 9)
			if err := f.commit(first); err != nil {
				t.Fatal(err)
			}
			_, secondKey, _ := ed25519.GenerateKey(rand.Reader)
			second := request(f.claim(t, secondKey, 10), 10)
			switch field {
			case "device":
				second.Decision.DeviceID = first.Decision.DeviceID
			case "operation":
				second.Decision.OperationID = first.Decision.OperationID
			case "intent":
				second.IntentID = first.IntentID
			case "serial":
				second.SerialHex = first.SerialHex
			}
			if err := f.commit(second); !errors.Is(err, ErrConflict) {
				t.Fatal("duplicate selected identity accepted", err)
			}
		})
	}
}

func TestMissingMetaCannotBeReinitialized(t *testing.T) {
	f := newFixture(t, "sqlite")
	if _, err := f.db.Exec(`DELETE FROM customer_v3_meta`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Records(context.Background()); !errors.Is(err, ErrStorage) {
		t.Fatal("missing state accepted", err)
	}
	if err := Initialize(context.Background(), f.db, f.manager, f.managerDigest); !errors.Is(err, ErrStorage) {
		t.Fatal("damaged state reinitialized", err)
	}
}

func TestGuardPanicReleasesTransactionAndReview(t *testing.T) {
	f := newFixture(t, "sqlite")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	req := request(f.claim(t, key, 11), 11)
	_, panicErr := f.store.Commit(context.Background(), f.pending, req, f.issuer, f.root, f.clock, f.acquire,
		func(context.Context, customerapprovalstore.Actor, string) (LiveAuthorityLease, error) {
			return lease{check: func() error { panic("fixture guard") }}, nil
		}, f.storage)
	if !errors.Is(panicErr, ErrInvalid) {
		t.Fatal("guard panic not failed closed", panicErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rows, err := f.store.Records(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatal("panic left owner locked or committed", err)
	}
	if err = f.commit(req); err != nil {
		t.Fatal("panic left review locked", err)
	}
}

func TestLiveReleasePanicAfterCommitIsUncertainAndReleasesReview(t *testing.T) {
	f := newFixture(t, "sqlite")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	req := request(f.claim(t, key, 15), 15)
	live := func(context.Context, customerapprovalstore.Actor, string) (LiveAuthorityLease, error) {
		return lease{check: func() error { return nil }, release: func() { panic("fixture release") }}, nil
	}
	_, err := f.store.Commit(context.Background(), f.pending, req, f.issuer, f.root, f.clock, f.acquire, live, f.storage)
	if !errors.Is(err, ErrUncertain) {
		t.Fatal("post-commit panic not uncertain", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rows, err := f.store.Records(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatal("committed state unavailable", err)
	}
	if _, err = f.pending.Records(ctx); err != nil {
		t.Fatal("review lease not released after panic", err)
	}
}

func TestCompetingOwnersSerializeOnDatabase(t *testing.T) {
	f := newFixture(t, "sqlite")
	var seq int
	var schema, path string
	if err := f.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &schema, &path); err != nil {
		t.Fatal(err)
	}
	otherDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer otherDB.Close()
	otherDB.SetMaxOpenConns(1)
	if _, err = f.db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		t.Fatal(err)
	}
	if _, err = otherDB.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		t.Fatal(err)
	}
	other, err := New(otherDB, f.manager, f.managerDigest)
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	first := request(f.claim(t, key, 12), 12)
	second := request(f.claim(t, key, 13), 13)
	var wg sync.WaitGroup
	result := make(chan error, 2)
	for _, item := range []struct {
		store   *Store
		request Request
	}{{f.store, first}, {other, second}} {
		wg.Add(1)
		go func(item struct {
			store   *Store
			request Request
		}) {
			defer wg.Done()
			_, err := item.store.Commit(context.Background(), f.pending, item.request, f.issuer, f.root, f.clock, f.acquire, f.live, f.storage)
			result <- err
		}(item)
	}
	wg.Wait()
	close(result)
	wins, conflicts := 0, 0
	for err := range result {
		if err == nil {
			wins++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("competing owners not serialized", wins, conflicts)
	}
}

func TestCallerCancellationBoundsContendedDatabase(t *testing.T) {
	f := newFixture(t, "sqlite")
	if MaxTransactionDuration <= 0 || MaxTransactionDuration >= customerpending.MaxReviewLease {
		t.Fatal("transaction timeout is not below review lease")
	}
	var seq int
	var schema, path string
	if err := f.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &schema, &path); err != nil {
		t.Fatal(err)
	}
	locker, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	locker.SetMaxOpenConns(1)
	hold, err := locker.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	if _, err = hold.ExecContext(context.Background(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	defer hold.ExecContext(context.Background(), `ROLLBACK`)
	if _, err = f.db.Exec(`PRAGMA busy_timeout=250`); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	req := request(f.claim(t, key, 17), 17)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = f.store.Commit(ctx, f.pending, req, f.issuer, f.root, f.clock, f.acquire, f.live, f.storage)
	if err == nil {
		t.Fatal("contended database committed")
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("fixture did not exercise caller deadline", ctx.Err())
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("contended database did not return within fixture bound")
	}
	if f.sessionCalls != 0 || f.issuerCalls != 0 {
		t.Fatal("authority work occurred despite lock")
	}
}

func TestExpiredContextAtGuardCannotCommit(t *testing.T) {
	f := newFixture(t, "sqlite")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	req := request(f.claim(t, key, 18), 18)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	count := 0
	live := func(c context.Context, _ customerapprovalstore.Actor, _ string) (LiveAuthorityLease, error) {
		return lease{check: func() error {
			count++
			if count == 2 {
				<-c.Done()
			}
			return nil
		}}, nil
	}
	_, err := f.store.Commit(ctx, f.pending, req, f.issuer, f.root, f.clock, f.acquire, live, f.storage)
	if err == nil {
		t.Fatal("expired context committed")
	}
	rows, err := f.store.Records(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatal("expired authority retained", err)
	}
}

func TestStorageGuardReceivesBoundedContext(t *testing.T) {
	f := newFixture(t, "sqlite")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	req := request(f.claim(t, key, 19), 19)
	deadlineObserved := false
	stop := errors.New("fixture preflight stopped")
	guard := func(ctx context.Context) error {
		d, ok := ctx.Deadline()
		deadlineObserved = ok && time.Until(d) > 0 && time.Until(d) <= MaxTransactionDuration
		return stop
	}
	_, err := f.store.Commit(context.Background(), f.pending, req, f.issuer, f.root, f.clock, f.acquire, f.live, guard)
	if !errors.Is(err, stop) || !deadlineObserved {
		t.Fatal("preflight did not receive bounded context", err)
	}
}
