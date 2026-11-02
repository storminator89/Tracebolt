package operatorauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type memoryAccounts struct {
	mu       sync.Mutex
	snapshot AccountSnapshot
	audits   []AccountAudit
	fail     bool
}

func (s *memoryAccounts) Load(context.Context) (AccountSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copySnapshot(s.snapshot), nil
}
func (s *memoryAccounts) Commit(_ context.Context, t AccountTransition) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return ErrAuthorityUncertain
	}
	if !validMemoryTransition(s.snapshot, t) {
		return ErrAccountConflict
	}
	s.snapshot = copySnapshot(t.Next)
	s.audits = append(s.audits, t.Audit)
	return nil
}

// Keep portable core tests independent of the Linux journal implementation.
func validMemoryTransition(before AccountSnapshot, t AccountTransition) bool {
	return t.PreviousRevision == before.Revision && t.Next.Revision == before.Revision+1 && t.Audit.Revision == t.Next.Revision
}
func accountFixture(t *testing.T) (*Manager, *memoryAccounts, Session, Session) {
	t.Helper()
	s := &memoryAccounts{snapshot: AccountSnapshot{AuthorityID: "authority_11111111111111111111111111111111", Profile: "tls", Version: AccountVersion, Revision: 1, Accounts: []AccountRecord{
		{Operator: Operator{ID: "operator_00000000000000000000000000000001", Username: "admin", PasswordHash: fixtureHash(), Capabilities: []Capability{Read, ManageAccounts}}, Revision: 1},
		{Operator: Operator{ID: "operator_00000000000000000000000000000002", Username: "worker", PasswordHash: fixtureHash(), Capabilities: []Capability{Read, RestartService}}, Revision: 1},
	}}}
	m, err := New(Config{AuthorityID: "authority_11111111111111111111111111111111", AuthorityProfile: "tls", AuthorityStore: s})
	if err != nil {
		t.Fatal(err)
	}
	return m, s, seedLiveSession(m, "admin", 1), seedLiveSession(m, "worker", 2)
}
func seedLiveSession(m *Manager, name string, n int) Session {
	e := m.live.byName[name]
	v := e.current.Load()
	life, cancel := context.WithCancel(context.Background())
	token := fmt.Sprintf("%064x", n)
	s := Session{ID: fmt.Sprintf("%032x", n), Token: token, actor: v.principal, account: e, accountRevision: v.record.Revision, lifetime: life, revoke: cancel, ExpiresAt: m.now().Add(DefaultTTL), gate: &sessionGate{now: m.now, expires: m.now().Add(DefaultTTL)}}
	s.actor.verifier = verifier{}
	m.sessions[sha256.Sum256([]byte(token))] = s
	return s
}
func changeFor(s Session) AccountChange {
	return AccountChange{TargetID: s.ActorID(), ExpectedRevision: s.ApprovalEpoch(), Capabilities: []Capability{Read, RestartService}}
}
func awaitAccount(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("account transition did not drain")
		return nil
	}
}

func TestLiveAccountsRevokeSessionsAndPersistAudit(t *testing.T) {
	for _, kind := range []string{"disable", "permissions", "password", "reset"} {
		t.Run(kind, func(t *testing.T) {
			m, store, admin, worker := accountFixture(t)
			copied := worker
			change := changeFor(worker)
			switch kind {
			case "disable":
				change.Disabled = true
			case "permissions":
				change.Capabilities = []Capability{Read}
			case "password":
				change.PasswordHash = fixtureHash()
			case "reset":
				change.ResetCredentials = true
			}
			if err := m.ChangeAccount(context.Background(), admin, change); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Lookup(worker.Token); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("old cookie survived")
			}
			if release, err := copied.BeginCapability(context.Background(), Read); err == nil {
				release()
				t.Fatal("copied session survived")
			}
			if worker.Lifetime().Err() == nil {
				t.Fatal("worker lifetime not cancelled")
			}
			if release, err := admin.BeginCapability(context.Background(), Read); err != nil {
				t.Fatal("unrelated account lost admission")
			} else {
				release()
			}
			if len(store.audits) != 1 || store.audits[0].TargetID != worker.ActorID() || store.audits[0].Previous != 1 || store.audits[0].Current != 2 || store.snapshot.Revision != 2 {
				t.Fatal("revision and audit not committed together")
			}
			if len(m.sessions) != 1 {
				t.Fatal("drained sessions still occupy quota")
			}
		})
	}
}
func TestLiveAccountLeasesDrainAndRejectNewWork(t *testing.T) {
	m, _, admin, worker := accountFixture(t)
	lease, err := m.BeginActorAdmission(context.Background(), worker.ActorID(), 1, RestartService)
	if err != nil {
		t.Fatal(err)
	}
	defer lease()
	sessionRelease, err := worker.BeginCapability(context.Background(), RestartService)
	if err != nil {
		t.Fatal(err)
	}
	defer sessionRelease()
	done := make(chan error, 1)
	go func() {
		c := changeFor(worker)
		c.Disabled = true
		done <- m.ChangeAccount(context.Background(), admin, c)
	}()
	select {
	case <-worker.Lifetime().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("did not fence new admission")
	}
	if r, e := m.BeginActorAdmission(context.Background(), worker.ActorID(), 1, RestartService); e == nil {
		r()
		t.Fatal("admitted after pending revoke")
	}
	if r, e := admin.BeginCapability(context.Background(), Read); e != nil {
		t.Fatal(e)
	} else {
		r()
	}
	select {
	case <-done:
		t.Fatal("returned with lease outstanding")
	default:
	}
	lease()
	select {
	case <-done:
		t.Fatal("returned with session admission outstanding")
	default:
	}
	sessionRelease()
	if e := awaitAccount(t, done); e != nil {
		t.Fatal(e)
	}
}
func TestLiveAccountRegrantNeverRevivesOldEpoch(t *testing.T) {
	m, store, admin, worker := accountFixture(t)
	c := changeFor(worker)
	c.Capabilities = []Capability{Read}
	if e := m.ChangeAccount(context.Background(), admin, c); e != nil {
		t.Fatal(e)
	}
	c.ExpectedRevision = 2
	c.Capabilities = []Capability{Read, RestartService}
	if e := m.ChangeAccount(context.Background(), admin, c); e != nil {
		t.Fatal(e)
	}
	for _, manager := range []*Manager{m, func() *Manager {
		v, e := New(Config{AuthorityID: "authority_11111111111111111111111111111111", AuthorityProfile: "tls", AuthorityStore: store})
		if e != nil {
			t.Fatal(e)
		}
		return v
	}()} {
		for _, epoch := range []uint64{0, 1, 2} {
			if r, e := manager.BeginActorAdmission(context.Background(), worker.ActorID(), epoch, RestartService); e == nil {
				r()
				t.Fatal("old/unbound approval revived")
			}
		}
		if r, e := manager.BeginActorAdmission(context.Background(), worker.ActorID(), 3, RestartService); e != nil {
			t.Fatal(e)
		} else {
			r()
		}
	}
}
func TestLiveAccountCommitFailureFreezesOnlyTarget(t *testing.T) {
	m, store, admin, worker := accountFixture(t)
	store.fail = true
	if e := m.ChangeAccount(context.Background(), admin, changeFor(worker)); !errors.Is(e, ErrAuthorityUncertain) {
		t.Fatal(e)
	}
	if m.ActorHasCapability(worker.ActorID(), RestartService) {
		t.Fatal("uncertain target retained authority")
	}
	if r, e := m.BeginActorAdmission(context.Background(), worker.ActorID(), 1, RestartService); e == nil {
		r()
		t.Fatal("uncertain target admitted")
	}
	if r, e := admin.BeginCapability(context.Background(), ManageAccounts); e != nil {
		t.Fatal(e)
	} else {
		r()
	}
	if len(store.audits) != 0 || store.snapshot.Revision != 1 {
		t.Fatal("failed audit reported committed")
	}
	if e := m.ChangeAccount(context.Background(), admin, changeFor(worker)); !errors.Is(e, ErrAuthorityUncertain) {
		t.Fatal("uncertain transition retried", e)
	}
}

type hashPauseContext struct {
	context.Context
	calls          int
	ready, proceed chan struct{}
}

func (c *hashPauseContext) Err() error {
	c.calls++
	if c.calls == 2 {
		close(c.ready)
		<-c.proceed
	}
	return c.Context.Err()
}
func TestLiveAccountLoginRejectsVerifierRevisionAfterHash(t *testing.T) {
	m, _, admin, worker := accountFixture(t)
	ctx := &hashPauseContext{Context: context.Background(), ready: make(chan struct{}), proceed: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, e := m.LoginNamed(ctx, "127.0.0.1", "worker", fixturePassword); done <- e }()
	select {
	case <-ctx.ready:
	case <-time.After(10 * time.Second):
		t.Fatal("password check did not finish")
	}
	c := changeFor(worker)
	c.ResetCredentials = true
	if e := m.ChangeAccount(context.Background(), admin, c); e != nil {
		close(ctx.proceed)
		t.Fatal(e)
	}
	close(ctx.proceed)
	if e := awaitAccount(t, done); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("old verifier minted a session", e)
	}
	if _, e := m.LoginNamed(context.Background(), "127.0.0.2", "worker", fixturePassword); e != nil {
		t.Fatal("fresh credential revision failed", e)
	}
}
func TestLiveAccountExplicitGrantAndLastAdministrator(t *testing.T) {
	m, _, admin, worker := accountFixture(t)
	if e := m.ChangeAccount(context.Background(), worker, changeFor(worker)); !errors.Is(e, ErrForbidden) {
		t.Fatal("ordinary read managed accounts", e)
	}
	c := changeFor(admin)
	c.Disabled = true
	if e := m.ChangeAccount(context.Background(), admin, c); !errors.Is(e, ErrConfiguration) {
		t.Fatal("last administrator removed", e)
	}
	if capabilityBit(ManageAccounts) != 65536 || capabilityBit(ReadCustomers) != 32768 {
		t.Fatal("capability bits aliased")
	}
	if _, e := New(Config{AuthorityID: "authority_11111111111111111111111111111111", AuthorityProfile: "tls", AuthorityStore: m.live.store, Operators: []Operator{}}); !errors.Is(e, ErrConfiguration) {
		t.Fatal("mixed authority admitted")
	}
}
func TestLiveAccountSelfResetAndConcurrentRevisionCAS(t *testing.T) {
	m, store, admin, worker := accountFixture(t)
	c := changeFor(admin)
	c.Capabilities = []Capability{Read, ManageAccounts}
	c.ResetCredentials = true
	if e := m.ChangeAccount(context.Background(), admin, c); e != nil {
		t.Fatal(e)
	}
	if admin.Lifetime().Err() == nil {
		t.Fatal("self reset retained session")
	}
	admin = seedLiveSession(m, "admin", 3)
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { done <- m.ChangeAccount(context.Background(), admin, changeFor(worker)) }()
	}
	a, b := awaitAccount(t, done), awaitAccount(t, done)
	if !(a == nil && errors.Is(b, ErrAccountConflict) || b == nil && errors.Is(a, ErrAccountConflict)) {
		t.Fatal("CAS did not select exactly one transition", a, b)
	}
	if len(store.audits) != 2 {
		t.Fatal("duplicate durable transition")
	}
}

func TestReviewRevokedRequesterCannotCommitAfterLeaseWait(t *testing.T) {
	m, store, admin, worker := accountFixture(t)
	lease, e := m.BeginActorAdmission(context.Background(), worker.ActorID(), 1, RestartService)
	if e != nil {
		t.Fatal(e)
	}
	defer lease()
	done := make(chan error, 1)
	go func() { done <- m.ChangeAccount(context.Background(), admin, changeFor(worker)) }()
	select {
	case <-worker.Lifetime().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("target not fenced")
	}
	logout := make(chan struct{})
	go func() { m.Logout(admin.Token); close(logout) }()
	select {
	case <-admin.Lifetime().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("requester not revoked")
	}
	lease()
	e = awaitAccount(t, done)
	select {
	case <-logout:
	case <-time.After(5 * time.Second):
		t.Fatal("logout did not drain")
	}
	if e == nil || len(store.audits) != 0 {
		t.Fatalf("revoked requester committed transition: err=%v audits=%d", e, len(store.audits))
	}
}
