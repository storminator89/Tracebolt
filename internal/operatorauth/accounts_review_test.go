package operatorauth

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
)

func reviewTwoAdmins(t *testing.T) (*Manager, *memoryAccounts, Session, Session) {
	t.Helper()
	_, store, _, _ := accountFixture(t)
	store.snapshot.Accounts[1].Operator.Capabilities = []Capability{Read, ManageAccounts, RestartService}
	m, e := New(Config{AuthorityStore: store, AuthorityID: store.snapshot.AuthorityID, AuthorityProfile: store.snapshot.Profile})
	if e != nil {
		t.Fatal(e)
	}
	return m, store, seedLiveSession(m, "admin", 1), seedLiveSession(m, "worker", 2)
}

func TestReviewCrossedAccountDisablesCannotDeadlockOrRemoveBothAdmins(t *testing.T) {
	for i := 0; i < 20; i++ {
		m, store, a, b := reviewTwoAdmins(t)
		start := make(chan struct{})
		done := make(chan error, 2)
		for _, pair := range [][2]Session{{a, b}, {b, a}} {
			pair := pair
			go func() {
				<-start
				done <- m.ChangeAccount(context.Background(), pair[0], AccountChange{TargetID: pair[1].ActorID(), ExpectedRevision: 1, Disabled: true, Capabilities: pair[1].Capabilities()})
			}()
		}
		close(start)
		x, y := awaitAccount(t, done), awaitAccount(t, done)
		if !(x == nil && errors.Is(y, ErrUnauthenticated) || y == nil && errors.Is(x, ErrUnauthenticated)) {
			t.Fatalf("crossed updates were not serialized safely: %v / %v", x, y)
		}
		if len(store.audits) != 1 {
			t.Fatal("crossed updates both committed")
		}
		active := 0
		for _, s := range []Session{a, b} {
			if r, e := s.BeginCapability(context.Background(), ManageAccounts); e == nil {
				r()
				active++
			}
		}
		if active != 1 {
			t.Fatal("crossed disable lost surviving administrator")
		}
	}
}

func TestReviewSelfDisablePreservesSecondAdministrator(t *testing.T) {
	m, store, a, b := reviewTwoAdmins(t)
	if e := m.ChangeAccount(context.Background(), a, AccountChange{TargetID: a.ActorID(), ExpectedRevision: 1, Disabled: true, Capabilities: a.Capabilities()}); e != nil {
		t.Fatal(e)
	}
	if a.Lifetime().Err() == nil || len(store.audits) != 1 {
		t.Fatal("self disable did not revoke and audit")
	}
	if r, e := a.BeginCapability(context.Background(), Read); e == nil {
		r()
		t.Fatal("self-disabled session survived")
	}
	if r, e := b.BeginCapability(context.Background(), ManageAccounts); e != nil {
		t.Fatal("other administrator blocked", e)
	} else {
		r()
	}
}

func TestReviewNestedActorProofSurvivesQueuedWriterWithoutRecursiveRead(t *testing.T) {
	m, _, admin, worker := accountFixture(t)
	ctx, outer, e := m.LeaseActor(context.Background(), worker.ActorID(), 1, Read, RestartService)
	if e != nil {
		t.Fatal(e)
	}
	defer outer()
	done := make(chan error, 1)
	go func() {
		c := changeFor(worker)
		c.Disabled = true
		done <- m.ChangeAccount(context.Background(), admin, c)
	}()
	select {
	case <-worker.Lifetime().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not fence target")
	}
	// The held root reader prevents acquisition; failed TryRLock proves the
	// writer is actually queued before the nested call (not merely marked).
	deadline := time.Now().Add(5 * time.Second)
	for worker.account.lease.TryRLock() {
		worker.account.lease.RUnlock()
		if time.Now().After(deadline) {
			t.Fatal("writer did not queue behind root lease")
		}
		runtime.Gosched()
	}
	type nested struct {
		release func()
		err     error
	}
	got := make(chan nested, 1)
	go func() { _, r, e := m.LeaseActor(ctx, worker.ActorID(), 1, RestartService); got <- nested{r, e} }()
	var inner func()
	select {
	case n := <-got:
		if n.err != nil {
			t.Fatal(n.err)
		}
		inner = n.release
	case <-time.After(5 * time.Second):
		t.Fatal("recursive actor admission deadlocked behind writer")
	}
	defer inner()
	outer()
	select {
	case <-done:
		t.Fatal("root release dropped outstanding nested proof")
	default:
	}
	if _, r, e := m.LeaseActor(ctx, worker.ActorID(), 1, RestartService); e == nil {
		r()
		t.Fatal("closed root proof admitted a new borrower")
	}
	inner()
	if e := awaitAccount(t, done); e != nil {
		t.Fatal(e)
	}
	if _, r, e := m.LeaseActor(ctx, worker.ActorID(), 1, RestartService); e == nil {
		r()
		t.Fatal("released proof revived revoked epoch")
	}
}

func TestReviewActorProofRejectsScopeAndEpochUpgrade(t *testing.T) {
	m, _, _, worker := accountFixture(t)
	ctx, release, e := m.LeaseActor(context.Background(), worker.ActorID(), 1, Read)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	for _, tc := range []struct {
		epoch uint64
		cap   Capability
	}{{1, RestartService}, {2, Read}} {
		if _, r, e := m.LeaseActor(ctx, worker.ActorID(), tc.epoch, tc.cap); e == nil {
			r()
			t.Fatal("held proof upgraded authority")
		}
	}
}

func TestReviewSelfResetDoesNotHideConcurrentLogout(t *testing.T) {
	m, store, admin, _ := accountFixture(t)
	lease, e := m.BeginActorAdmission(context.Background(), admin.ActorID(), 1, ManageAccounts)
	if e != nil {
		t.Fatal(e)
	}
	defer lease()
	done := make(chan error, 1)
	go func() {
		done <- m.ChangeAccount(context.Background(), admin, AccountChange{TargetID: admin.ActorID(), ExpectedRevision: 1, Capabilities: admin.Capabilities(), ResetCredentials: true})
	}()
	select {
	case <-admin.Lifetime().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("self reset not fenced")
	}
	logout := make(chan struct{})
	go func() { m.Logout(admin.Token); close(logout) }()
	deadline := time.Now().Add(5 * time.Second)
	for admin.gate.revocationSerial.Load() < 2 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if admin.gate.revocationSerial.Load() < 2 {
		t.Fatal("concurrent logout not observed")
	}
	lease()
	e = awaitAccount(t, done)
	select {
	case <-logout:
	case <-time.After(5 * time.Second):
		t.Fatal("logout did not drain")
	}
	if e == nil || len(store.audits) != 0 {
		t.Fatal("self reset ignored independent logout", e)
	}
}
