package windowsservice

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type stagedServiceFixture struct {
	*fakeService
	transitions       int
	transitionErr     error
	changeBeforeError bool
	closeErr          error
}

func (s *stagedServiceFixture) Close() error {
	return s.closeErr
}

func (s *stagedServiceFixture) SetAutomatic() error {
	s.transitions++
	if s.transitionErr == nil || s.changeBeforeError {
		s.snapshot.Configuration.StartType = 2
	}
	return s.transitionErr
}

type stagedBackendFixture struct {
	*fakeBackend
	staged *stagedServiceFixture
}

func (b *stagedBackendFixture) Open(a access) (service, error) {
	s, err := b.fakeBackend.Open(a)
	if err != nil {
		return s, err
	}
	return b.staged, nil
}
func (b *stagedBackendFixture) Create(c Configuration) (service, error) {
	_, err := b.fakeBackend.Create(c)
	b.staged = &stagedServiceFixture{fakeService: b.fakeBackend.s}
	return b.staged, err
}
func stagedFixture(t *testing.T) (*stagedBackendFixture, Receipt) {
	t.Helper()
	b := &stagedBackendFixture{fakeBackend: fixtureBackend(t)}
	p, err := plan(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	p.Configuration.StartType = 4
	r, err := installMode(context.Background(), b, p, true)
	if err != nil || r.Version != 2 || !r.Complete || b.staged.snapshot.Configuration.StartType != 4 {
		t.Fatal("disabled staging failed", err)
	}
	return b, r
}
func TestFreshReadSetupStaysDisabledAndOrdinaryLifecycleRejectsReceipt(t *testing.T) {
	b, r := stagedFixture(t)
	for _, a := range []access{startAccess, stopAccess, deleteAccess} {
		if _, err := apply(context.Background(), b, r, a); err == nil {
			t.Fatal("ordinary lifecycle accepted staged receipt")
		}
	}
	if b.staged.starts+b.staged.stops+b.staged.deletes+b.staged.transitions != 0 {
		t.Fatal("staged service mutated")
	}
	s, snapshot, err := openOwnedMode(context.Background(), b, r, readAccess, true, true)
	if err != nil || snapshot.State != Stopped {
		t.Fatal(err)
	}
	_ = s.Close()
	next, err := activateFreshReadSetup(context.Background(), b, r)
	if err != nil || next.Version != 1 || next.InstallationID != r.InstallationID || next.ServiceSID != r.ServiceSID || b.staged.transitions != 1 || b.staged.starts != 0 {
		t.Fatal("wrong one-way transition", err)
	}
	if _, _, err = openOwned(context.Background(), b, next, readAccess, true); err != nil {
		t.Fatal(err)
	}
	if _, err = activateFreshReadSetup(context.Background(), b, r); err == nil || b.staged.transitions != 1 {
		t.Fatal("transition was retried/adopted")
	}
}
func TestFreshReadSetupRejectsUnknownAndRunningBindingsBeforeTransition(t *testing.T) {
	for _, mutation := range []func(*stagedBackendFixture, *Receipt){
		func(b *stagedBackendFixture, r *Receipt) { r.Version = 1 },
		func(b *stagedBackendFixture, r *Receipt) { r.Complete = false },
		func(b *stagedBackendFixture, r *Receipt) { b.staged.snapshot.State = Running },
		func(b *stagedBackendFixture, r *Receipt) { b.staged.snapshot.Configuration.StartType = 3 },
		func(b *stagedBackendFixture, r *Receipt) { b.staged.snapshot.Configuration.BinaryPath += " foreign" },
		func(b *stagedBackendFixture, r *Receipt) { b.staged.snapshot.ServiceSID = "S-1-5-80-5-4-3-2-1" },
		func(b *stagedBackendFixture, r *Receipt) { b.hash = "changed" },
	} {
		b, r := stagedFixture(t)
		mutation(b, &r)
		if _, err := activateFreshReadSetup(context.Background(), b, r); err == nil || b.staged.transitions != 0 {
			t.Fatal("unowned/running state transitioned")
		}
	}
}
func TestFreshReadSetupIndeterminateTransitionOnlyReadOnlyReconciliation(t *testing.T) {
	for _, changed := range []bool{false, true} {
		b, r := stagedFixture(t)
		b.staged.transitionErr = errors.New("synthetic uncertain result")
		b.staged.changeBeforeError = changed
		if _, err := activateFreshReadSetup(context.Background(), b, r); err == nil {
			t.Fatal("uncertain transition completed")
		}
		got, err := reconcileFreshReadSetup(context.Background(), b, r)
		want := r
		if changed {
			want = automaticReceipt(r)
		}
		if err != nil || !reflect.DeepEqual(got, want) || b.staged.transitions != 1 {
			t.Fatal("reconciliation mutated or misidentified", err)
		}
		b.staged.snapshot.Configuration.RequiredPrivileges = append(b.staged.snapshot.Configuration.RequiredPrivileges, "SeDebugPrivilege")
		if _, err = reconcileFreshReadSetup(context.Background(), b, r); err == nil {
			t.Fatal("adopted changed service")
		}
	}
}
func TestFreshReadSetupPlanAdmissionDoesNotBroadenOrdinaryInstall(t *testing.T) {
	b := fixtureBackend(t)
	p, err := plan(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	p.Configuration.StartType = 4
	if _, err = install(context.Background(), b, p); err == nil || b.created != 0 {
		t.Fatal("ordinary install admitted disabled plan")
	}
	p.Configuration.StartType = 2
	if _, err = installMode(context.Background(), b, p, true); err == nil || b.created != 0 {
		t.Fatal("staged install admitted automatic plan")
	}
}

func TestFreshReadSetupCloseFailureRemainsIndeterminate(t *testing.T) {
	b, r := stagedFixture(t)
	closeErr := errors.New("synthetic SCM handle close failure")
	b.staged.closeErr = closeErr
	next, err := activateFreshReadSetup(context.Background(), b, r)
	if !errors.Is(err, closeErr) || next != (Receipt{}) || b.staged.transitions != 1 || b.staged.starts != 0 {
		t.Fatalf("close failure reported completed transition: receipt=%+v err=%v", next, err)
	}
	if b.staged.snapshot.Configuration.StartType != 2 {
		t.Fatal("fixture must retain the completed but indeterminate automatic effect")
	}
	b.staged.closeErr = nil
	reconciled, err := reconcileFreshReadSetup(context.Background(), b, r)
	if err != nil || reconciled != automaticReceipt(r) || b.staged.transitions != 1 || b.staged.starts != 0 {
		t.Fatal("read-only reconciliation failed or replayed effect", err)
	}
}
