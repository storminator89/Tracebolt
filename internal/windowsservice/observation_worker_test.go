package windowsservice

import (
	"context"
	"errors"
	"testing"
)

func TestObservationWorkerExactRestrictedIdentityAndRunningParent(t *testing.T) {
	b, _ := installedFixture(t)
	b.s.snapshot.State, b.s.snapshot.ProcessID = Running, 123
	baseline, err := validateObservationWorker(context.Background(), func() error { return nil }, b, b.layout.Executable, observationWorkerProcess{456, 123, 200, 100, true})
	if err != nil || baseline.ParentProcessID != 123 || baseline.ServiceSID != fixtureSID || baseline.ExecutableSHA256 != fixtureHash || baseline.Layout != b.layout {
		t.Fatal("worker binding", err)
	}
	for name, mutate := range map[string]func(*fakeBackend){
		"no parent":             func(b *fakeBackend) { b.s.snapshot.ProcessID = 0 },
		"stopped":               func(b *fakeBackend) { b.s.snapshot.State = Stopped },
		"starting":              func(b *fakeBackend) { b.s.snapshot.State = StartPending },
		"same process":          func(b *fakeBackend) { b.s.snapshot.ProcessID = 456 },
		"foreign sid":           func(b *fakeBackend) { b.s.snapshot.ServiceSID = "S-1-5-80-9-8-7-6-5" },
		"foreign hash":          func(b *fakeBackend) { b.hash = "bad" },
		"foreign configuration": func(b *fakeBackend) { b.s.snapshot.Configuration.BinaryPath += " --extra" },
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := installedFixture(t)
			b.s.snapshot.State, b.s.snapshot.ProcessID = Running, 123
			mutate(b)
			if _, err := validateObservationWorker(context.Background(), func() error { return nil }, b, b.layout.Executable, observationWorkerProcess{456, 123, 200, 100, true}); err == nil {
				t.Fatal("unsafe worker admitted")
			}
		})
	}
	// The baseline changes if a different running parent replaces it.
	b.s.snapshot.ProcessID = 789
	replaced, err := validateObservationWorker(context.Background(), func() error { return nil }, b, b.layout.Executable, observationWorkerProcess{456, 789, 200, 100, true})
	if err != nil || replaced == baseline {
		t.Fatal("parent replacement hidden", err)
	}
	if b.s.starts != 0 || b.s.stops != 0 || b.s.deletes != 0 {
		t.Fatal("worker changed SCM")
	}
	for _, a := range b.opened {
		if a != readAccess {
			t.Fatal("worker requested mutation")
		}
	}
}
func TestObservationWorkerIdentityFailurePrecedesStateReads(t *testing.T) {
	b, _ := installedFixture(t)
	b.opened = nil
	b.verified = 0
	if _, err := validateObservationWorker(context.Background(), func() error { return ErrUnsafeIdentity }, b, b.layout.Executable, observationWorkerProcess{456, 123, 200, 100, true}); !errors.Is(err, ErrUnsafeIdentity) {
		t.Fatal(err)
	}
	if len(b.opened) != 0 || b.verified != 0 {
		t.Fatal("unrestricted identity reached private state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := validateObservationWorker(ctx, func() error { t.Fatal("canceled invocation read token"); return nil }, b, b.layout.Executable, observationWorkerProcess{456, 123, 200, 100, true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestObservationWorkerRejectsOrphanAndPIDReuse(t *testing.T) {
	b, _ := installedFixture(t)
	b.s.snapshot.State, b.s.snapshot.ProcessID = Running, 123
	for _, process := range []observationWorkerProcess{
		{456, 789, 200, 100, true},  // actual creator differs from current SCM process
		{456, 123, 200, 300, true},  // creator PID was reused after worker creation
		{456, 123, 200, 200, true},  // ambiguous creation ordering
		{456, 123, 200, 100, false}, // exited parent
		{456, 123, 200, 0, true},
	} {
		if _, err := validateObservationWorker(context.Background(), func() error { return nil }, b, b.layout.Executable, process); err == nil {
			t.Fatal("orphan/reused parent admitted")
		}
	}
}
