package windowsservice

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func nextStatus(t *testing.T, c <-chan status) status {
	t.Helper()
	select {
	case s := <-c:
		return s
	case <-time.After(2 * time.Second):
		t.Fatal("timed out awaiting fixture status")
		return status{}
	}
}
func nextError(t *testing.T, c <-chan error) error {
	t.Helper()
	select {
	case err := <-c:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timed out awaiting fixture worker")
		return nil
	}
}
func TestRuntimeReadyStopWaitsForWorker(t *testing.T) {
	controls := make(chan control)
	statuses := make(chan status, 16)
	finished := make(chan error, 1)
	readyGate := make(chan struct{})
	cancelSeen := make(chan struct{})
	exitGate := make(chan struct{})
	worker := func(ctx context.Context, ready func()) error {
		<-readyGate
		ready()
		ready()
		<-ctx.Done()
		close(cancelSeen)
		<-exitGate
		return ctx.Err()
	}
	go func() {
		finished <- runLifecycle(context.Background(), worker, controls, func(s status) { statuses <- s })
	}()
	if s := nextStatus(t, statuses); s.State != StartPending || s.AcceptStop || s.CheckPoint == 0 {
		t.Fatal(s)
	}
	close(readyGate)
	if s := nextStatus(t, statuses); s.State != Running || !s.AcceptStop || !s.AcceptShutdown || s.CheckPoint != 0 || s.WaitHint != 0 {
		t.Fatal(s)
	}
	controls <- controlInterrogate
	if s := nextStatus(t, statuses); s.State != Running {
		t.Fatal(s)
	}
	controls <- controlStop
	if s := nextStatus(t, statuses); s.State != StopPending || s.AcceptStop {
		t.Fatal(s)
	}
	select {
	case <-cancelSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("worker not cancelled")
	}
	select {
	case <-finished:
		t.Fatal("reported completion with live worker")
	default:
	}
	close(exitGate)
	if s := nextStatus(t, statuses); s.State != Stopped {
		t.Fatal(s)
	}
	if err := nextError(t, finished); err != nil {
		t.Fatal(err)
	}
}
func TestRuntimeShutdownDuringInitialization(t *testing.T) {
	for _, stop := range []control{controlStop, controlShutdown} {
		t.Run(string(rune('0'+stop)), func(t *testing.T) {
			controls := make(chan control)
			statuses := make(chan status, 16)
			done := make(chan error, 1)
			go func() {
				done <- runLifecycle(context.Background(), func(ctx context.Context, ready func()) error { <-ctx.Done(); ready(); return ctx.Err() }, controls, func(s status) { statuses <- s })
			}()
			if nextStatus(t, statuses).State != StartPending {
				t.Fatal("not starting")
			}
			controls <- stop
			var states []State
			for {
				s := nextStatus(t, statuses)
				states = append(states, s.State)
				if s.State == Stopped {
					break
				}
			}
			if !reflect.DeepEqual(states, []State{StopPending, Stopped}) {
				t.Fatal(states)
			}
			if err := nextError(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestRuntimeWorkerFailureNeverReportsRunning(t *testing.T) {
	want := errors.New("fixture startup rejected")
	var states []State
	err := runLifecycle(context.Background(), func(context.Context, func()) error { return want }, nil, func(s status) { states = append(states, s.State) })
	if !errors.Is(err, want) || !reflect.DeepEqual(states, []State{StartPending, StopPending, Stopped}) {
		t.Fatal(states, err)
	}
}
func TestRuntimeUnexpectedSuccessIsFailure(t *testing.T) {
	if err := runLifecycle(context.Background(), func(context.Context, func()) error { return nil }, nil, func(status) {}); err == nil {
		t.Fatal("unexpected worker exit reported success")
	}
}
func TestRuntimeParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	statuses := make(chan status, 16)
	done := make(chan error, 1)
	go func() {
		done <- runLifecycle(ctx, func(ctx context.Context, ready func()) error { ready(); <-ctx.Done(); return ctx.Err() }, nil, func(s status) { statuses <- s })
	}()
	nextStatus(t, statuses)
	nextStatus(t, statuses)
	cancel()
	if nextStatus(t, statuses).State != StopPending || nextStatus(t, statuses).State != Stopped {
		t.Fatal("bad cancelled transition")
	}
	if err := nextError(t, done); err != nil {
		t.Fatal(err)
	}
}
func TestRuntimeTokenRestrictions(t *testing.T) {
	safe := runtimeIdentity{UserSID: LocalServiceSID, Groups: []identityGroup{{SID: fixtureSID, Enabled: true, Owner: true}}}
	if err := validateIdentity(safe, fixtureSID); err != nil {
		t.Fatal(err)
	}
	cases := map[string]runtimeIdentity{
		"LocalSystem":         {UserSID: "S-1-5-18", Groups: safe.Groups},
		"ordinary user":       {UserSID: "S-1-5-21-1-2-3-1001", Groups: safe.Groups},
		"missing service SID": {UserSID: LocalServiceSID},
		"disabled SID":        {UserSID: LocalServiceSID, Groups: []identityGroup{{SID: fixtureSID, Owner: true}}},
		"not owner":           {UserSID: LocalServiceSID, Groups: []identityGroup{{SID: fixtureSID, Enabled: true}}},
		"deny only":           {UserSID: LocalServiceSID, Groups: []identityGroup{{SID: fixtureSID, Enabled: true, Owner: true, DenyOnly: true}}},
		"administrator":       {UserSID: LocalServiceSID, Groups: append(append([]identityGroup{}, safe.Groups...), identityGroup{SID: "S-1-5-32-544", Enabled: true})},
		"extra privilege":     {UserSID: LocalServiceSID, Groups: safe.Groups, UnexpectedPrivilege: true},
	}
	for name, identity := range cases {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(validateIdentity(identity, fixtureSID), ErrUnsafeIdentity) {
				t.Fatal("unsafe token accepted")
			}
		})
	}
}

func TestRuntimeInstallationBinding(t *testing.T) {
	b, _ := installedFixture(t)
	safe := b.s.snapshot
	safe.State = StartPending
	safe.ProcessID = 123
	if err := validateRuntimeInstallation(b.layout, safe, b.layout.Executable, fixtureHash, 123); err != nil {
		t.Fatal(err)
	}
	safe.ProcessID = 0 // SCM PID is not guaranteed valid in START_PENDING.
	if err := validateRuntimeInstallation(b.layout, safe, b.layout.Executable, fixtureHash, 123); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Snapshot, *string, *string, *uint32){
		"wrong process":    func(s *Snapshot, e, h *string, p *uint32) { s.State = Running; *p = 456 },
		"wrong image path": func(s *Snapshot, e, h *string, p *uint32) { *e = `D:\other.exe` },
		"wrong hash":       func(s *Snapshot, e, h *string, p *uint32) { *h = "bad" },
		"stopped":          func(s *Snapshot, e, h *string, p *uint32) { s.State = Stopped },
		"foreign marker":   func(s *Snapshot, e, h *string, p *uint32) { s.Configuration.Description = "foreign" },
		"LocalSystem":      func(s *Snapshot, e, h *string, p *uint32) { s.Configuration.Account = "LocalSystem" },
		"unexpected args":  func(s *Snapshot, e, h *string, p *uint32) { s.Configuration.BinaryPath += ` "--other"` },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := safe
			exe, hash, pid := b.layout.Executable, fixtureHash, uint32(123)
			change(&snapshot, &exe, &hash, &pid)
			if !errors.Is(validateRuntimeInstallation(b.layout, snapshot, exe, hash, pid), ErrMismatch) {
				t.Fatal("runtime binding mismatch accepted")
			}
		})
	}
}
