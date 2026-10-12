package windowssoftwarejob

import (
	"bytes"
	"context"
	"errors"
	"localrmm/internal/actionpermit"
	"sync"
	"testing"
	"time"
)

func TestAcceptIsDurableSourceFreeOneUseAndRestartIsStatusOnly(t *testing.T) {
	f := fixture(t)
	raw := f.approve(t)
	n := &nativeFixture{readiness: f.source.value, result: NativeResult{ReturnCode: 0, ReturnCodeKnown: true, RegistrationVerified: Yes}}
	x, store := executorFixture(t, f, n)
	h, e := x.Accept(context.Background(), raw)
	if e != nil || h == nil || n.opens != 0 || n.installs != 0 {
		t.Fatal("accept accessed adapter", e)
	}
	var record ExecutorRecord
	if canonical(store.files["executor.json"], &record, MaxBytes) != nil || len(record.Attempts) != 1 || record.Attempts[0].Attempted || record.Attempts[0].Result != nil || !bytes.Equal(record.Attempts[0].Envelope, raw) {
		t.Fatal("ack before durable consume")
	}
	if _, e = x.Accept(context.Background(), raw); !errors.Is(e, ErrConsumed) {
		t.Fatal("resubmit accepted", e)
	}
	reopened := reopenExecutor(t, f, store, n)
	if _, e = reopened.RunAccepted(context.Background(), h); !errors.Is(e, ErrConsumed) {
		t.Fatal("capability crossed executor", e)
	}
	if _, e = reopened.RunAccepted(context.Background(), &Accepted{}); !errors.Is(e, ErrConsumed) {
		t.Fatal("forged capability", e)
	}
	if _, e = reopened.Execute(context.Background(), raw); !errors.Is(e, ErrConsumed) {
		t.Fatal("restart replay", e)
	}
	status, e := reopened.Status(context.Background())
	if e != nil || !status.InterventionRequired || status.Attempts[0].Attempted {
		t.Fatal("abandoned admission hidden", e)
	}
	// Original living owner can run only once; no persisted record manufactures it.
	if _, e = x.RunAccepted(context.Background(), h); e != nil {
		t.Fatal(e)
	}
	if _, e = x.RunAccepted(context.Background(), h); !errors.Is(e, ErrConsumed) || n.installs != 1 {
		t.Fatal("capability reused", e)
	}
}

func TestLongInstallDoesNotBlockStatusOrOutboxAndCannotTakeSecondOwner(t *testing.T) {
	f := fixture(t)
	raw := f.approve(t)
	entered, release := make(chan struct{}), make(chan struct{})
	n := &nativeFixture{readiness: f.source.value, result: NativeResult{ReturnCode: 0, ReturnCodeKnown: true, RegistrationVerified: Yes}, onInstall: func() { close(entered); <-release }}
	x, _ := executorFixture(t, f, n)
	h, e := x.Accept(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := x.RunAccepted(context.Background(), h); done <- e }()
	<-entered
	check := make(chan error, 1)
	go func() {
		s, e := x.Status(context.Background())
		if e == nil && (len(s.Attempts) != 1 || !s.Attempts[0].Attempted || !s.InterventionRequired) {
			e = ErrInvalid
		}
		check <- e
	}()
	select {
	case e := <-check:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("status held behind install")
	}
	if _, e = x.Outbox(context.Background(), "result", f.id, actionpermit.Digest(raw)); !errors.Is(e, ErrUnavailable) {
		t.Fatal("unfinished report synthesized", e)
	}
	if _, e = x.RunAccepted(context.Background(), h); !errors.Is(e, ErrConsumed) {
		t.Fatal("second owner entered", e)
	}
	if _, e = x.Accept(context.Background(), raw); !errors.Is(e, ErrConsumed) {
		t.Fatal("lost submit retried", e)
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if n.installs != 1 {
		t.Fatal("more than one install")
	}
}

func TestAcceptanceFailureAndExpiredQueuedStartNeverReachNative(t *testing.T) {
	for _, kind := range []string{"write_failure", "expires_after_accept", "revoke_after_accept"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			raw := f.approve(t)
			n := &nativeFixture{readiness: f.source.value, result: NativeResult{ReturnCode: 0, ReturnCodeKnown: true, RegistrationVerified: Yes}}
			x, store := executorFixture(t, f, n)
			if kind == "write_failure" {
				store.fail = store.writes + 1
			}
			h, e := x.Accept(context.Background(), raw)
			if kind == "write_failure" {
				if e == nil || h != nil || n.opens != 0 {
					t.Fatal("uncertain admission acknowledged", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if kind == "expires_after_accept" {
				f.at = f.at.Add(time.Minute)
			} else {
				f.guard.current.Enabled = false
			}
			result, e := x.RunAccepted(context.Background(), h)
			if e != nil || result.Outcome != "not_attempted" || n.opens != 0 || n.installs != 0 {
				t.Fatal("queued authority revived", result, e)
			}
		})
	}
}

type lockedAuthority struct {
	mu      sync.Mutex
	current Current
}

func (a *lockedAuthority) WithCurrent(ctx context.Context, b Binding, fn func(Current) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return fn(a.current)
}

type blockedPreparation struct {
	nativeFixture
	entered, release chan struct{}
}

func (n *blockedPreparation) PrepareExact(context.Context, Selection) (PreparedPackage, error) {
	close(n.entered)
	<-n.release
	return &n.nativeFixture, nil
}
func TestPreparationWithExclusiveAuthorityReturnsBusyWithoutDeadlock(t *testing.T) {
	f := fixture(t)
	raw := f.approve(t)
	n := &blockedPreparation{nativeFixture: nativeFixture{readiness: f.source.value, result: NativeResult{ReturnCode: 0, ReturnCodeKnown: true, RegistrationVerified: Yes}}, entered: make(chan struct{}), release: make(chan struct{})}
	x, _ := executorFixture(t, f, n)
	x.authority = &lockedAuthority{current: f.guard.current}
	h, e := x.Accept(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := x.RunAccepted(context.Background(), h); done <- e }()
	<-n.entered
	if _, e = x.Status(context.Background()); !errors.Is(e, ErrConflict) {
		t.Fatal("preparation status did not return busy", e)
	}
	if _, e = x.Outbox(context.Background(), "result", f.id, actionpermit.Digest(raw)); !errors.Is(e, ErrConflict) {
		t.Fatal("preparation outbox did not return busy", e)
	}
	close(n.release)
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("authority/kernel lock inversion")
	}
}
func TestCloseDuringInstallNeverSignsOrReplaysLateCompletion(t *testing.T) {
	f := fixture(t)
	raw := f.approve(t)
	entered, release := make(chan struct{}), make(chan struct{})
	n := &nativeFixture{readiness: f.source.value, result: NativeResult{ReturnCode: 0, ReturnCodeKnown: true, RegistrationVerified: Yes}, onInstall: func() { close(entered); <-release }}
	x, store := executorFixture(t, f, n)
	h, e := x.Accept(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := x.RunAccepted(context.Background(), h); done <- e }()
	<-entered
	x.Close()
	close(release)
	if e = <-done; !errors.Is(e, ErrUncertain) {
		t.Fatal("late completion signed", e)
	}
	reopened := reopenExecutor(t, f, store, n)
	s, e := reopened.Status(context.Background())
	if e != nil || !s.InterventionRequired || !s.Attempts[0].Attempted || s.Attempts[0].Result != nil || s.Attempts[0].ReportState != "missing" {
		t.Fatal("closed attempt rewritten", e)
	}
	if _, e = reopened.Execute(context.Background(), raw); !errors.Is(e, ErrConsumed) || n.installs != 1 {
		t.Fatal("closed attempt retried", e)
	}
}

// This fixture actually exercises the kernel-installed hook, rather than an
// adapter that returns without checking its private start authority.
type startCheckingNative struct {
	nativeFixture
	clock   func() time.Time
	before  func()
	gateErr error
}

func (n *startCheckingNative) PrepareExact(context.Context, Selection) (PreparedPackage, error) {
	return n, nil
}
func (n *startCheckingNative) InstallOnce(ctx context.Context) (NativeResult, error) {
	if n.before != nil {
		n.before()
	}
	n.gateErr = CheckInstallStart(ctx, n.clock())
	if n.gateErr != nil {
		return NativeResult{RegistrationVerified: Unknown}, n.gateErr
	}
	n.installs++
	return n.result, nil
}

type postCallbackAuthority struct {
	mu      sync.Mutex
	current Current
	after   func()
}

func (a *postCallbackAuthority) WithCurrent(ctx context.Context, b Binding, fn func(Current) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	e := fn(a.current)
	if e == nil && a.after != nil {
		a.after()
	}
	return e
}
func TestKernelNativeStartHookReentersExclusiveAuthorityAndKeepsFreshBounds(t *testing.T) {
	for _, kind := range []string{"success", "shorter_leaf", "clock_rollback"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			raw := f.approve(t)
			base := f.at
			a := &postCallbackAuthority{current: f.guard.current}
			n := &startCheckingNative{nativeFixture: nativeFixture{readiness: f.source.value, result: NativeResult{ReturnCode: 0, ReturnCodeKnown: true, RegistrationVerified: Yes}}, clock: func() time.Time { return f.at }}
			n.before = func() {
				switch kind {
				case "shorter_leaf":
					a.current.LeafNotAfter = base.Add(5 * time.Second).Unix()
					a.after = func() { f.at = base.Add(10 * time.Second) }
				case "clock_rollback":
					f.at = base.Add(3 * time.Second)
					a.after = func() { f.at = base.Add(2 * time.Second) }
				}
			}
			x, _ := executorFixture(t, f, n)
			x.authority = a
			result, e := x.Execute(context.Background(), raw)
			if kind == "success" {
				if e != nil || n.gateErr != nil || n.installs != 1 || result.Outcome != "succeeded" {
					t.Fatal("real start hook failed/deadlocked", result, e, n.gateErr)
				}
				return
			}
			if n.installs != 0 || !errors.Is(n.gateErr, ErrExpired) {
				t.Fatal("fresh native-start bounds lost", result, e, n.gateErr, n.installs)
			}
		})
	}
}
