//go:build linux

package actionhelper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
)

type fakeBackend struct {
	mu                       sync.Mutex
	checks, starts, observes int
	check                    func(context.Context, int) (Observation, error)
	start                    func(context.Context) error
	observe                  func(context.Context) (Observation, error)
}

func (f *fakeBackend) Check(c context.Context, _ Target) (Observation, error) {
	f.mu.Lock()
	f.checks++
	n := f.checks
	fn := f.check
	f.mu.Unlock()
	if fn != nil {
		return fn(c, n)
	}
	return Active, nil
}
func (f *fakeBackend) TryRestart(c context.Context, _ string) error {
	f.mu.Lock()
	f.starts++
	fn := f.start
	f.mu.Unlock()
	if fn != nil {
		return fn(c)
	}
	return nil
}
func (f *fakeBackend) Observe(c context.Context, _ string) (Observation, error) {
	f.mu.Lock()
	f.observes++
	fn := f.observe
	f.mu.Unlock()
	if fn != nil {
		return fn(c)
	}
	return Active, nil
}
func (f *fakeBackend) counts() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks, f.starts, f.observes
}

type runtimeFixture struct {
	s        *Server
	state    *actionstate.State
	a        Authority
	key      ed25519.PrivateKey
	backend  *fakeBackend
	peer     Peer
	clock    atomic.Int64
	dir      string
	loadHook func()
}

func fixtureAuthority() (Authority, ed25519.PrivateKey) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{107}, 32))
	d := actionpermit.Digest([]byte("fixture pin"))
	p := Policy{Version: PolicyVersion, Enabled: true, ManagerID: "manager_" + strings.Repeat("1", 32), KeyID: actionpermit.Digest(key.Public().(ed25519.PublicKey)), EndpointID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: d, TransportProfile: ProductionTLS, AgentUID: 1234, AgentGID: 1234, MaxLifetimeSeconds: 60, Targets: []Target{{Unit: "fixture.service", ReviewDigest: d, Units: []UnitPin{{Unit: "fixture.service", ConfigurationDigest: d}}, Inputs: []FilePin{{Path: "/usr/bin/systemctl", Digest: d}, {Path: "/usr/lib/systemd/system/fixture.service", Digest: d}}}}}
	return Authority{Policy: p, PublicKey: key.Public().(ed25519.PublicKey), Revision: actionpermit.Digest([]byte("fixture revision"))}, key
}
func newFixture(t *testing.T) *runtimeFixture {
	t.Helper()
	a, k := fixtureAuthority()
	f := &runtimeFixture{a: a, key: k, backend: &fakeBackend{}, peer: Peer{UID: 1234, GID: 1234, PID: 321}, dir: filepath.Join(t.TempDir(), "actions")}
	f.clock.Store(time.Date(2026, 10, 5, 18, 0, 0, 0, time.UTC).UnixMicro())
	v, e := a.verifier()
	if e != nil {
		t.Fatal(e)
	}
	f.state, e = actionstate.Initialize(context.Background(), f.dir, v)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.state.Close() })
	f.s, e = New(Dependencies{Load: func() (Authority, error) {
		if f.loadHook != nil {
			f.loadHook()
		}
		return f.a, nil
	}, Identity: func() error { return nil }, Peer: func(net.Conn) (Peer, error) { return f.peer, nil }, Backend: f.backend, State: f.state, Now: func() time.Time { return time.UnixMicro(f.clock.Load()).UTC() }})
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *runtimeFixture) request(t *testing.T, seq uint64) Request {
	t.Helper()
	d, e := targetDigest(f.a.Policy.Targets[0])
	if e != nil {
		t.Fatal(e)
	}
	plan := actionpermit.Plan{Version: actionpermit.PlanVersion, Action: actionpermit.TryRestartService, Unit: f.a.Policy.Targets[0].Unit, UnitPolicyDigest: d}
	pd, _ := actionpermit.PlanDigest(plan)
	raw, _ := json.Marshal(f.a.Policy)
	now := time.UnixMicro(f.clock.Load()).Unix()
	p := actionpermit.Permit{Version: actionpermit.Version, ManagerID: f.a.Policy.ManagerID, KeyID: f.a.Policy.KeyID, EndpointID: f.a.Policy.EndpointID, IncarnationDigest: f.a.Policy.IncarnationDigest, JobID: fmt.Sprintf("action_%032x", seq), Sequence: seq, Plan: plan, PlanDigest: pd, OperatorID: "operator_" + strings.Repeat("3", 32), ApprovalDigest: actionpermit.Digest([]byte("approved fixture")), RootPolicyDigest: actionpermit.Digest(raw), IssuedAt: now, NotBefore: now, StartDeadline: now + 60}
	msg, e := actionpermit.SigningMessage(p)
	if e != nil {
		t.Fatal(e)
	}
	env, e := actionpermit.Encode(p, ed25519.Sign(f.key, msg))
	if e != nil {
		t.Fatal(e)
	}
	return Request{Version: RequestVersion, Operation: SubmitOperation, Envelope: env}
}
func TestRuntimeDurablePhasesDuplicateAndNext(t *testing.T) {
	f := newFixture(t)
	r := f.request(t, 1)
	p, _ := actionpermit.Decode(r.Envelope)
	f.backend.check = func(_ context.Context, n int) (Observation, error) {
		st, e := f.state.Status(context.Background(), p.JobID)
		want := actionstate.Admitted
		if n == 2 {
			want = actionstate.Dispatching
		}
		if e != nil || st.Phase != want {
			t.Errorf("check %d phase %s %v", n, st.Phase, e)
		}
		return Active, nil
	}
	f.backend.start = func(context.Context) error {
		st, e := f.state.Status(context.Background(), p.JobID)
		if e != nil || st.Phase != actionstate.Dispatching || st.DispatchAt.IsZero() {
			t.Errorf("dispatch not durable %v %v", st, e)
		}
		return nil
	}
	st, e := f.s.Handle(context.Background(), f.peer, r)
	if e != nil || st.Phase != actionstate.OperationCompleted || st.ObservedState != actionstate.ObservedActive {
		t.Fatal(st, e)
	}
	f.a.Policy.Enabled = false
	f.a.Revision = actionpermit.Digest([]byte("revoked"))
	duplicate, e := f.s.Handle(context.Background(), f.peer, r)
	if e != nil || duplicate != st {
		t.Fatal("duplicate changed", duplicate, e)
	}
	_, starts, _ := f.backend.counts()
	if starts != 1 {
		t.Fatal(starts)
	}
	status, e := f.s.Handle(context.Background(), f.peer, Request{Version: RequestVersion, Operation: StatusOperation, JobID: p.JobID})
	if e != nil || status != st {
		t.Fatal(status, e)
	}
	f.a.Policy.Enabled = true
	f.a.Revision = actionpermit.Digest([]byte("fixture revision"))
	f.backend.check = nil
	f.backend.start = nil
	st, e = f.s.Handle(context.Background(), f.peer, f.request(t, 2))
	if e != nil || st.Phase != actionstate.OperationCompleted {
		t.Fatal(st, e)
	}
}
func TestRuntimeDenialsNeverInvoke(t *testing.T) {
	for _, kind := range []string{"disabled", "peer", "signature", "wrong_policy", "wrong_endpoint", "future", "profile"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			r := f.request(t, 1)
			peer := f.peer
			switch kind {
			case "disabled":
				f.a.Policy.Enabled = false
			case "peer":
				peer.UID++
			case "signature":
				r.Envelope[len(r.Envelope)-4] ^= 1
			case "wrong_policy":
				f.a.Policy.MaxLifetimeSeconds = 59
			case "wrong_endpoint":
				f.a.Policy.EndpointID = "agent_" + strings.Repeat("9", 32)
			case "future":
				f.clock.Add(-int64(time.Minute / time.Microsecond))
			case "profile":
				f.a.Policy.TransportProfile = DisposableHTTPTest
				f.a.Policy.HTTPTestAcknowledged = true
			}
			_, e := f.s.Handle(context.Background(), peer, r)
			if e == nil {
				t.Fatal("accepted")
			}
			_, starts, _ := f.backend.counts()
			if starts != 0 {
				t.Fatal(starts)
			}
		})
	}
}
func TestRuntimeFinalChecksAndConsumedNotStarted(t *testing.T) {
	for _, kind := range []string{"inactive", "check_error", "revoked", "expired", "canceled", "clock_back"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			r := f.request(t, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.backend.check = func(_ context.Context, n int) (Observation, error) {
				if n != 2 {
					return Active, nil
				}
				switch kind {
				case "inactive":
					return Inactive, nil
				case "check_error":
					return Unknown, ErrRejected
				case "revoked":
					f.a.Policy.Enabled = false
					f.a.Revision = actionpermit.Digest([]byte("revoked"))
				case "expired":
					f.clock.Add(int64(time.Minute / time.Microsecond))
				case "canceled":
					cancel()
				case "clock_back":
					f.clock.Add(-1)
				}
				return Active, nil
			}
			st, e := f.s.Handle(ctx, f.peer, r)
			if kind == "clock_back" {
				if e == nil {
					t.Fatal("clock accepted")
				}
			} else if e != nil || st.Phase != actionstate.NotStarted {
				t.Fatal(st, e)
			}
			_, starts, _ := f.backend.counts()
			if starts != 0 {
				t.Fatal(starts)
			}
			f.clock.Add(int64(time.Hour / time.Microsecond))
			f.backend.check = nil
			retry, e := f.s.Handle(context.Background(), f.peer, r)
			if e != nil {
				t.Fatal(e)
			}
			if retry.Phase == actionstate.OperationCompleted {
				t.Fatal("replayed")
			}
			_, starts, _ = f.backend.counts()
			if starts != 0 {
				t.Fatal(starts)
			}
		})
	}
}
func TestRuntimeCancelDuringLastAuthorityLoadDoesNotStart(t *testing.T) {
	f := newFixture(t)
	r := f.request(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.backend.check = func(_ context.Context, n int) (Observation, error) {
		if n == 2 {
			f.loadHook = cancel
		}
		return Active, nil
	}
	st, e := f.s.Handle(ctx, f.peer, r)
	if e != nil || st.Phase != actionstate.NotStarted || st.Reason != actionstate.ReasonCanceled {
		t.Fatal(st, e)
	}
	_, starts, _ := f.backend.counts()
	if starts != 0 {
		t.Fatal(starts)
	}
}
func TestRuntimeInvocationUncertaintyBlocksAndNeverRetries(t *testing.T) {
	for _, failure := range []error{ErrUnavailable, context.DeadlineExceeded, context.Canceled} {
		t.Run(failure.Error(), func(t *testing.T) {
			f := newFixture(t)
			r := f.request(t, 1)
			f.backend.start = func(ctx context.Context) error {
				if _, ok := ctx.Deadline(); !ok {
					t.Error("no observation deadline")
				}
				return failure
			}
			st, e := f.s.Handle(context.Background(), f.peer, r)
			if e != nil || st.Phase != actionstate.NeedsIntervention || st.Outcome != actionstate.OutcomeUnknown {
				t.Fatal(st, e)
			}
			duplicate, e := f.s.Handle(context.Background(), f.peer, r)
			if e != nil || duplicate != st {
				t.Fatal(duplicate, e)
			}
			_, e = f.s.Handle(context.Background(), f.peer, f.request(t, 2))
			if !errors.Is(e, actionstate.ErrBusy) {
				t.Fatal(e)
			}
			_, starts, _ := f.backend.counts()
			if starts != 1 {
				t.Fatal(starts)
			}
		})
	}
}
func TestRuntimeCancelAfterInvocationRetainsResult(t *testing.T) {
	f := newFixture(t)
	r := f.request(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.backend.start = func(operation context.Context) error {
		cancel()
		if operation.Err() != nil {
			t.Fatal("request canceled operation")
		}
		return nil
	}
	f.backend.observe = func(context.Context) (Observation, error) { return Unknown, ErrUnavailable }
	st, e := f.s.Handle(ctx, f.peer, r)
	if e != nil || st.Phase != actionstate.OperationCompleted || st.ObservedState != actionstate.ObservedUnknown {
		t.Fatal(st, e)
	}
}
func TestRuntimeConcurrentDuplicateGetsOriginalDispatchStatus(t *testing.T) {
	f := newFixture(t)
	r := f.request(t, 1)
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	f.backend.start = func(context.Context) error { close(started); <-release; return nil }
	go func() { _, e := f.s.Handle(context.Background(), f.peer, r); done <- e }()
	<-started
	st, e := f.s.Handle(context.Background(), f.peer, r)
	if e != nil || st.Phase != actionstate.Dispatching {
		t.Fatal(st, e)
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	_, starts, _ := f.backend.counts()
	if starts != 1 {
		t.Fatal(starts)
	}
}
func TestRuntimeRestartNeverRecreatesAttempt(t *testing.T) {
	f := newFixture(t)
	r := f.request(t, 1)
	_, attempt, e := f.state.Begin(context.Background(), r.Envelope, time.UnixMicro(f.clock.Load()).UTC())
	if e != nil || attempt == nil {
		t.Fatal(e)
	}
	if _, e = attempt.MarkDispatching(context.Background(), time.UnixMicro(f.clock.Load()).UTC()); e != nil {
		t.Fatal(e)
	}
	f.state.Close()
	v, _ := f.a.verifier()
	f.state, e = actionstate.Open(context.Background(), f.dir, v)
	if e != nil {
		t.Fatal(e)
	}
	f.s, e = New(Dependencies{Load: func() (Authority, error) { return f.a, nil }, Identity: func() error { return nil }, Peer: func(net.Conn) (Peer, error) { return f.peer, nil }, Backend: f.backend, State: f.state, Now: func() time.Time { return time.UnixMicro(f.clock.Load()).UTC() }})
	if e != nil {
		t.Fatal(e)
	}
	st, e := f.s.Handle(context.Background(), f.peer, r)
	if e != nil || st.Phase != actionstate.NeedsIntervention {
		t.Fatal(st, e)
	}
	_, starts, _ := f.backend.counts()
	if starts != 0 {
		t.Fatal(starts)
	}
}

func TestRuntimeRejectsClockRollbackAfterDurableDispatch(t *testing.T) {
	f := newFixture(t)
	r := f.request(t, 1)
	original := f.clock.Load()
	f.backend.check = func(_ context.Context, n int) (Observation, error) {
		if n == 1 {
			f.clock.Store(original + 10_000_000)
		} else {
			f.clock.Store(original + 5_000_000)
		}
		return Active, nil
	}
	_, err := f.s.Handle(context.Background(), f.peer, r)
	if !errors.Is(err, actionpermit.ErrClock) {
		t.Fatal(err)
	}
	_, starts, _ := f.backend.counts()
	if starts != 0 {
		t.Fatal("invoked after clock reversal", starts)
	}
	p, _ := actionpermit.Decode(r.Envelope)
	st, err := f.state.Status(context.Background(), p.JobID)
	if err != nil || st.Phase != actionstate.Dispatching {
		t.Fatal(st, err)
	}
}

func TestProfileSwitchRetainsFloorAndRejectsOldPolicyPermit(t *testing.T) {
	f := newFixture(t)
	first := f.request(t, 1)
	oldNext := f.request(t, 2)
	original, e := f.s.Handle(context.Background(), f.peer, first)
	if e != nil {
		t.Fatal(e)
	}
	f.state.Close()
	f.a.Policy.TransportProfile = DisposableHTTPTest
	f.a.Policy.HTTPTestAcknowledged = true
	f.a.Revision = actionpermit.Digest([]byte("explicit test-policy revision"))
	v, e := f.a.verifier()
	if e != nil {
		t.Fatal(e)
	}
	f.state, e = actionstate.Open(context.Background(), f.dir, v)
	if e != nil {
		t.Fatal(e)
	}
	f.s, e = New(Dependencies{Load: func() (Authority, error) { return f.a, nil }, Identity: func() error { return nil }, Peer: func(net.Conn) (Peer, error) { return f.peer, nil }, Backend: f.backend, State: f.state, Now: func() time.Time { return time.UnixMicro(f.clock.Load()).UTC() }})
	if e != nil {
		t.Fatal(e)
	}
	same, e := f.s.Handle(context.Background(), f.peer, first)
	if e != nil || same != original {
		t.Fatal("old history changed", same, e)
	}
	if _, e = f.s.Handle(context.Background(), f.peer, oldNext); e == nil {
		t.Fatal("old production policy permit accepted")
	}
	if _, e = f.s.Handle(context.Background(), f.peer, f.request(t, 1)); !errors.Is(e, actionstate.ErrConflict) {
		t.Fatal("old sequence/job reused", e)
	}
	next, e := f.s.Handle(context.Background(), f.peer, f.request(t, 2))
	if e != nil || next.Phase != actionstate.OperationCompleted {
		t.Fatal(next, e)
	}
	_, starts, _ := f.backend.counts()
	if starts != 2 {
		t.Fatal(starts)
	}
}
