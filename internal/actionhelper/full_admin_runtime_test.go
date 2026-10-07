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
	"os"
	"path/filepath"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
	"localrmm/internal/mutationfence"
)

type fullAdminRuntimeBackend struct {
	*fakeBackend
	inspection ServiceInspection
}

func (b *fullAdminRuntimeBackend) InspectService(context.Context, string) (ServiceInspection, error) {
	return b.inspection, nil
}
func (b *fullAdminRuntimeBackend) ListServices(context.Context) ([]string, error) {
	return []string{b.inspection.Unit}, nil
}
func newRuntimeV2(t *testing.T) (*runtimeFixture, *fullAdminRuntimeBackend) {
	t.Helper()
	a, key := fixtureAuthority()
	a.Policy.Version = PolicyVersionV2
	a.Policy.Scope = FullAdminServiceScope
	a.Policy.Targets = []Target{}
	backend := &fullAdminRuntimeBackend{fakeBackend: &fakeBackend{}, inspection: ServiceInspection{Unit: "sshd.service", UnitPolicyDigest: actionpermit.Digest([]byte("root-controlled current graph")), AffectedServices: []string{"sshd.service"}, ObservedState: Active}}
	f := &runtimeFixture{a: a, key: key, backend: backend.fakeBackend, peer: Peer{UID: 1234, GID: 1234, PID: 321}, dir: filepath.Join(t.TempDir(), "actions")}
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
	dir := filepath.Join(t.TempDir(), "fence")
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	fence, e := mutationfence.Create(context.Background(), dir, mutationfence.Binding{ManagerID: a.Policy.ManagerID, EndpointID: a.Policy.EndpointID, IncarnationDigest: a.Policy.IncarnationDigest}, time.UnixMicro(f.clock.Load()).Unix())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { fence.Close() })
	deps := Dependencies{Load: func() (Authority, error) { return f.a, nil }, Identity: func() error { return nil }, Peer: func(net.Conn) (Peer, error) { return f.peer, nil }, Backend: backend, State: f.state, Now: func() time.Time { return time.UnixMicro(f.clock.Load()).UTC() }}
	if _, e = New(deps); e == nil {
		t.Fatal("v2 without shared fence")
	}
	deps.Fence = fence
	deps.FenceRequired = true
	f.s, e = New(deps)
	if e != nil {
		t.Fatal(e)
	}
	return f, backend
}
func requestV2(t *testing.T, f *runtimeFixture, b *fullAdminRuntimeBackend, seq uint64) Request {
	t.Helper()
	plan := actionpermit.Plan{Version: actionpermit.PlanVersionV2, Action: actionpermit.TryRestartService, Unit: b.inspection.Unit, UnitPolicyDigest: b.inspection.UnitPolicyDigest}
	plan.AffectedServicesDigest, _ = actionpermit.AffectedServicesDigest(b.inspection.AffectedServices)
	pd, _ := actionpermit.PlanDigest(plan)
	policy, _ := json.Marshal(f.a.Policy)
	now := time.UnixMicro(f.clock.Load()).Unix()
	p := actionpermit.Permit{Version: actionpermit.VersionV2, ManagerID: f.a.Policy.ManagerID, KeyID: f.a.Policy.KeyID, EndpointID: f.a.Policy.EndpointID, IncarnationDigest: f.a.Policy.IncarnationDigest, JobID: fmt.Sprintf("action_%032x", seq), Sequence: seq, Plan: plan, PlanDigest: pd, OperatorID: "operator_33333333333333333333333333333333", ApprovalDigest: actionpermit.Digest([]byte("named exact approval")), RootPolicyDigest: actionpermit.Digest(policy), IssuedAt: now, NotBefore: now, StartDeadline: now + 60}
	msg, e := actionpermit.SigningMessage(p)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := actionpermit.Encode(p, ed25519.Sign(f.key, msg))
	if e != nil {
		t.Fatal(e)
	}
	return Request{Version: RequestVersionV2, Operation: SubmitOperation, Envelope: raw}
}
func TestFullAdminRuntimeInspectsBeforeConsumeAndRechecksBeforeDispatch(t *testing.T) {
	for _, rejectAt := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(rejectAt), func(t *testing.T) {
			f, b := newRuntimeV2(t)
			r := requestV2(t, f, b, 1)
			p, _ := actionpermit.Decode(r.Envelope)
			b.check = func(_ context.Context, n int) (Observation, error) {
				if n == rejectAt {
					return Unknown, ErrRejected
				}
				return Active, nil
			}
			st, e := f.s.Handle(context.Background(), f.peer, r)
			if rejectAt == 1 {
				if e == nil {
					t.Fatal("pre-admission drift admitted")
				}
				if _, e = f.state.Status(context.Background(), p.JobID); !errors.Is(e, actionstate.ErrNotFound) {
					t.Fatal("consumed stale preview", e)
				}
			} else if e != nil || st.Phase != actionstate.NotStarted {
				t.Fatal(st, e)
			}
			if _, starts, _ := b.counts(); starts != 0 {
				t.Fatal("stale configuration executed")
			}
		})
	}
	f, b := newRuntimeV2(t)
	r := requestV2(t, f, b, 1)
	st, e := f.s.Handle(context.Background(), f.peer, r)
	if e != nil || st.Phase != actionstate.OperationCompleted {
		t.Fatal(st, e)
	}
	again, e := f.s.Handle(context.Background(), f.peer, r)
	if e != nil || again != st {
		t.Fatal("duplicate changed", e)
	}
	checks, starts, _ := b.counts()
	if checks != 3 || starts != 1 {
		t.Fatal(checks, starts)
	}
}
func TestFullAdminRuntimeUncertainResultRetainsFenceAndNoRetry(t *testing.T) {
	f, b := newRuntimeV2(t)
	b.start = func(context.Context) error { return ErrUnavailable }
	r := requestV2(t, f, b, 1)
	st, e := f.s.Handle(context.Background(), f.peer, r)
	if e != nil || st.Phase != actionstate.NeedsIntervention {
		t.Fatal(st, e)
	}
	_, _ = f.s.Handle(context.Background(), f.peer, r)
	if _, starts, _ := b.counts(); starts != 1 {
		t.Fatal("retried uncertain operation")
	}
	owner := mutationfence.Owner{Action: mutationfence.Package, JobID: "update_11111111111111111111111111111111", Sequence: 1, EnvelopeDigest: actionpermit.Digest(nil)}
	if _, _, e = f.s.inner.deps.Fence.Acquire(context.Background(), owner, time.UnixMicro(f.clock.Load()).Unix()); !errors.Is(e, mutationfence.ErrBusy) {
		t.Fatal("released uncertain fence", e)
	}
}
func TestFullAdminCapabilitiesV2IPCAndLegacyIsolation(t *testing.T) {
	f, _ := newRuntimeV2(t)
	c, e := f.s.Capabilities(context.Background(), f.peer)
	if e != nil || c.Version != CapabilitiesVersionV2 || c.Scope != FullAdminServiceScope || c.ReviewNotice != FullAdminReviewNotice || len(c.Services) != 1 {
		t.Fatal(c, e)
	}
	var old bytes.Buffer
	if e = writeCapabilities(&old, c, nil); e == nil {
		t.Fatal("legacy IPC advertised broad authority")
	}
	var wire bytes.Buffer
	if e = writeCapabilitiesVersion(&wire, c, nil, ResponseVersionV2); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadResponse(bytes.NewReader(wire.Bytes())); e == nil {
		t.Fatal("legacy reader accepted v2")
	}
	if _, e = ReadResponseV2(bytes.NewReader(wire.Bytes())); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(f.a.Policy)
	if _, e = ValidateSetupPolicy(raw, f.a.PublicKey); e != nil {
		t.Fatal(e)
	}
	legacy := f.a.Policy
	legacy.Version = PolicyVersion
	raw, _ = json.Marshal(legacy)
	if _, e = ValidateSetupPolicy(raw, f.a.PublicKey); e == nil {
		t.Fatal("v1 adopted full grant")
	}
	noScope := f.a.Policy
	noScope.Scope = ""
	raw, _ = json.Marshal(noScope)
	if _, e = ValidateSetupPolicy(raw, f.a.PublicKey); e == nil {
		t.Fatal("v2 implicit scope")
	}
}
