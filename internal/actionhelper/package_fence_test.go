//go:build linux

package actionhelper

import (
	"context"
	"errors"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
	"localrmm/internal/mutationfence"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func installFixtureFence(t *testing.T, f *runtimeFixture) *mutationfence.Fence {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "shared")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	b := mutationfence.Binding{ManagerID: f.a.Policy.ManagerID, EndpointID: f.a.Policy.EndpointID, IncarnationDigest: f.a.Policy.IncarnationDigest}
	fence, e := mutationfence.Create(context.Background(), dir, b, time.UnixMicro(f.clock.Load()).Unix())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = fence.Close() })
	f.s.inner.deps.Fence = fence
	f.s.inner.deps.FenceRequired = true
	return fence
}
func TestPackageFenceBlocksServiceBeforeBackend(t *testing.T) {
	f := newFixture(t)
	fence := installFixtureFence(t, f)
	owner := mutationfence.Owner{Action: mutationfence.Package, JobID: "update_11111111111111111111111111111111", Sequence: 1, EnvelopeDigest: actionpermit.Digest([]byte("package"))}
	if _, _, e := fence.Acquire(context.Background(), owner, time.UnixMicro(f.clock.Load()).Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.Handle(context.Background(), f.peer, f.request(t, 1)); e == nil {
		t.Fatal("service crossed active package fence")
	}
	checks, starts, _ := f.backend.counts()
	if starts != 0 || checks != 0 {
		t.Fatal("backend touched", checks, starts)
	}
	if e := fence.Complete(context.Background(), owner, "completed", time.UnixMicro(f.clock.Load()).Unix()); e != nil {
		t.Fatal(e)
	}
	st, e := f.s.Handle(context.Background(), f.peer, f.request(t, 1))
	if e != nil || st.Outcome != actionstate.OutcomeCompleted {
		t.Fatal(st, e)
	}
	owner.Sequence = 2
	owner.JobID = "update_22222222222222222222222222222222"
	if _, fresh, e := fence.Acquire(context.Background(), owner, time.UnixMicro(f.clock.Load()).Unix()); e != nil || !fresh {
		t.Fatal("completed service retained fence", e)
	}
}
func TestUncertainServiceRetainsCrossActionFence(t *testing.T) {
	f := newFixture(t)
	fence := installFixtureFence(t, f)
	f.backend.start = func(context.Context) error { return errors.New("lost dispatch result") }
	_, _ = f.s.Handle(context.Background(), f.peer, f.request(t, 1))
	owner := mutationfence.Owner{Action: mutationfence.Prepare, JobID: "update_11111111111111111111111111111111", Sequence: 1, EnvelopeDigest: actionpermit.Digest([]byte("prepare"))}
	if _, _, e := fence.Acquire(context.Background(), owner, time.UnixMicro(f.clock.Load()).Unix()); !errors.Is(e, mutationfence.ErrBusy) {
		t.Fatal("uncertain service unlocked package operations", e)
	}
}

func TestHelperStartedBeforePackageScopeRefusesLaterAdmission(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-yet-provisioned")
	identity := func() error { return nil }
	if e := fenceRuntimeIdentity(dir, false, identity); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := fenceRuntimeIdentity(dir, false, identity); e == nil {
		t.Fatal("unfenced helper retained authority after package setup")
	}
	if e := fenceRuntimeIdentity(dir, true, identity); e != nil {
		t.Fatal("already fenced helper rejected", e)
	}
}
