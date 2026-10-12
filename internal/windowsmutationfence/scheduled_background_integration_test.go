package windowsmutationfence_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	wua "localrmm/internal/windowsupdatejob"
	"testing"
	"time"
)

// Test-only persistence adapter; production uses the enrollment-owned store.
// Error returns leave exact original bytes intact, as that store's contract does.
type scheduledPairTransaction struct {
	*domainStore
	f *pairedDomains
}

func (s *scheduledPairTransaction) WindowsUpdateEnrollmentBinding() enrollmentstate.Binding {
	return enrollmentstate.Binding{InstanceID: s.f.consent.Binding.ManagerID, Profile: "tls", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory}
}
func (s *scheduledPairTransaction) WindowsUpdateJobTransaction(ctx context.Context, b wua.Binding, key ed25519.PublicKey, at time.Time, fn func(*wua.Record, wua.Current, time.Time) error) (wua.Record, time.Time, error) {
	raw, e := s.Read("jobs.json")
	if e != nil {
		return wua.Record{}, at, e
	}
	r, e := wua.DecodeRecord(raw)
	if e != nil {
		return r, at, e
	}
	if b != r.Consent.Binding || !bytes.Equal(key, r.PublicKey) || at.Unix() < r.ClockFloor {
		return wua.Record{}, at, wua.ErrAuthority
	}
	r.ClockFloor = at.Unix()
	if e = fn(&r, s.f.wuaAuthority.value, at); e != nil {
		return wua.Record{}, at, e
	}
	if e = wua.CheckFinal(ctx); e != nil {
		return wua.Record{}, at, e
	}
	raw, e = wua.EncodeRecord(r)
	if e != nil {
		return wua.Record{}, at, e
	}
	if e = s.Write("jobs.json", raw); e != nil {
		return wua.Record{}, at, e
	}
	return r, at, nil
}

type scheduledPair struct {
	f         *pairedDomains
	m         *wua.Manager
	store     *domainStore
	actor, id string
	approval  wua.ScheduleApproval
}

func newScheduledPair(t *testing.T) *scheduledPair {
	t.Helper()
	f := newPair(t, true, true, true)
	ctx := context.Background()
	r, e := wua.NewRecordWithExecutor(f.consent, public(f.wuaKey), public(f.wuaExecutorKey), f.at.Load())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := wua.EncodeRecord(r)
	if e != nil {
		t.Fatal(e)
	}
	c, _ := json.Marshal(f.consent)
	s := &scheduledPair{f: f, store: &domainStore{files: map[string][]byte{"jobs.json": raw, "started.json": c, "receipt.json": c}}, actor: id("operator_", 30), id: id("update_", 30)}
	s.m, e = wua.OpenTransactional(ctx, &scheduledPairTransaction{domainStore: s.store, f: f}, f.consent.Binding, f.wuaKey, f.now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.m.Close)
	if e = s.m.ConfigureOperatorPolicy(func(actor string) bool { return actor == s.actor }); e != nil {
		t.Fatal(e)
	}
	if e = s.m.ConfigureSchedulePolicy(ctx, func(actor string) bool { return actor == s.actor }); e != nil {
		t.Fatal(e)
	}
	if e = s.m.Request(ctx, f.consent.Binding.DeviceID, s.actor, s.id, f.wuaNative.readiness.Selection); e != nil {
		t.Fatal(e)
	}
	proof := s.readiness(t)
	if e = s.m.Report(ctx, proof); e != nil {
		t.Fatal(e)
	}
	v, e := s.m.View(ctx, f.consent.Binding.DeviceID, s.actor)
	if e != nil || v.Job.Preview == nil {
		t.Fatal(e)
	}
	if e = s.m.Schedule(ctx, f.consent.Binding.DeviceID, s.actor, s.id, v.Job.Preview.Digest, f.at.Load()+1, f.at.Load()+121, true); e != nil {
		t.Fatal(e)
	}
	raw, _ = s.store.Read("jobs.json")
	r, e = wua.DecodeRecord(raw)
	if e != nil {
		t.Fatal(e)
	}
	s.approval = r.Jobs[0].Schedule.Approval
	f.at.Add(1)
	if _, e = s.m.Pending(ctx); e != nil {
		t.Fatal(e)
	}
	return s
}
func (s *scheduledPair) readiness(t *testing.T) []byte {
	t.Helper()
	ctx := context.Background()
	challenge, e := s.m.ClaimReadiness(ctx, s.id)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := s.f.executor.Readiness(ctx, challenge)
	if e != nil {
		t.Fatal(e)
	}
	saved, e := s.f.executor.Outbox(ctx, "readiness", s.id, actionpermit.Digest(challenge))
	if e != nil || !bytes.Equal(proof, saved) {
		t.Fatal("no exact durable readiness", e)
	}
	return saved
}
func (s *scheduledPair) status(t *testing.T) {
	t.Helper()
	v, e := s.f.executor.Status(context.Background())
	if e != nil || len(v.MutationReport) == 0 {
		t.Fatal(e)
	}
	if e = s.m.Report(context.Background(), v.MutationReport); e != nil {
		t.Fatal(e)
	}
}
func TestScheduledBackgroundBusyMSIWaitsThenSameReportAdmitsOneWUA(t *testing.T) {
	s := newScheduledPair(t)
	f := s.f
	ctx := context.Background()
	entered, release := make(chan struct{}), make(chan struct{})
	f.msiNative.entered = entered
	f.msiNative.release = release
	if e := f.endpoint.Accept(ctx, f.msiPermit); e != nil {
		t.Fatal(e)
	}
	await(t, entered)
	proof := s.readiness(t)
	s.status(t)
	if e := s.m.Report(ctx, proof); !errors.Is(e, wua.ErrUnavailable) {
		close(release)
		f.endpoint.Wait()
		t.Fatal("busy owner issued", e)
	}
	if f.wuaNative.calls.Load() != 0 {
		t.Fatal("WUA ran with MSI owner")
	}
	close(release)
	f.endpoint.Wait()
	s.status(t)
	if e := s.m.Report(ctx, proof); e != nil {
		t.Fatal("same signed readiness failed", e)
	}
	permit, e := s.m.Claim(ctx, s.id)
	if e != nil {
		t.Fatal(e)
	}
	result, e := f.executor.Execute(ctx, permit)
	if e != nil || result.Outcome != "succeeded" || f.wuaNative.calls.Load() != 1 || f.msiNative.calls.Load() != 1 || f.fenceStatus(t).Blocked {
		t.Fatal("one shared native admission failed", result, e)
	}
	if f.wuaNative.prepares.Load() != 3 {
		t.Fatal("readiness was regenerated", f.wuaNative.prepares.Load())
	}
	f.executor.Close()
	f.openWUA(t)
	if _, e = f.executor.Execute(ctx, permit); !errors.Is(e, wua.ErrConsumed) {
		t.Fatal("restart replay", e)
	}
}
func TestScheduledBackgroundNativeEdgeExpiryAndCleanupKeepDurableOwner(t *testing.T) {
	for _, kind := range []string{"window", "current-leaf", "cleanup"} {
		t.Run(kind, func(t *testing.T) {
			s := newScheduledPair(t)
			f := s.f
			ctx := context.Background()
			proof := s.readiness(t)
			s.status(t)
			if e := s.m.Report(ctx, proof); e != nil {
				t.Fatal(e)
			}
			permit, e := s.m.Claim(ctx, s.id)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "window":
				f.wuaNative.beforeStart = func() { f.at.Store(s.approval.EndAt) }
			case "current-leaf":
				f.wuaNative.beforeStart = func() { f.wuaAuthority.value.LeafNotAfter = f.at.Load() }
			case "cleanup":
				f.wuaNative.closeError = errors.New("cleanup uncertain")
			}
			_, e = f.executor.Execute(ctx, permit)
			if e != nil {
				t.Fatal(e)
			}
			if !f.fenceStatus(t).Blocked {
				t.Fatal("uncertainty auto-unlocked")
			}
			if kind != "cleanup" && f.wuaNative.calls.Load() != 0 {
				t.Fatal("expired actual native edge")
			}
			r := readWUA(t, f.wuaStore)
			if len(r.Attempts) != 1 || r.Attempts[0].MutationCompletion != nil {
				t.Fatal("failed edge fabricated settlement")
			}
		})
	}
}
