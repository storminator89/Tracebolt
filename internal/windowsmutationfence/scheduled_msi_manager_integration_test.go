//go:build linux

package windowsmutationfence_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"localrmm/internal/enrollmentstate"
	msi "localrmm/internal/windowsmanagedmsi"
	manager "localrmm/internal/windowsmanagedmsimanager"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The transaction adapter persists only canonical metadata in memory. Real
// manager/endpoint/fence kernels are connected; MSI and Windows providers are inert.
type scheduledManagerStore struct {
	record  msi.Record
	current *msi.Current
	now     func() time.Time
}

func (s *scheduledManagerStore) WindowsManagedMSIEnrollmentBinding() enrollmentstate.Binding {
	return enrollmentstate.Binding{InstanceID: s.record.Grant.Binding.ManagerID, Profile: "tls", CollectionProfile: "windows-inventory-v1"}
}
func (s *scheduledManagerStore) ReadRegisteredWindowsManagedMSI(ctx context.Context, b msi.Binding, k ed25519.PublicKey) (msi.Record, error) {
	if b != s.record.Grant.Binding || !bytes.Equal(k, s.record.PublicKey) {
		return msi.Record{}, msi.ErrAuthority
	}
	raw, e := msi.EncodeRecord(s.record)
	if e != nil {
		return msi.Record{}, e
	}
	return msi.DecodeRecord(raw)
}
func (s *scheduledManagerStore) WindowsManagedMSITransaction(ctx context.Context, b msi.Binding, k ed25519.PublicKey, at time.Time, fn func(*msi.Record, msi.Current, time.Time) error) (msi.Record, time.Time, error) {
	r, e := s.ReadRegisteredWindowsManagedMSI(ctx, b, k)
	if e != nil {
		return r, at, e
	}
	r.ClockFloor = s.now().Unix()
	if e = fn(&r, *s.current, s.now()); e != nil {
		return r, at, e
	}
	if e = msi.CheckFinal(ctx); e != nil {
		return r, at, e
	}
	if e = msi.Transition(s.record, r); e != nil {
		return r, at, e
	}
	if e = msi.FinalDeadline(s.record, r, *s.current, s.now().Unix()); e != nil {
		return r, at, e
	}
	raw, e := msi.EncodeRecord(r)
	if e != nil {
		return r, at, e
	}
	s.record, e = msi.DecodeRecord(raw)
	return s.record, s.now(), e
}
func (s *scheduledManagerStore) ReconcileWindowsManagedMSISchedulePolicy(ctx context.Context, b msi.Binding, k ed25519.PublicKey, now func() time.Time, allowed func(string) bool) (msi.Record, error) {
	r, e := s.ReadRegisteredWindowsManagedMSI(ctx, b, k)
	if e != nil {
		return r, e
	}
	if e = msi.TerminalizeSchedulePolicy(&r, now().Unix(), allowed); e != nil {
		return r, e
	}
	if e = msi.Transition(s.record, r); e != nil {
		return r, e
	}
	s.record = r
	return r, nil
}
func TestScheduledMSIJoinedManagerEndpointFenceRestart(t *testing.T) {
	f := newPair(t, true, true, false, true)
	ctx := context.Background()
	raw, _ := f.msiStore.Read("endpoint.json")
	var endpoint msi.EndpointRecord
	if e := msi.Canonical(raw, &endpoint, msi.MaxRecordBytes); e != nil {
		t.Fatal(e)
	}
	dp, e := msi.VerifyPermit(endpoint.Delivery, public(f.msiKey))
	if e != nil {
		t.Fatal(e)
	}
	rp, e := msi.VerifyPermit(endpoint.ReadinessPermit, public(f.msiKey))
	if e != nil {
		t.Fatal(e)
	}
	record, e := msi.NewRecord(f.grant, public(f.msiKey), public(f.msiExecutorKey), f.at.Load())
	if e != nil {
		t.Fatal(e)
	}
	record.Artifact = &msi.Artifact{Package: dp.Package, NativeAcceptanceDigest: dp.NativeAcceptanceDigest, PublisherStatus: dp.PublisherStatus, PublisherEvidenceDigest: dp.PublisherEvidenceDigest, CustodyDigest: digest("inert app-owned spool occurrence"), IntentAt: dp.IssuedAt, CompletedAt: dp.IssuedAt, Offset: dp.Package.Size, PrefixDigest: dp.Package.SHA256, LastChunkDigest: dp.Package.SHA256}
	record.TransferID = dp.TransferID
	record.Jobs.Sequence = 1
	record.DeliveryPermit = endpoint.Delivery
	record.DeliveryReport = endpoint.DeliveryReport
	record.DeliveryClaimedAt = dp.IssuedAt
	record.ReadinessPermit = endpoint.ReadinessPermit
	record.ReadinessReport = endpoint.ReadinessReport
	record.ReadinessClaimedAt = rp.IssuedAt
	if e = record.Validate(); e != nil {
		t.Fatal("already imported source seed", e)
	}
	// Match manager startup custody with the existing inert endpoint bytes. This
	// writes a private fixture file only, never an MSI invocation or host setup.
	dir, e := os.MkdirTemp(".", ".scheduled-msi-joined-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	dir, e = filepath.Abs(dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = manager.CreateSpool(dir); e != nil {
		t.Skip("protected source fixture ancestors unavailable", e)
	}
	if e = os.WriteFile(filepath.Join(manager.SpoolPath(dir), "artifact.msi"), f.payload.data, 0600); e != nil {
		t.Fatal(e)
	}
	spool, e := manager.OpenSpool(dir)
	if e != nil {
		t.Fatal(e)
	}
	store := &scheduledManagerStore{record: record, current: &f.msiCurrent, now: f.now}
	actor := dp.ActorID
	open := func() *manager.Manager {
		m, e := manager.Open(ctx, store, f.grant.Binding, f.msiKey, spool, f.now, func() error { return nil })
		if e != nil {
			t.Fatal(e)
		}
		allowed := func(a string) bool { return a == actor }
		if e = m.ConfigureOperatorPolicy(allowed, allowed); e != nil {
			t.Fatal(e)
		}
		if e = m.ConfigureSchedulePolicy(ctx, allowed); e != nil {
			t.Fatal(e)
		}
		return m
	}
	m := open()
	q := msi.ScheduleRequest{ArtifactID: msi.ArtifactIdentity(*record.Artifact), BindingDigest: msi.BindingDigest(f.grant.Binding), TransferID: dp.TransferID, JobSequence: 1, ReadinessDigest: msi.Digest(record.ReadinessReport), StartAt: rp.ExpiresAt, EndAt: rp.ExpiresAt + 120, PackageReviewAccepted: true, TermsAccepted: true, ServiceRiskAccepted: true, SynchronousActionsAccepted: true, ScheduleAccepted: true}
	wrong := q
	wrong.ArtifactRetiredCount++
	if e = m.Schedule(ctx, actor, wrong); !errors.Is(e, msi.ErrConflict) {
		t.Fatal("occurrence changed", e)
	}
	if e = m.Schedule(ctx, actor, q); e != nil {
		t.Fatal(e)
	}
	digest := store.record.Schedule.Approval.Digest
	m.Close()
	f.endpoint.Close()
	m = open()
	f.openMSI(t)
	f.at.Store(q.StartAt)
	ready, e := m.Poll(ctx)
	if e != nil || len(ready.Permit) == 0 {
		t.Fatal("fresh readiness", e)
	}
	if e = m.CheckRelease(ctx, ready.Permit, ""); e != nil {
		t.Fatal(e)
	}
	if e = f.endpoint.Accept(ctx, ready.Permit); e != nil {
		t.Fatal(e)
	}
	st, e := f.endpoint.Status(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Report(ctx, st.MutationReport); e != nil {
		t.Fatal("signed real shared state", e)
	}
	if e = m.Report(ctx, st.Report); e != nil {
		t.Fatal("signed real readiness", e)
	}
	install, e := m.Poll(ctx)
	if e != nil || len(install.Permit) == 0 {
		t.Fatal("one install", e)
	}
	if e = m.CheckRelease(ctx, install.Permit, ""); e != nil {
		t.Fatal(e)
	}
	if e = f.endpoint.Accept(ctx, install.Permit); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(3 * time.Second)
	var result []byte
	for time.Now().Before(deadline) {
		raw, _ := f.msiStore.Read("endpoint.json")
		var saved msi.EndpointRecord
		if msi.Canonical(raw, &saved, msi.MaxRecordBytes) == nil && len(saved.ResultReport) > 0 {
			result = saved.ResultReport
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(result) == 0 {
		t.Fatal("inert native completion missing")
	}
	if e = m.Report(ctx, result); e != nil {
		t.Fatal(e)
	}
	m.Close()
	f.endpoint.Close()
	m = open()
	defer m.Close()
	f.openMSI(t)
	defer f.endpoint.Close()
	v, e := m.View(ctx)
	if e != nil || v.State != "complete" || v.Result == nil || v.Result.Outcome != "succeeded" || v.Schedule == nil || v.Schedule.Digest != digest || f.msiNative.calls.Load() != 1 {
		t.Fatal("durable one-attempt outcome", v, e)
	}
	if p, e := m.Poll(ctx); e != nil || len(p.Permit) != 0 {
		t.Fatal("manager replay", e)
	}
	if e = f.endpoint.Accept(ctx, install.Permit); e == nil {
		t.Fatal("endpoint replay")
	}
}
