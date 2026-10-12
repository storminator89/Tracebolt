package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/actionpermit"
	msi "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	job "localrmm/internal/windowsupdatejob"
	"testing"
	"time"
)

func setupScheduledBackgroundPeer(t *testing.T, f *windowsUpdateStoreFixture) {
	t.Helper()
	c := &f.consent
	c.Version = job.ScheduledBackgroundConsentVersion
	c.BackgroundAcknowledged = true
	c.MutationPlanDigest = actionpermit.Digest([]byte("fresh combined scheduled background plan"))
	mk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{117}, 32)).Public().(ed25519.PublicKey)
	me := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{118}, 32)).Public().(ed25519.PublicKey)
	b := msi.Binding{ManagerID: c.Binding.ManagerID, DeviceID: c.Binding.DeviceID, IncarnationDigest: c.Binding.IncarnationDigest, ExecutorID: id("executor", 25), ExecutorKeyID: actionpermit.Digest(me), KeyID: actionpermit.Digest(mk), DeliveryGrantID: id("grant", 25), InstallGrantID: id("grant", 26)}
	wb, _ := json.Marshal(c.Binding)
	mb, _ := json.Marshal(b)
	c.PeerBindingDigest = actionpermit.Digest(mb)
	g := msi.Grant{Version: msi.ReusableGrantVersion, ReusableAcknowledged: true, Binding: b, MutationPlanDigest: c.MutationPlanDigest, PeerBindingDigest: actionpermit.Digest(wb), DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: c.ExpiresAt}
	if e := f.store.SetupWindowsManagedMSIFleetCreateOnly(context.Background(), mk, me, g, f.at, false); e != nil {
		t.Fatal(e)
	}
}
func scheduledStoreShared(t *testing.T, s *scheduledStoreFixture, busy bool, at int64, revision uint64) []byte {
	t.Helper()
	_, r, _ := s.f.record(t)
	j := r.Jobs[0]
	ch, e := job.VerifyChallenge(j.Challenge, r.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	state := fence.Status{Active: true, Phase: "idle", Revision: revision, Retained: 1}
	if busy {
		state.Blocked = true
		state.Domain = fence.ManagedMSI
		state.JobID = id("transfer", 25)
		state.Phase = "dispatch_intent"
		state.Recovery = "intervention_required"
	}
	raw, e := job.SignStatement(job.Statement{Version: job.RelayVersion, Kind: "mutation", Binding: r.Consent.Binding, JobID: j.ID, ReferenceDigest: actionpermit.Digest(j.Challenge), Deadline: ch.Deadline, IssuedAt: at, ExpiresAt: at + 60, Mutation: &state}, s.f.executor)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestScheduledBackgroundEnrollmentReconcilesExactSavedReadinessAfterBusy(t *testing.T) {
	s := newScheduledStoreFixture(t, true)
	proof := s.due(t)
	ctx := context.Background()
	if e := s.m.Report(ctx, scheduledStoreShared(t, s, true, s.f.at.Unix(), 1)); e != nil {
		t.Fatal(e)
	}
	before, original, _ := s.f.record(t)
	if e := s.m.Report(ctx, proof); !errors.Is(e, job.ErrUnavailable) {
		t.Fatal("busy issued permit", e)
	}
	after, r, _ := s.f.record(t)
	if !bytes.Equal(before, after) || r.Sequence != 0 || len(r.Jobs[0].Envelope) != 0 {
		t.Fatal("business rejection wrote prospective authority")
	}
	s.m.Close()
	s.m = s.open(t, true)
	s.f.at = s.f.at.Add(time.Second)
	if e := s.m.Report(ctx, scheduledStoreShared(t, s, false, s.f.at.Unix(), 2)); e != nil {
		t.Fatal(e)
	}
	if e := s.m.Report(ctx, proof); e != nil {
		t.Fatal("exact outbox failed after refresh/reopen", e)
	}
	before, r, _ = s.f.record(t)
	if r.Sequence != 1 || r.ReadinessSequence != original.ReadinessSequence || !bytes.Equal(r.Jobs[0].Challenge, original.Jobs[0].Challenge) || r.Jobs[0].Schedule.Approval != s.approval {
		t.Fatal("reconciliation minted replacement authority")
	}
	if e := s.m.Report(ctx, proof); e != nil {
		t.Fatal(e)
	}
	after, _, _ = s.f.record(t)
	if !bytes.Equal(before, after) {
		t.Fatal("duplicate report re-signed")
	}
	if _, e := s.m.Claim(ctx, s.id); e != nil {
		t.Fatal(e)
	}
	if _, e := s.m.Claim(ctx, s.id); !errors.Is(e, job.ErrConsumed) {
		t.Fatal(e)
	}
}
func TestScheduledBackgroundFinalCommitRechecksSharedCaptureAfterBlockingChecks(t *testing.T) {
	s := newScheduledStoreFixture(t, true)
	ctx := context.Background()
	// Shared evidence is valid at report entry but expires before readiness does.
	s.f.at = time.Unix(s.approval.StartAt+1, 0)
	if _, e := s.m.Pending(ctx); e != nil {
		t.Fatal(e)
	}
	proof := s.readiness(t)
	if e := s.m.Report(ctx, scheduledStoreShared(t, s, false, s.approval.StartAt, 1)); e != nil {
		t.Fatal(e)
	}
	before, _, _ := s.f.record(t)
	end := time.Unix(s.approval.StartAt+60, 0)
	ctx = WithOverviewClock(ctx, func() time.Time { return s.f.at })
	ctx = job.WithFinalCheck(ctx, func() error { s.f.at = end; return nil })
	e := s.m.Report(ctx, proof)
	if !errors.Is(e, job.ErrUnavailable) {
		t.Fatal("expired final capture issued", e)
	}
	after, r, floor := s.f.record(t)
	if !bytes.Equal(before, after) || r.Sequence != 0 || floor != end.Unix() {
		t.Fatal("final failure committed authority")
	}
}
func TestScheduledBackgroundOriginalCapCancellationAndPolicyRemainIrreversible(t *testing.T) {
	s := newScheduledStoreFixture(t, true)
	ctx := context.Background()
	if e := s.m.CancelSchedule(ctx, s.f.consent.Binding.DeviceID, s.actor, s.id, s.approval.Digest); e != nil {
		t.Fatal(e)
	}
	h, e := s.m.History(ctx, s.f.consent.Binding.DeviceID)
	if e != nil || h.RemainingCapacity != 31 {
		t.Fatal("cancellation refunded original grant", h, e)
	}
	s.m.Close()
	s.m = s.open(t, true)
	if e := s.m.RevokeScheduling(ctx, s.f.consent.Binding.DeviceID, s.actor, true); e != nil {
		t.Fatal(e)
	}
	s.m.Close()
	s.m = s.open(t, true)
	v, e := s.m.View(ctx, s.f.consent.Binding.DeviceID, s.actor)
	if e != nil || !v.SchedulingRevoked || v.SchedulingAvailable || !v.BackgroundScheduling {
		t.Fatal("restart revived schedule", v, e)
	}
}
