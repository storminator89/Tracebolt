package windowsupdatejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/actionpermit"
	"testing"
	"time"
)

func reusableManagerFixture(t *testing.T, scheduled bool) *workflowFixture {
	t.Helper()
	f := fixture(t)
	f.consent.Version = ReusableConsentVersion
	f.consent.ReusableAcknowledged = true
	f.consent.BackgroundAcknowledged = true
	f.consent.MutationPlanDigest = actionpermit.Digest([]byte("fresh reusable plan"))
	f.consent.PeerBindingDigest = actionpermit.Digest([]byte("fresh MSI peer"))
	f.guard.current.LeafNotAfter = f.consent.ExpiresAt
	if scheduled {
		f.consent.ScheduleScope = ScheduleScope
		f.consent.ScheduleAcknowledged = true
	}
	r, e := NewRecordWithExecutor(f.consent, f.key.Public().(ed25519.PublicKey), executorKey().Public().(ed25519.PublicKey), f.at.Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := EncodeRecord(r)
	c, _ := json.Marshal(f.consent)
	f.store.files = map[string][]byte{"jobs.json": raw, "started.json": c, "receipt.json": c}
	f.m, e = Open(f.store, f.guard, f.source, f.key, func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	if e = f.m.ConfigureOperatorPolicy(func(string) bool { return true }); e != nil {
		t.Fatal(e)
	}
	if scheduled {
		f.m.source = nil
		if e = f.m.ConfigureSchedulePolicy(context.Background(), func(string) bool { return true }); e != nil {
			t.Fatal(e)
		}
	}
	return f
}
func reusableApprovedResult(t *testing.T, f *workflowFixture, outcome string) []byte {
	t.Helper()
	ctx := context.Background()
	f.request(t)
	if e := f.m.Report(ctx, backgroundSharedReport(t, f, f.at.Unix(), false, uint64(f.at.Unix()))); e != nil {
		t.Fatal(e)
	}
	p := f.m.record.Jobs[0].Preview
	if e := f.m.Approve(ctx, f.consent.Binding.DeviceID, f.actor, f.id, p.Digest, true); e != nil {
		t.Fatal(e)
	}
	raw, e := f.m.Claim(ctx, f.id)
	if e != nil {
		t.Fatal(e)
	}
	result := Result{JobID: f.id, EnvelopeDigest: actionpermit.Digest(raw), Attempted: true, Outcome: outcome, OperationResult: 2, RebootRequired: No, CompletedAt: f.at.Unix()}
	if outcome == "failed" {
		result.OperationResult = 4
		result.HResult = -1
	}
	if outcome == "uncertain" {
		result.OperationResult = 0
		result.RebootRequired = Unknown
	}
	proof, e := SignStatement(Statement{Version: RelayVersion, Kind: "result", Binding: f.consent.Binding, JobID: f.id, ReferenceDigest: result.EnvelopeDigest, Deadline: p.ExpiresAt, IssuedAt: result.CompletedAt, ExpiresAt: result.CompletedAt + 300, Result: &result}, executorKey())
	if e != nil {
		t.Fatal(e)
	}
	if e = f.m.Report(ctx, proof); e != nil {
		t.Fatal(e)
	}
	return raw
}
func requestManagerRetirement(t *testing.T, f *workflowFixture) []byte {
	t.Helper()
	j := f.m.record.Jobs[0]
	ctx := context.Background()
	if e := f.m.Retire(ctx, f.consent.Binding.DeviceID, f.actor, j.ID, j.Occurrence, actionpermit.Digest(j.Envelope), actionpermit.Digest(j.ResultReport), true); e != nil {
		t.Fatal(e)
	}
	raw, e := f.m.ClaimRetirement(ctx, j.ID)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func managerRetirementAck(t *testing.T, f *workflowFixture, raw []byte) []byte {
	t.Helper()
	p, e := VerifyRetirement(raw, f.m.record.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	a, e := SignRetirementReport(RetirementReport{Version: RetirementVersion, Binding: p.Binding, JobID: p.JobID, Selection: p.Selection, Occurrence: p.Occurrence, ReferenceDigest: actionpermit.Digest(raw), EnvelopeDigest: p.EnvelopeDigest, ResultDigest: p.ResultDigest, ReleaseDigest: actionpermit.Digest([]byte("synthetic released owner")), IssuedAt: f.at.Unix(), ExpiresAt: min(f.at.Unix()+300, p.ExpiresAt)}, executorKey())
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func TestReusableManagerFortyIndependentJobsAcrossReopen(t *testing.T) {
	f := reusableManagerFixture(t, false)
	ctx := context.Background()
	var firstAck, firstPermit []byte
	for i := 1; i <= 40; i++ {
		f.id = fmt.Sprintf("update_%032x", i)
		f.source.value.CapturedAt = f.at.Unix()
		prior, _ := DecodeRecord(f.m.raw)
		permit := reusableApprovedResult(t, f, "succeeded")
		if e := CheckReusableTransition(prior, f.m.record); e != nil {
			t.Fatal("approval transition", i, e)
		}
		if i == 1 {
			firstPermit = permit
		}
		v, e := f.m.View(ctx, f.consent.Binding.DeviceID, f.actor)
		if e != nil || v.Available || !v.ReusableJobs || v.Job.Retirement.State != "available" {
			t.Fatal("successful work was freed before review", i, e)
		}
		j := f.m.record.Jobs[0]
		if e = f.m.Retire(ctx, f.consent.Binding.DeviceID, f.actor, j.ID, j.Occurrence, actionpermit.Digest(j.Envelope), actionpermit.Digest(j.ResultReport), false); !errors.Is(e, ErrInvalid) {
			t.Fatal("unchecked retirement", e)
		}
		raw := requestManagerRetirement(t, f)
		again, e := f.m.ClaimRetirement(ctx, f.id)
		if e != nil || !bytes.Equal(raw, again) {
			t.Fatal("claim retry changed metadata authority", e)
		}
		before, _ := DecodeRecord(f.m.raw)
		ack := managerRetirementAck(t, f, raw)
		if i == 1 {
			firstAck = ack
		}
		if e = f.m.Report(ctx, ack); e != nil {
			t.Fatal(i, e)
		}
		if e = CheckReusableTransition(before, f.m.record); e != nil {
			t.Fatal("retirement transition", i, e)
		}
		if e = f.m.Report(ctx, ack); e != nil {
			t.Fatal("exact ack not idempotent", e)
		}
		if len(f.m.record.Jobs) != 1 || len(f.m.record.Recent) > MaxRecentJobs || f.m.record.Sequence != uint64(i) || f.m.record.RetiredFloor != uint64(i) || len(f.m.raw) > 40<<10 {
			t.Fatal("unbounded or rolled back state", i, len(f.m.raw))
		}
		f.m, e = Open(f.store, f.guard, f.source, f.key, func() time.Time { return f.at })
		if e != nil {
			t.Fatal("reopen", i, e)
		}
		f.at = f.at.Add(time.Second)
	}
	if e := f.m.Report(ctx, firstAck); e == nil {
		t.Fatal("old compacted acknowledgement revived")
	}
	p, _ := Verify(firstPermit, f.key.Public().(ed25519.PublicKey))
	if e := f.m.Approve(ctx, f.consent.Binding.DeviceID, f.actor, p.Preview.ID, p.Preview.Digest, true); e == nil {
		t.Fatal("old approval revived")
	}
	h, e := f.m.History(ctx, f.consent.Binding.DeviceID)
	if e != nil || !h.ReusableJobs || h.RemainingCapacity != 1 || len(h.Jobs) != MaxRecentJobs {
		t.Fatal("reusable history", h, e)
	}
}
func TestReusableManagerOnlySettledSuccessCanRetire(t *testing.T) {
	for _, outcome := range []string{"failed", "uncertain"} {
		t.Run(outcome, func(t *testing.T) {
			f := reusableManagerFixture(t, false)
			reusableApprovedResult(t, f, outcome)
			j := f.m.record.Jobs[0]
			if e := f.m.Retire(context.Background(), f.consent.Binding.DeviceID, f.actor, j.ID, j.Occurrence, actionpermit.Digest(j.Envelope), actionpermit.Digest(j.ResultReport), true); e == nil {
				t.Fatal("unsafe retirement")
			}
			f.id = fmt.Sprintf("update_%032x", 77)
			if e := f.m.Request(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, f.source.value.Selection); e == nil {
				t.Fatal("unsettled work freed")
			}
		})
	}
}
func TestReusableScheduleReservationConsumesOccurrenceBeforeDispatchAndBlocksAfterCancel(t *testing.T) {
	f := reusableManagerFixture(t, true)
	a := approveSchedule(t, f)
	if f.m.record.Sequence != 1 || f.m.record.Jobs[0].Occurrence != 1 || len(f.m.record.Jobs[0].Envelope) != 0 {
		t.Fatal("reservation did not consume occurrence")
	}
	if e := f.m.CancelSchedule(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, a.Digest); e != nil {
		t.Fatal(e)
	}
	f.id = fmt.Sprintf("update_%032x", 99)
	if e := f.m.Request(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, f.source.value.Selection); e == nil {
		t.Fatal("cancel silently freed occurrence")
	}
}
func TestReusableRetirementExpiryAndPinsBlockWithoutRenewal(t *testing.T) {
	f := reusableManagerFixture(t, false)
	reusableApprovedResult(t, f, "succeeded")
	j := f.m.record.Jobs[0]
	if e := f.m.Retire(context.Background(), f.consent.Binding.DeviceID, f.actor, j.ID, j.Occurrence+1, actionpermit.Digest(j.Envelope), actionpermit.Digest(j.ResultReport), true); e == nil {
		t.Fatal("changed occurrence")
	}
	raw := requestManagerRetirement(t, f)
	ack := managerRetirementAck(t, f, raw)
	f.at = f.at.Add(300 * time.Second)
	if e := f.m.Report(context.Background(), ack); !errors.Is(e, ErrExpired) {
		t.Fatal("expired ack", e)
	}
	if _, e := f.m.ClaimRetirement(context.Background(), f.id); !errors.Is(e, ErrExpired) {
		t.Fatal("expired permit refreshed", e)
	}
	v, e := f.m.View(context.Background(), f.consent.Binding.DeviceID, f.actor)
	if e != nil || v.Available || v.Job.Retirement.State != "blocked" {
		t.Fatal("expired retirement freed", e)
	}
}

func TestReusableRetirementDistinguishesAcceptedOldResultFromMissedExpiredReport(t *testing.T) {
	ctx := context.Background()
	accepted := reusableManagerFixture(t, false)
	reusableApprovedResult(t, accepted, "succeeded")
	original := bytes.Clone(accepted.m.record.Jobs[0].ResultReport)
	accepted.at = accepted.at.Add(301 * time.Second)
	_ = requestManagerRetirement(t, accepted)
	if !bytes.Equal(original, accepted.m.record.Jobs[0].ResultReport) {
		t.Fatal("retirement resigned accepted result")
	}
	missed := reusableManagerFixture(t, false)
	missed.request(t)
	if e := missed.m.Report(ctx, backgroundSharedReport(t, missed, missed.at.Unix(), false, 1)); e != nil {
		t.Fatal(e)
	}
	p := missed.m.record.Jobs[0].Preview
	if e := missed.m.Approve(ctx, missed.consent.Binding.DeviceID, missed.actor, missed.id, p.Digest, true); e != nil {
		t.Fatal(e)
	}
	raw, e := missed.m.Claim(ctx, missed.id)
	if e != nil {
		t.Fatal(e)
	}
	result := Result{JobID: missed.id, EnvelopeDigest: actionpermit.Digest(raw), Attempted: true, Outcome: "succeeded", OperationResult: 2, RebootRequired: No, CompletedAt: missed.at.Unix()}
	proof, e := SignStatement(Statement{Version: RelayVersion, Kind: "result", Binding: missed.consent.Binding, JobID: missed.id, ReferenceDigest: result.EnvelopeDigest, Deadline: p.ExpiresAt, IssuedAt: result.CompletedAt, ExpiresAt: result.CompletedAt + 300, Result: &result}, executorKey())
	if e != nil {
		t.Fatal(e)
	}
	missed.at = missed.at.Add(301 * time.Second)
	if e = missed.m.Report(ctx, proof); !errors.Is(e, ErrExpired) {
		t.Fatal("missed report revived", e)
	}
	if e = missed.m.Retire(ctx, missed.consent.Binding.DeviceID, missed.actor, missed.id, 1, result.EnvelopeDigest, actionpermit.Digest(proof), true); e == nil {
		t.Fatal("unaccepted result retired")
	}
	if missed.m.record.Jobs[0].Result != nil || missed.m.record.RetiredFloor != 0 {
		t.Fatal("unaccepted evidence installed into record")
	}
}

func TestReusableManualFinalIssueRejectsAgedOrBusySharedEvidence(t *testing.T) {
	f := reusableManagerFixture(t, false)
	f.request(t)
	ctx := context.Background()
	if e := f.m.Report(ctx, backgroundSharedReport(t, f, f.at.Unix()-30, false, 1)); e != nil {
		t.Fatal(e)
	}
	j := f.m.record.Jobs[0]
	if e := CheckScheduledMutationIssue(f.m.record, j, f.at.Unix()); e != nil {
		t.Fatal(e)
	}
	if e := CheckScheduledMutationIssue(f.m.record, j, f.at.Unix()+31); !errors.Is(e, ErrUnavailable) {
		t.Fatal("final aged shared status admitted", e)
	}
	if e := f.m.Report(ctx, backgroundSharedReport(t, f, f.at.Unix(), true, 2)); e != nil {
		t.Fatal(e)
	}
	if e := CheckScheduledMutationIssue(f.m.record, j, f.at.Unix()); !errors.Is(e, ErrUnavailable) {
		t.Fatal("concurrent MSI owner admitted", e)
	}
}
