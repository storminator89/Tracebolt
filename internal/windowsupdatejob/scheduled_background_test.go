package windowsupdatejob

import (
	"bytes"
	"context"
	"errors"
	"localrmm/internal/actionpermit"
	fence "localrmm/internal/windowsmutationfence"
	"testing"
	"time"
)

func backgroundSharedReport(t *testing.T, f *workflowFixture, at int64, busy bool, revision uint64) []byte {
	t.Helper()
	j := f.m.record.Jobs[0]
	c, e := VerifyChallenge(j.Challenge, f.m.record.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	status := fence.Status{Active: true, Phase: "idle", Revision: revision, Retained: 1}
	if busy {
		status.Blocked = true
		status.Domain = fence.ManagedMSI
		status.JobID = "transfer_88888888888888888888888888888888"
		status.Phase = "dispatch_intent"
		status.Recovery = "intervention_required"
	}
	raw, e := SignStatement(Statement{Version: RelayVersion, Kind: "mutation", Binding: f.consent.Binding, JobID: f.id, ReferenceDigest: actionpermit.Digest(j.Challenge), Deadline: c.Deadline, IssuedAt: at, ExpiresAt: at + 60, Mutation: &status}, executorKey())
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func pendingBackgroundReadiness(t *testing.T, f *workflowFixture) []byte {
	t.Helper()
	raw, e := f.m.ClaimReadiness(context.Background(), f.id)
	if e != nil {
		t.Fatal(e)
	}
	c, e := VerifyChallenge(raw, f.m.record.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	r := f.source.value
	r.CapturedAt = f.at.Unix()
	proof, e := SignStatement(Statement{Version: RelayVersion, Kind: "readiness", Binding: f.consent.Binding, JobID: f.id, ReferenceDigest: actionpermit.Digest(raw), Deadline: c.Deadline, IssuedAt: r.CapturedAt, ExpiresAt: min(r.CapturedAt+60, c.Deadline), Readiness: &r}, executorKey())
	if e != nil {
		t.Fatal(e)
	}
	return proof
}
func TestScheduledBackgroundWaitsForFreshInWindowIdleWithoutChangingIntent(t *testing.T) {
	for _, initial := range []string{"missing", "pre-window", "busy"} {
		t.Run(initial, func(t *testing.T) {
			f := scheduleFixture(t, true)
			a := approveSchedule(t, f)
			ctx := context.Background()
			if initial == "pre-window" {
				if e := f.m.Report(ctx, backgroundSharedReport(t, f, f.at.Unix(), false, 1)); e != nil {
					t.Fatal(e)
				}
			}
			f.at = time.Unix(a.StartAt, 0)
			if _, e := f.m.Pending(ctx); e != nil {
				t.Fatal(e)
			}
			if initial == "busy" {
				if e := f.m.Report(ctx, backgroundSharedReport(t, f, f.at.Unix(), true, 1)); e != nil {
					t.Fatal(e)
				}
			}
			proof := pendingBackgroundReadiness(t, f)
			challenge := bytes.Clone(f.m.record.Jobs[0].Challenge)
			sequence := f.m.record.ReadinessSequence
			if e := f.m.Report(ctx, proof); !errors.Is(e, ErrUnavailable) {
				t.Fatal("unconfirmed shared owner issued", e)
			}
			if f.m.record.Sequence != 0 || len(f.m.record.Jobs[0].Envelope) != 0 || f.m.record.Jobs[0].Schedule.Approval != a || reservedOperations(f.m.record) != 1 {
				t.Fatal("blocked issuance changed original authority")
			}
			f.at = f.at.Add(time.Second)
			if e := f.m.Report(ctx, backgroundSharedReport(t, f, f.at.Unix(), false, 2)); e != nil {
				t.Fatal(e)
			}
			if e := f.m.Report(ctx, proof); e != nil {
				t.Fatal("same immutable report rejected", e)
			}
			saved := bytes.Clone(f.m.record.Jobs[0].Envelope)
			if len(saved) == 0 || f.m.record.Sequence != 1 || f.m.record.ReadinessSequence != sequence || !bytes.Equal(challenge, f.m.record.Jobs[0].Challenge) || f.m.record.Jobs[0].Schedule.Approval != a {
				t.Fatal("reconciliation regenerated authority")
			}
			if e := f.m.Report(ctx, proof); e != nil || !bytes.Equal(saved, f.m.record.Jobs[0].Envelope) || f.m.record.Sequence != 1 {
				t.Fatal("duplicate permit", e)
			}
			v, e := f.m.View(ctx, f.consent.Binding.DeviceID, f.actor)
			if e != nil || !v.BackgroundExecutor || !v.BackgroundScheduling || !v.SchedulingAvailable {
				t.Fatal("combined view missing", e)
			}
			permit, e := f.m.Claim(ctx, f.id)
			if e != nil || !bytes.Equal(permit, saved) {
				t.Fatal(e)
			}
			if _, e = f.m.Claim(ctx, f.id); !errors.Is(e, ErrConsumed) {
				t.Fatal("claim replay", e)
			}
		})
	}
}
func TestScheduledBackgroundWaitingDoesNotReviveExpiredOrRevokedAuthority(t *testing.T) {
	for _, kind := range []string{"expired-report", "past-window", "removed-actor", "changed-readiness"} {
		t.Run(kind, func(t *testing.T) {
			f := scheduleFixture(t, true)
			a := approveSchedule(t, f)
			ctx := context.Background()
			f.at = time.Unix(a.StartAt, 0)
			if _, e := f.m.Pending(ctx); e != nil {
				t.Fatal(e)
			}
			if kind == "changed-readiness" {
				f.source.value.Downloaded = No
			}
			proof := pendingBackgroundReadiness(t, f)
			if kind == "expired-report" {
				f.at = f.at.Add(60 * time.Second)
			}
			if kind == "past-window" {
				f.at = time.Unix(a.EndAt, 0)
			}
			if kind == "removed-actor" {
				reopenScheduled(t, f, false)
			}
			if e := f.m.Report(ctx, backgroundSharedReport(t, f, f.at.Unix(), false, 2)); e != nil {
				t.Fatal(e)
			}
			e := f.m.Report(ctx, proof)
			if kind == "changed-readiness" {
				if e != nil || f.m.record.Jobs[0].State != "schedule_blocked" {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("expired/revoked issued")
			}
			if f.m.record.Sequence != 0 || len(f.m.record.Jobs[0].Envelope) != 0 || f.m.record.Jobs[0].Schedule.Approval != a || reservedOperations(f.m.record) != 1 {
				t.Fatal("original grant reservation changed")
			}
		})
	}
}
