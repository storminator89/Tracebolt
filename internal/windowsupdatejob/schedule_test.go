package windowsupdatejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
)

func scheduleFixture(t *testing.T) *workflowFixture {
	t.Helper()
	f := fixture(t)
	f.consent.Version = ScheduledConsentVersion
	f.consent.ScheduleScope = ScheduleScope
	f.consent.ScheduleAcknowledged = true
	f.consent.ExpiresAt = f.at.Unix() + 90000
	f.guard.current.LeafNotAfter = f.at.Unix() + 90000
	r, e := NewRecordWithExecutor(f.consent, f.key.Public().(ed25519.PublicKey), executorKey().Public().(ed25519.PublicKey), f.at.Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := EncodeRecord(r)
	consent, _ := json.Marshal(f.consent)
	f.store.files = map[string][]byte{"jobs.json": raw, "started.json": consent, "receipt.json": consent}
	f.m, e = Open(f.store, f.guard, f.source, f.key, func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	f.m.source = nil
	if e = f.m.ConfigureOperatorPolicy(func(actor string) bool { return actor == f.actor }); e != nil {
		t.Fatal(e)
	}
	if e = f.m.ConfigureSchedulePolicy(context.Background(), func(actor string) bool { return actor == f.actor }); e != nil {
		t.Fatal(e)
	}
	return f
}
func scheduleReport(t *testing.T, f *workflowFixture, mutate func(*Readiness)) []byte {
	t.Helper()
	raw, e := f.m.ClaimReadiness(context.Background(), f.id)
	if e != nil {
		t.Fatal(e)
	}
	challenge, e := VerifyChallenge(raw, f.key.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	r := f.source.value
	r.CapturedAt = f.at.Unix()
	if mutate != nil {
		mutate(&r)
	}
	proof, e := SignStatement(Statement{Version: RelayVersion, Kind: "readiness", Binding: f.consent.Binding, JobID: f.id, ReferenceDigest: actionpermit.Digest(raw), Deadline: challenge.Deadline, IssuedAt: r.CapturedAt, ExpiresAt: min(r.CapturedAt+60, challenge.Deadline), Readiness: &r}, executorKey())
	if e != nil {
		t.Fatal(e)
	}
	if e = f.m.Report(context.Background(), proof); e != nil {
		t.Fatal(e)
	}
	return proof
}
func approveSchedule(t *testing.T, f *workflowFixture) ScheduleApproval {
	t.Helper()
	f.request(t)
	scheduleReport(t, f, nil)
	p := *f.m.record.Jobs[len(f.m.record.Jobs)-1].Preview
	if e := f.m.Schedule(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, p.Digest, f.at.Unix()+120, f.at.Unix()+600, true); e != nil {
		t.Fatal(e)
	}
	return f.m.record.Jobs[len(f.m.record.Jobs)-1].Schedule.Approval
}
func reopenScheduled(t *testing.T, f *workflowFixture, allowed bool) {
	t.Helper()
	m, e := Open(f.store, f.guard, f.source, f.key, func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	m.source = nil
	if e = m.ConfigureOperatorPolicy(func(string) bool { return true }); e != nil {
		t.Fatal(e)
	}
	if e = m.ConfigureSchedulePolicy(context.Background(), func(string) bool { return allowed }); e != nil {
		t.Fatal(e)
	}
	f.m = m
}
func TestScheduleFreshReadinessIssuesOnceAndExecutesOnce(t *testing.T) {
	f := scheduleFixture(t)
	a := approveSchedule(t, f)
	if f.m.record.Sequence != 0 || reservedOperations(f.m.record) != 1 {
		t.Fatal("approval allocated install sequence or lost reservation")
	}
	if p, e := f.m.Pending(context.Background()); e != nil || p != nil {
		t.Fatal("early work", p, e)
	}
	reopenScheduled(t, f, true)
	if f.m.record.Jobs[0].Schedule.Approval != a {
		t.Fatal("restart renewed authority")
	}
	f.at = time.Unix(a.StartAt, 0)
	p, e := f.m.Pending(context.Background())
	if e != nil || p == nil || p.Kind != "readiness" || p.Deadline > f.at.Unix()+120 {
		t.Fatal(p, e)
	}
	proof := scheduleReport(t, f, nil)
	saved := bytes.Clone(f.m.record.Jobs[0].Envelope)
	if e = f.m.Report(context.Background(), proof); e != nil || !bytes.Equal(saved, f.m.record.Jobs[0].Envelope) || f.m.record.Sequence != 1 || reservedOperations(f.m.record) != 1 {
		t.Fatal("report regenerated or double counted", e)
	}
	permit, e := Verify(saved, f.key.Public().(ed25519.PublicKey))
	if e != nil || permit.Version != ScheduledPermitVersion || permit.ApprovedAt != a.ApprovedAt || permit.PermitIssuedAt != a.StartAt || permit.Preview.ExpiresAt > a.EndAt {
		t.Fatal(permit, e)
	}
	raw, e := f.m.Claim(context.Background(), f.id)
	if e != nil || !bytes.Equal(raw, saved) {
		t.Fatal(e)
	}
	if _, e = f.m.Claim(context.Background(), f.id); !errors.Is(e, ErrConsumed) {
		t.Fatal("redelivery", e)
	}
	if e = f.m.CancelSchedule(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, a.Digest); !errors.Is(e, ErrConsumed) {
		t.Fatal("cancel stopped consumed claim", e)
	}
	n := &nativeFixture{readiness: f.source.value, result: NativeResult{OperationResult: 2, RebootRequired: No}}
	n.readiness.CapturedAt = f.at.Unix()
	x, store := executorFixture(t, f, n)
	result, e := x.Execute(context.Background(), raw)
	if e != nil || result.Outcome != "succeeded" || n.installs != 1 {
		t.Fatal(result, e, n.installs)
	}
	x = reopenExecutor(t, f, store, n)
	if _, e = x.Execute(context.Background(), raw); !errors.Is(e, ErrConsumed) || n.installs != 1 {
		t.Fatal("restart reinstall", e)
	}
}
func TestScheduleNeedsFreshConsentAndExplicitApproval(t *testing.T) {
	f := fixture(t)
	f.m.source = nil
	f.request(t)
	scheduleReport(t, f, nil)
	p := f.m.record.Jobs[0].Preview
	if e := f.m.Schedule(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, p.Digest, f.at.Unix()+120, f.at.Unix()+240, true); !errors.Is(e, ErrAuthority) {
		t.Fatal("manual scope promoted", e)
	}
	f = scheduleFixture(t)
	f.request(t)
	scheduleReport(t, f, nil)
	p = f.m.record.Jobs[0].Preview
	for _, window := range [][2]int64{{0, 120}, {86401, 86521}, {120, 179}, {120, 3721}, {120, 100000}} {
		if e := f.m.Schedule(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, p.Digest, f.at.Unix()+window[0], f.at.Unix()+window[1], true); !errors.Is(e, ErrInvalid) {
			t.Fatal(window, e)
		}
	}
	if e := f.m.Schedule(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, p.Digest, f.at.Unix()+120, f.at.Unix()+240, false); !errors.Is(e, ErrInvalid) {
		t.Fatal("implicit approval", e)
	}
	f.guard.current.LeafNotAfter = f.at.Unix() + 200
	if e := f.m.Schedule(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, p.Digest, f.at.Unix()+120, f.at.Unix()+240, true); !errors.Is(e, ErrInvalid) {
		t.Fatal("window outlived approval leaf", e)
	}
}
func TestScheduleCancelChangedFactsExpiryAndLostReadinessAreTerminal(t *testing.T) {
	for _, mode := range []string{"cancel_before", "cancel_issued", "changed", "unknown", "lost_readiness", "expired", "operator_removed", "revoke"} {
		t.Run(mode, func(t *testing.T) {
			f := scheduleFixture(t)
			a := approveSchedule(t, f)
			ctx := context.Background()
			switch mode {
			case "cancel_before":
				if e := f.m.CancelSchedule(ctx, f.consent.Binding.DeviceID, f.actor, f.id, a.Digest); e != nil {
					t.Fatal(e)
				}
			case "operator_removed":
				reopenScheduled(t, f, false)
				reopenScheduled(t, f, true)
			case "revoke":
				if e := f.m.RevokeScheduling(ctx, f.consent.Binding.DeviceID, f.actor, true); e != nil {
					t.Fatal(e)
				}
				reopenScheduled(t, f, true)
			case "expired":
				f.at = time.Unix(a.EndAt, 0)
			default:
				f.at = time.Unix(a.StartAt, 0)
				if _, e := f.m.Pending(ctx); e != nil {
					t.Fatal(e)
				}
				if mode == "lost_readiness" {
					if _, e := f.m.ClaimReadiness(ctx, f.id); e != nil {
						t.Fatal(e)
					}
					if p, e := f.m.Pending(ctx); e != nil || p != nil {
						t.Fatal("lost claim redelivery", e)
					}
					f.at = f.at.Add(120 * time.Second)
				} else {
					scheduleReport(t, f, func(r *Readiness) {
						if mode == "changed" {
							r.RebootBehavior = "always"
						}
						if mode == "unknown" {
							r.Downloaded = Unknown
						}
					})
					if mode == "cancel_issued" {
						if e := f.m.CancelSchedule(ctx, f.consent.Binding.DeviceID, f.actor, f.id, a.Digest); e != nil {
							t.Fatal(e)
						}
					}
				}
			}
			if f.at.Unix() < a.StartAt {
				f.at = time.Unix(a.StartAt, 0)
			}
			if p, e := f.m.Pending(ctx); e != nil || p != nil {
				t.Fatal("terminal schedule dispatched", p, e)
			}
			if _, e := f.m.Claim(ctx, f.id); e == nil {
				t.Fatal("terminal schedule delivered")
			}
			before := f.m.record.ReadinessSequence
			reopenScheduled(t, f, true)
			if p, e := f.m.Pending(ctx); e != nil || p != nil || f.m.record.ReadinessSequence != before {
				t.Fatal("terminal schedule regenerated", p, e)
			}
			if reservedOperations(f.m.record) != 1 {
				t.Fatal("terminal schedule lost reservation")
			}
		})
	}
}
func TestScheduleRetainsThirtyTwoReservationsAndNoEarlyInstallSequence(t *testing.T) {
	f := scheduleFixture(t)
	ctx := context.Background()
	for i := 0; i < MaxJobs; i++ {
		f.id = fmt.Sprintf("update_%032x", i+1)
		a := approveSchedule(t, f)
		if e := f.m.CancelSchedule(ctx, f.consent.Binding.DeviceID, f.actor, f.id, a.Digest); e != nil {
			t.Fatal(i, e)
		}
	}
	if f.m.record.Sequence != 0 || len(f.m.record.Jobs) != MaxJobs {
		t.Fatal("wrong capacity", f.m.record.Sequence, len(f.m.record.Jobs))
	}
	f.id = fmt.Sprintf("update_%032x", MaxJobs+1)
	if e := f.m.Request(ctx, f.consent.Binding.DeviceID, f.actor, f.id, f.source.value.Selection); !errors.Is(e, ErrConflict) {
		t.Fatal("capacity reset", e)
	}
	h, e := f.m.History(ctx, f.consent.Binding.DeviceID)
	if e != nil || h.RemainingCapacity != 0 || h.Reason != "capacity_exhausted" {
		t.Fatal(h, e)
	}
}
func TestScheduleClockRollbackAndImmutableTransition(t *testing.T) {
	f := scheduleFixture(t)
	a := approveSchedule(t, f)
	beforeRaw, _ := EncodeRecord(f.m.record)
	before, _ := DecodeRecord(beforeRaw)
	f.at = time.Unix(a.EndAt, 0)
	if _, e := f.m.Pending(context.Background()); e != nil {
		t.Fatal(e)
	}
	f.at = time.Unix(a.StartAt, 0)
	if _, e := f.m.Pending(context.Background()); !errors.Is(e, ErrExpired) {
		t.Fatal("rollback revived schedule", e)
	}
	after, _ := DecodeRecord(beforeRaw)
	after.Jobs[0].Schedule.Approval.EndAt++
	after.Jobs[0].Schedule.Approval.Digest = scheduleDigest(after.Jobs[0].Schedule.Approval)
	if e := CheckScheduleTransition(before, after); e == nil {
		t.Fatal("immutable window changed")
	}
	after, _ = DecodeRecord(beforeRaw)
	after.Jobs = nil
	if e := CheckScheduleTransition(before, after); e == nil {
		t.Fatal("reservation deleted")
	}
}
func TestSchedulePermitRejectedByManualOnlyExecutorAndManualBytesUnchanged(t *testing.T) {
	f := scheduleFixture(t)
	a := approveSchedule(t, f)
	f.at = time.Unix(a.StartAt, 0)
	if _, e := f.m.Pending(context.Background()); e != nil {
		t.Fatal(e)
	}
	scheduleReport(t, f, nil)
	raw := f.m.record.Jobs[0].Envelope
	f.consent.Version = ConsentVersion
	f.consent.ScheduleScope = ""
	f.consent.ScheduleAcknowledged = false
	n := &nativeFixture{readiness: f.source.value}
	x, _ := executorFixture(t, f, n)
	if _, e := x.Accept(context.Background(), raw); !errors.Is(e, ErrAuthority) || n.opens != 0 {
		t.Fatal("manual executor promoted", e)
	}
	manual := fixture(t)
	wire := manual.approve(t)
	if bytes.Contains(wire, []byte("schedule")) || bytes.Contains(wire, []byte("permitIssuedAt")) {
		t.Fatal("manual wire expanded")
	}
	consent, _ := json.Marshal(manual.consent)
	if bytes.Contains(consent, []byte("schedule")) {
		t.Fatal("manual consent expanded")
	}
	record := manual.store.files["jobs.json"]
	if bytes.Contains(record, []byte("schedule")) {
		t.Fatal("manual record expanded")
	}
}
