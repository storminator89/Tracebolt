package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentstate"
	job "localrmm/internal/windowsupdatejob"
)

type scheduledStoreFixture struct {
	f         *windowsUpdateStoreFixture
	m         *job.Manager
	id, actor string
	selection job.Selection
	approval  job.ScheduleApproval
}

func newScheduledStoreFixture(t *testing.T) *scheduledStoreFixture {
	t.Helper()
	f := newWindowsUpdateStoreFixture(t, false)
	f.consent.Version = job.ScheduledConsentVersion
	f.consent.ScheduleScope = job.ScheduleScope
	f.consent.ScheduleAcknowledged = true
	if e := f.setup(); e != nil {
		t.Fatal(e)
	}
	s := &scheduledStoreFixture{f: &f, id: id("update", 12), actor: id("operator", 12), selection: job.Selection{UpdateID: "12345678-1234-1234-1234-123456789abc", Revision: 2}}
	s.m = s.open(t, true)
	if e := s.m.Request(context.Background(), f.consent.Binding.DeviceID, s.actor, s.id, s.selection); e != nil {
		t.Fatal("request", e)
	}
	if e := s.m.Report(context.Background(), s.readiness(t)); e != nil {
		t.Fatal("baseline", e)
	}
	v, e := s.m.View(context.Background(), f.consent.Binding.DeviceID, s.actor)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.m.Schedule(context.Background(), f.consent.Binding.DeviceID, s.actor, s.id, v.Job.Preview.Digest, f.at.Unix()+120, f.at.Unix()+300, true); e != nil {
		t.Fatal("schedule", e)
	}
	_, r, _ := f.record(t)
	s.approval = r.Jobs[0].Schedule.Approval
	return s
}
func (s *scheduledStoreFixture) open(t *testing.T, allowed bool) *job.Manager {
	t.Helper()
	m, e := job.OpenTransactional(context.Background(), s.f.store, s.f.consent.Binding, s.f.key, func() time.Time { return s.f.at })
	if e != nil {
		t.Fatal(e)
	}
	if e = m.ConfigureOperatorPolicy(func(string) bool { return true }); e != nil {
		t.Fatal(e)
	}
	if e = m.ConfigureSchedulePolicy(context.Background(), func(string) bool { return allowed }); e != nil {
		t.Fatal(e)
	}
	return m
}
func (s *scheduledStoreFixture) readiness(t *testing.T) []byte {
	t.Helper()
	raw, e := s.m.ClaimReadiness(context.Background(), s.id)
	if e != nil {
		t.Fatal("readiness claim", e)
	}
	c, e := job.VerifyChallenge(raw, s.f.key.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	r := job.Readiness{Selection: s.selection, CapturedAt: s.f.at.Unix(), Software: job.Yes, Installed: job.No, Hidden: job.No, Downloaded: job.Yes, EULAAccepted: job.Yes, CanRequestUserInput: job.No, CanRequireSource: job.No, RequiresNetwork: job.No, BundledCount: 0, InstallerBusy: job.No, RebootRequiredBefore: job.No, RebootBehavior: "never", OfflineVerified: job.Yes}
	proof, e := job.SignStatement(job.Statement{Version: job.RelayVersion, Kind: "readiness", Binding: s.f.consent.Binding, JobID: s.id, ReferenceDigest: actionpermit.Digest(raw), Deadline: c.Deadline, IssuedAt: r.CapturedAt, ExpiresAt: min(r.CapturedAt+60, c.Deadline), Readiness: &r}, s.f.executor)
	if e != nil {
		t.Fatal(e)
	}
	return proof
}
func (s *scheduledStoreFixture) due(t *testing.T) []byte {
	t.Helper()
	s.f.at = time.Unix(s.approval.StartAt, 0).UTC()
	p, e := s.m.Pending(context.Background())
	if e != nil || p == nil || p.Kind != "readiness" {
		t.Fatal("due", p, e)
	}
	return s.readiness(t)
}
func TestWindowsUpdateScheduleEnrollmentRoundTrip(t *testing.T) {
	s := newScheduledStoreFixture(t)
	s.m = s.open(t, true)
	proof := s.due(t)
	if e := s.m.Report(context.Background(), proof); e != nil {
		t.Fatal("issue", e)
	}
	before, r, _ := s.f.record(t)
	if r.Sequence != 1 || len(r.Jobs) != 1 || r.Jobs[0].Schedule.Approval != s.approval {
		t.Fatal("reservation or original authority changed")
	}
	if e := s.m.Report(context.Background(), proof); e != nil {
		t.Fatal("exact report replay", e)
	}
	after, _, _ := s.f.record(t)
	if !bytes.Equal(before, after) {
		t.Fatal("replayed report changed bytes")
	}
	raw, e := s.m.Claim(context.Background(), s.id)
	if e != nil || len(raw) == 0 {
		t.Fatal("claim", e)
	}
	s.m = s.open(t, true)
	if again, e := s.m.Claim(context.Background(), s.id); !errors.Is(e, job.ErrConsumed) || len(again) != 0 {
		t.Fatal("restart claim", e)
	}
}
func TestWindowsUpdateScheduleFinalIssuanceExpiryKeepsOnlyRejectionFloor(t *testing.T) {
	s := newScheduledStoreFixture(t)
	proof := s.due(t)
	before, original, _ := s.f.record(t)
	end := s.f.at.Add(60 * time.Second)
	ctx := WithOverviewClock(context.Background(), func() time.Time { return s.f.at })
	ctx = job.WithFinalCheck(ctx, func() error { s.f.at = end; return nil })
	if e := s.m.Report(ctx, proof); !errors.Is(e, job.ErrExpired) {
		t.Fatal("final-expired permit issued", e)
	}
	after, r, floor := s.f.record(t)
	if !bytes.Equal(before, after) || r.Sequence != 0 || len(r.Jobs[0].Envelope) != 0 || floor != end.Unix() || r.Jobs[0].Schedule.Approval != original.Jobs[0].Schedule.Approval {
		t.Fatal("rejected issuance mutated schedule")
	}
	s.f.at = end.Add(-time.Second)
	if e := s.m.Report(context.Background(), proof); !errors.Is(e, job.ErrExpired) {
		t.Fatal("clock rollback revived report", e)
	}
}
func TestWindowsUpdateScheduleCancelVersusClaimSerializes(t *testing.T) {
	s := newScheduledStoreFixture(t)
	if e := s.m.Report(context.Background(), s.due(t)); e != nil {
		t.Fatal(e)
	}
	other := s.open(t, true)
	start := make(chan struct{})
	cancelled := make(chan error, 1)
	type claimed struct {
		raw []byte
		err error
	}
	claims := make(chan claimed, 1)
	go func() {
		<-start
		cancelled <- s.m.CancelSchedule(context.Background(), s.f.consent.Binding.DeviceID, s.actor, s.id, s.approval.Digest)
	}()
	go func() { <-start; b, e := other.Claim(context.Background(), s.id); claims <- claimed{b, e} }()
	close(start)
	c, p := <-cancelled, <-claims
	if c == nil {
		if p.err == nil || len(p.raw) != 0 {
			t.Fatal("cancel and claim both won")
		}
	} else if !errors.Is(c, job.ErrConsumed) || p.err != nil || len(p.raw) == 0 {
		t.Fatal("neither terminal outcome", c, p.err)
	}
	_, r, _ := s.f.record(t)
	if r.Sequence != 1 || len(r.Jobs) != 1 || r.Jobs[0].Schedule.Approval != s.approval {
		t.Fatal("race lost immutable history")
	}
}
func TestWindowsUpdateScheduleStartupRemovalAndExplicitRevokePersist(t *testing.T) {
	for _, kind := range []string{"operator", "grant"} {
		t.Run(kind, func(t *testing.T) {
			s := newScheduledStoreFixture(t)
			if kind == "operator" {
				s.m = s.open(t, false)
			} else {
				if e := s.m.RevokeScheduling(context.Background(), s.f.consent.Binding.DeviceID, s.actor, true); e != nil {
					t.Fatal(e)
				}
			}
			s.m = s.open(t, true)
			s.f.at = time.Unix(s.approval.StartAt, 0)
			if p, e := s.m.Pending(context.Background()); e != nil || p != nil {
				t.Fatal("authority resurrected", p, e)
			}
			_, r, _ := s.f.record(t)
			if r.Jobs[0].State != "schedule_blocked" || len(r.Jobs[0].Envelope) > 0 || r.Sequence != 0 {
				t.Fatal("revocation lost")
			}
		})
	}
}
func TestWindowsUpdateScheduleTransactionRejectsReservationDeletionAndWindowExtension(t *testing.T) {
	s := newScheduledStoreFixture(t)
	before, _, _ := s.f.record(t)
	if _, _, e := s.f.transaction(context.Background(), s.f.at, func(r *job.Record, _ job.Current, _ time.Time) error { r.Jobs = nil; return nil }); !errors.Is(e, job.ErrConflict) {
		t.Fatal("deleted scheduled authority", e)
	}
	if _, _, e := s.f.transaction(context.Background(), s.f.at, func(r *job.Record, _ job.Current, _ time.Time) error { r.Jobs[0].Schedule.Approval.EndAt++; return nil }); !errors.Is(e, job.ErrConflict) {
		t.Fatal("renewed window", e)
	}
	after, _, _ := s.f.record(t)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected mutation changed record")
	}
}

func TestWindowsUpdateScheduleStartupIsolatesExpiredAndRevokedRegistryMembers(t *testing.T) {
	for _, kind := range []string{"expired", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			s := newScheduledStoreFixture(t)
			_, before, _ := s.f.record(t)
			if kind == "revoked" {
				control := s.f.fixture.control(s.f.snapshot, 211)
				control.Now = s.f.at.Unix() + 1
				if _, e := s.f.store.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); e != nil {
					t.Fatal(e)
				}
				s.f.at = s.f.at.Add(2 * time.Second)
			} else {
				s.f.at = time.Unix(s.f.snapshot.Intent.NotAfter+1, 0).UTC()
			}
			m, e := job.OpenRegisteredTransactional(context.Background(), s.f.store, s.f.consent.Binding, s.f.key, func() time.Time { return s.f.at }, func() error { return nil })
			if e != nil {
				t.Fatal("registered unavailable member", e)
			}
			registry, e := job.NewRegistry([]*job.Manager{m})
			if e != nil {
				t.Fatal(e)
			}
			if e = registry.ConfigureOperatorPolicy(func(string) bool { return true }); e != nil {
				t.Fatal(e)
			}
			if e = registry.ConfigureSchedulePolicy(context.Background(), func(string) bool { return false }); e != nil {
				t.Fatal("unavailable member blocked fleet startup", e)
			}
			_, after, rejected := s.f.record(t)
			if after.ClockFloor != before.ClockFloor || after.SchedulePolicyFloor != s.f.at.Unix() || rejected != s.f.at.Unix() || after.Jobs[0].State != "schedule_blocked" || after.Jobs[0].Schedule.Approval != s.approval || after.Jobs[0].Schedule.OutcomeAt != s.f.at.Unix() {
				t.Fatal("terminalization changed successful authority or lost revoke")
			}
			if _, e = m.Pending(context.Background()); e == nil {
				t.Fatal("startup terminalization granted dispatch")
			}
			if e = s.f.store.OpenWindowsUpdateJobs(context.Background(), s.f.key.Public().(ed25519.PublicKey)); e != nil {
				t.Fatal("terminalization corrupted reciprocal history", e)
			}
		})
	}
}
