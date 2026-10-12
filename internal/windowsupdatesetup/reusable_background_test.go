package windowsupdatesetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
	"testing"
	"time"
)

func reusableBackgroundFixture(t *testing.T, scheduled bool) (*setupFixture, CoordinatedMaterial) {
	t.Helper()
	f, m := backgroundFixture(t)
	p, e := NewReusableBackgroundPlan(f.p.Offer, f.p.Artifact, f.p.Identity, f.p.Observer, scheduled)
	if e != nil {
		t.Fatal(e)
	}
	f.p, e = NewCoordinatedPlan(p, m.Roster.Plan.PlanDigest)
	if e != nil {
		t.Fatal(e)
	}
	m.Roster.Version = fence.ReusableWUARosterVersion
	m.Roster.Plan.Version = fence.ReusableWUAPlanVersion
	b := job.Binding{ManagerID: f.p.Offer.ManagerID, DeviceID: f.p.Offer.DeviceID, IncarnationDigest: f.p.Offer.IncarnationDigest, ExecutorID: m.ExecutorID, ExecutorKeyID: m.Roster.WUA.ExecutorKeyDigest, GrantID: m.GrantID, KeyID: m.Roster.WUA.ManagerKeyDigest}
	c := job.Consent{Version: job.ReusableConsentVersion, ReusableAcknowledged: true, BackgroundAcknowledged: true, Scope: job.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: f.p.Offer.ExpiresAt, MutationPlanDigest: f.p.MutationPlanDigest, PeerBindingDigest: m.Roster.MSI.BindingDigest}
	if scheduled {
		c.ScheduleScope = job.ScheduleScope
		c.ScheduleAcknowledged = true
	}
	m.Roster.WUA = job.MutationParticipant(c)
	return f, m
}
func applyReusableBackground(f *setupFixture, m CoordinatedMaterial, reusable, schedule bool) (job.SetupRegistration, error) {
	return apply(context.Background(), f.p, f.payload, Approval{Digest: f.p.Digest(), Install: true, Relay: true, ProcessQuery: true, Background: true, Reusable: reusable, Schedule: schedule}, f.h, func() (ed25519.PrivateKey, string, string, error) {
		return bytes.Clone(m.Key), m.ExecutorID, m.GrantID, nil
	}, func() time.Time { return f.now }, m)
}
func TestReusableBackgroundSetupRequiresExactFreshScopeAndApproval(t *testing.T) {
	for _, scheduled := range []bool{false, true} {
		f, m := reusableBackgroundFixture(t, scheduled)
		if _, e := applyReusableBackground(f, m, false, scheduled); e == nil || f.created != 0 {
			t.Fatal("missing reusable approval mutated setup")
		}
		if _, e := applyReusableBackground(f, m, true, !scheduled); e == nil || f.created != 0 {
			t.Fatal("schedule scope/approval mismatch mutated setup")
		}
		oldRoster := m
		oldRoster.Roster.Version = fence.BackgroundRosterVersion
		oldRoster.Roster.Plan.Version = fence.BackgroundPlanVersion
		if _, e := applyReusableBackground(f, oldRoster, true, scheduled); e == nil || f.created != 0 || f.generated != 0 {
			t.Fatal("mixed old roster mutated fresh setup")
		}
		r, e := applyReusableBackground(f, m, true, scheduled)
		if e != nil {
			t.Fatal(e)
		}
		c := f.config(t)
		if !r.Consent.Reusable() || r.Consent.ScheduleAcknowledged != scheduled || r.Consent.ExpiresAt != f.p.Offer.ExpiresAt || c.Mutation.Version != fence.ReusableWUARosterVersion || c.Version != windowsupdateipc.ServiceConfigVersion || VerifyInstalled(f.s, c) != nil || len(f.s.files["activation.json"]) != 0 {
			t.Fatal("wrong fresh scope or automatic activation")
		}
		old := *c.Mutation
		old.Version = fence.BackgroundRosterVersion
		old.Plan.Version = fence.BackgroundPlanVersion
		if job.ValidMutationRoster(&old, r.Consent) {
			t.Fatal("old roster promoted")
		}
		cc := c
		cc.Mutation = &old
		if cc.Validate() == nil {
			t.Fatal("config accepted old roster")
		}
		for _, version := range []string{job.ConsentVersion, job.ScheduledConsentVersion, job.CoordinatedConsentVersion, job.BackgroundConsentVersion, job.ScheduledBackgroundConsentVersion} {
			bad := r
			bad.Consent.Version = version
			if bad.Validate() == nil {
				t.Fatal("old consent adopted reusable acknowledgement", version)
			}
		}
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32))
		activation, e := job.SignBackgroundActivation(r, key)
		if e != nil || activation.Verify(r) != nil {
			t.Fatal("fresh manager activation rejected", e)
		}
		oldF, oldM := backgroundFixture(t)
		oldR, e := applyBackground(oldF, oldM, true)
		if e != nil || activation.Verify(oldR) == nil {
			t.Fatal("activation promoted old consent", e)
		}
		saved := f.p
		saved.Version = BackgroundVersion
		saved.ProcessQueryDisclosure = BackgroundDisclosure
		saved.ScheduleScope = ""
		saved.ScheduleDisclosure = ""
		f.s.files["provision.json"], _ = json.Marshal(saved)
		if VerifyInstalled(f.s, c) == nil {
			t.Fatal("old plan authorized new used state")
		}
	}
}
func TestReusableBackgroundPlanRejectsLegacyDisclosureAndUnselectedSchedule(t *testing.T) {
	f, _ := reusableBackgroundFixture(t, false)
	for _, change := range []func(*Plan){
		func(p *Plan) { p.Version = BackgroundVersion },
		func(p *Plan) { p.ProcessQueryDisclosure = BackgroundDisclosure },
		func(p *Plan) { p.ScheduleDisclosure = job.BackgroundScheduleDisclosure },
		func(p *Plan) { p.ScheduleScope = job.ScheduleScope },
		func(p *Plan) { p.ScheduleScope = job.ScheduleScope; p.ScheduleDisclosure = ScheduleDisclosure },
	} {
		p := f.p
		change(&p)
		if p.Validate() == nil {
			t.Fatal("partial or old plan adopted authority")
		}
	}
}
