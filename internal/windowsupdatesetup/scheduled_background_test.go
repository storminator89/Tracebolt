package windowsupdatesetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
	"testing"
	"time"
)

func scheduledBackgroundFixture(t *testing.T) (*setupFixture, CoordinatedMaterial) {
	t.Helper()
	f, m := backgroundFixture(t)
	p, e := NewScheduledBackgroundPlan(f.p.Offer, f.p.Artifact, f.p.Identity, f.p.Observer)
	if e != nil {
		t.Fatal(e)
	}
	f.p, e = NewCoordinatedPlan(p, m.Roster.Plan.PlanDigest)
	if e != nil {
		t.Fatal(e)
	}
	b := job.Binding{ManagerID: f.p.Offer.ManagerID, DeviceID: f.p.Offer.DeviceID, IncarnationDigest: f.p.Offer.IncarnationDigest, ExecutorID: m.ExecutorID, ExecutorKeyID: m.Roster.WUA.ExecutorKeyDigest, GrantID: m.GrantID, KeyID: m.Roster.WUA.ManagerKeyDigest}
	c := job.Consent{Version: job.ScheduledBackgroundConsentVersion, BackgroundAcknowledged: true, Scope: job.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: f.p.Offer.ExpiresAt, MutationPlanDigest: f.p.MutationPlanDigest, PeerBindingDigest: m.Roster.MSI.BindingDigest, ScheduleScope: job.ScheduleScope, ScheduleAcknowledged: true}
	m.Roster.WUA = job.MutationParticipant(c)
	return f, m
}
func applyScheduledBackground(f *setupFixture, m CoordinatedMaterial, schedule bool) (job.SetupRegistration, error) {
	return apply(context.Background(), f.p, f.payload, Approval{Digest: f.p.Digest(), Install: true, Relay: true, ProcessQuery: true, Background: true, Schedule: schedule}, f.h, func() (ed25519.PrivateKey, string, string, error) {
		return bytes.Clone(m.Key), m.ExecutorID, m.GrantID, nil
	}, func() time.Time { return f.now }, m)
}
func TestScheduledBackgroundFreshSetupBindsConsentAndRetainsWrappers(t *testing.T) {
	f, m := scheduledBackgroundFixture(t)
	if _, e := applyScheduledBackground(f, m, false); e == nil || f.created != 0 {
		t.Fatal("missing independent schedule acknowledgement mutated setup")
	}
	r, e := applyScheduledBackground(f, m, true)
	if e != nil {
		t.Fatal(e)
	}
	c := f.config(t)
	if r.Version != job.BackgroundRegistrationVersion || r.Consent.Version != job.ScheduledBackgroundConsentVersion || !r.Consent.Background() || !r.Consent.ScheduleAcknowledged || c.Version != windowsupdateipc.ServiceConfigVersion || f.relay.Version != lanclient.WindowsBackgroundUpdateRelayGrantVersion || VerifyInstalled(f.s, c) != nil {
		t.Fatal("combined authority not exactly bound")
	}
	if r.Consent.ExpiresAt != f.p.Offer.ExpiresAt || len(f.s.files["activation.json"]) != 0 {
		t.Fatal("setup extended lifetime or started service")
	}
	for _, v := range []string{job.ConsentVersion, job.ScheduledConsentVersion, job.CoordinatedConsentVersion, job.BackgroundConsentVersion} {
		bad := r
		bad.Consent.Version = v
		if bad.Validate() == nil {
			t.Fatalf("old consent %s adopted scheduling/background", v)
		}
	}
	bad := r
	bad.Version = job.SetupRegistrationVersion
	if bad.Validate() == nil {
		t.Fatal("legacy wrapper adopted background")
	}
	old, oldMaterial := backgroundFixture(t)
	manual, e := applyBackground(old, oldMaterial, true)
	if e != nil {
		t.Fatal(e)
	}
	if manual.Consent.ScheduleAcknowledged || manual.Consent.Version != job.BackgroundConsentVersion {
		t.Fatal("old profile promoted")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32))
	activation, e := job.SignBackgroundActivation(r, key)
	if e != nil || activation.Verify(r) != nil || activation.Verify(manual) == nil {
		t.Fatal("activation did not bind full new consent", e)
	}
	oldActivation, e := job.SignBackgroundActivation(manual, key)
	if e != nil || oldActivation.Verify(r) == nil {
		t.Fatal("manual activation authorized combined profile")
	}
	stale := *c.Mutation
	stale.WUA = job.MutationParticipant(manual.Consent)
	if job.ValidMutationRoster(&stale, r.Consent) {
		t.Fatal("old participant digest promoted")
	}
	saved := f.p
	saved.Version = BackgroundVersion
	saved.ScheduleScope = ""
	saved.ScheduleDisclosure = ""
	saved.ProcessQueryDisclosure = BackgroundDisclosure
	f.s.files["provision.json"], _ = json.Marshal(saved)
	if VerifyInstalled(f.s, c) == nil {
		t.Fatal("old plan adopted combined ledger")
	}
}
func TestScheduledBackgroundPlanCannotBeSmuggledIntoOlderProfiles(t *testing.T) {
	f, _ := scheduledBackgroundFixture(t)
	for _, v := range []string{Version, CoordinatedVersion, BackgroundVersion} {
		p := f.p
		p.Version = v
		if p.Validate() == nil {
			t.Fatalf("combined disclosure accepted as %s", v)
		}
	}
	legacy := newSetupFixture(t)
	p, e := NewScheduledPlan(legacy.p.Offer, legacy.p.Artifact, legacy.p.Identity, legacy.p.Observer)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = NewCoordinatedPlan(p, f.p.MutationPlanDigest); e == nil {
		t.Fatal("standalone scheduled grant adopted")
	}
}
