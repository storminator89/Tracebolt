package windowsupdatesetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/lanclient"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
	"testing"
	"time"
)

func backgroundFixture(t *testing.T) (*setupFixture, CoordinatedMaterial) {
	f, m := coordinatedSetupFixture(t)
	p, e := NewBackgroundPlan(f.p.Offer, f.p.Artifact, f.p.Identity, f.p.Observer)
	if e != nil {
		t.Fatal(e)
	}
	f.p, e = NewCoordinatedPlan(p, m.Roster.Plan.PlanDigest)
	if e != nil {
		t.Fatal(e)
	}
	m.Roster.Version = fence.BackgroundRosterVersion
	m.Roster.Plan.Version = fence.BackgroundPlanVersion
	b := job.Binding{ManagerID: f.p.Offer.ManagerID, DeviceID: f.p.Offer.DeviceID, IncarnationDigest: f.p.Offer.IncarnationDigest, ExecutorID: m.ExecutorID, ExecutorKeyID: m.Roster.WUA.ExecutorKeyDigest, GrantID: m.GrantID, KeyID: m.Roster.WUA.ManagerKeyDigest}
	c := job.Consent{Version: job.BackgroundConsentVersion, BackgroundAcknowledged: true, Scope: job.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: f.p.Offer.ExpiresAt, MutationPlanDigest: f.p.MutationPlanDigest, PeerBindingDigest: m.Roster.MSI.BindingDigest}
	m.Roster.WUA = job.MutationParticipant(c)
	f.image.Version = windowspackage.UpdateServiceImageVersion
	f.image.Path = f.p.Executable
	f.h.CreateService = func(_ context.Context, c windowsupdateipc.Config) error {
		if len(f.s.files["provision.json"]) == 0 || len(f.s.files["executor.json"]) == 0 || len(f.s.files["receipt.json"]) != 0 || c.Version != windowsupdateipc.ServiceConfigVersion {
			t.Fatal("service before durable intent/state or wrong entry")
		}
		return nil
	}
	f.h.VerifyService = func(context.Context, windowsupdateipc.Config) error { return nil }
	return f, m
}
func applyBackground(f *setupFixture, m CoordinatedMaterial, ack bool) (job.SetupRegistration, error) {
	return apply(context.Background(), f.p, f.payload, Approval{Digest: f.p.Digest(), Install: true, Relay: true, ProcessQuery: true, Background: ack}, f.h, func() (ed25519.PrivateKey, string, string, error) {
		return bytes.Clone(m.Key), m.ExecutorID, m.GrantID, nil
	}, func() time.Time { return f.now }, m)
}
func TestBackgroundSetupStagesDisabledWithFreshRegistration(t *testing.T) {
	f, m := backgroundFixture(t)
	r, e := applyBackground(f, m, true)
	if e != nil {
		t.Fatal(e)
	}
	c := f.config(t)
	if r.Version != job.BackgroundRegistrationVersion || !r.Consent.BackgroundAcknowledged || r.Consent.ScheduleAcknowledged || c.Version != windowsupdateipc.ServiceConfigVersion || c.Mutation.Version != fence.BackgroundRosterVersion || f.relay.Version != lanclient.WindowsBackgroundUpdateRelayGrantVersion || f.relay.ExecutorPeer.Version != windowsupdateipc.ServicePeerVersion || VerifyInstalled(f.s, c) != nil {
		t.Fatal("fresh profile not complete")
	}
	if _, ok := f.s.files["activation.json"]; ok {
		t.Fatal("setup activated service")
	}
	var k keyMaterial
	if json.Unmarshal(f.s.files["executor-key.json"], &k) != nil || k.Version != BackgroundKeyVersion {
		t.Fatal("key domain")
	}
	clear(k.Key)
	if _, _, _, e = InspectRemoval(f.s); e == nil {
		t.Fatal("legacy removal adopted background")
	}
	for _, v := range []string{job.ConsentVersion, job.ScheduledConsentVersion, job.CoordinatedConsentVersion} {
		bad := r.Consent
		bad.Version = v
		if bad.Validate() == nil {
			t.Fatal("old consent adopted background")
		}
	}
	bad := r.Consent
	bad.ScheduleScope = job.ScheduleScope
	bad.ScheduleAcknowledged = true
	if bad.Validate() == nil {
		t.Fatal("manual background grants scheduling")
	}
}
func TestBackgroundSetupMissingAckAndUncertainSCMStayFenced(t *testing.T) {
	f, m := backgroundFixture(t)
	if _, e := applyBackground(f, m, false); e == nil || f.created != 0 {
		t.Fatal("unapproved service created")
	}
	f, m = backgroundFixture(t)
	f.h.CreateService = func(context.Context, windowsupdateipc.Config) error { return errors.New("uncertain SCM") }
	if _, e := applyBackground(f, m, true); e == nil || len(f.s.files["provision.json"]) == 0 || len(f.s.files["receipt.json"]) != 0 {
		t.Fatal("uncertain SCM claimed complete")
	}
	if _, e := Registration(f.s); e == nil {
		t.Fatal("partial registration exported")
	}
}

func TestBackgroundManagerActivationBindsExactRegistration(t *testing.T) {
	f, m := backgroundFixture(t)
	r, e := applyBackground(f, m, true)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32))
	a, e := job.SignBackgroundActivation(r, key)
	if e != nil || a.Verify(r) != nil {
		t.Fatal(e)
	}
	r.Consent.ExpiresAt++
	if a.Verify(r) == nil {
		t.Fatal("activation extended grant")
	}
	old := newSetupFixture(t)
	legacy, e := old.apply()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = job.SignBackgroundActivation(legacy, key); e == nil {
		t.Fatal("manager promoted old foreground registration")
	}
}
