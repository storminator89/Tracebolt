package windowsupdatesetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	job "localrmm/internal/windowsupdatejob"
)

func TestDownloadCoexistenceSetupPinsFreshConsentAndDisabledService(t *testing.T) {
	for _, scheduled := range []bool{false, true} {
		f, m := reusableBackgroundFixture(t, scheduled)
		p, err := NewDownloadCoexistenceBackgroundPlan(f.p.Offer, f.p.Artifact, f.p.Identity, f.p.Observer, scheduled)
		if err != nil {
			t.Fatal(err)
		}
		f.p, err = NewCoordinatedPlan(p, m.Roster.Plan.PlanDigest)
		if err != nil {
			t.Fatal(err)
		}
		b := job.Binding{ManagerID: f.p.Offer.ManagerID, DeviceID: f.p.Offer.DeviceID, IncarnationDigest: f.p.Offer.IncarnationDigest, ExecutorID: m.ExecutorID, ExecutorKeyID: m.Roster.WUA.ExecutorKeyDigest, GrantID: m.GrantID, KeyID: m.Roster.WUA.ManagerKeyDigest}
		c := job.Consent{Version: job.DownloadCoexistenceConsentVersion, ReusableAcknowledged: true, BackgroundAcknowledged: true, DownloadScope: job.DownloadScope, DownloadAcknowledged: true, Scope: job.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: f.p.Offer.ExpiresAt, MutationPlanDigest: f.p.MutationPlanDigest, PeerBindingDigest: m.Roster.MSI.BindingDigest}
		if scheduled {
			c.ScheduleScope = job.ScheduleScope
			c.ScheduleAcknowledged = true
		}
		m.Roster.WUA = job.MutationParticipant(c)
		approval := Approval{Digest: f.p.Digest(), Install: true, Relay: true, ProcessQuery: true, Background: true, Reusable: true, Download: true, Schedule: scheduled}
		run := func(a Approval) (job.SetupRegistration, error) {
			return apply(context.Background(), f.p, f.payload, a, f.h, func() (ed25519.PrivateKey, string, string, error) {
				return bytes.Clone(m.Key), m.ExecutorID, m.GrantID, nil
			}, func() time.Time { return f.now }, m)
		}
		for _, change := range []func(*Approval){func(a *Approval) { a.Download = false }, func(a *Approval) { a.Schedule = !scheduled }, func(a *Approval) { a.Reusable = false }, func(a *Approval) { a.Background = false }} {
			bad := approval
			change(&bad)
			if _, err := run(bad); err == nil || f.created != 0 || f.generated != 0 {
				t.Fatal("incomplete combined approval changed setup")
			}
		}
		registration, err := run(approval)
		if err != nil {
			t.Fatal(err)
		}
		config := f.config(t)
		if registration.Consent != c || VerifyInstalled(f.s, config) != nil || len(f.s.files["activation.json"]) != 0 {
			t.Fatal("fresh consent mismatch or automatic activation")
		}
		activation, err := job.SignBackgroundActivation(registration, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32)))
		if err != nil || activation.Verify(registration) != nil {
			t.Fatal("exact fresh activation rejected", err)
		}
		old := registration
		old.Consent.Version = job.DownloadConsentVersion
		if activation.Verify(old) == nil || job.ValidMutationRoster(config.Mutation, old.Consent) {
			t.Fatal("old download consent promoted")
		}
		// Installed verification must bind this exact new version, even when WUA
		// scheduling is absent because the separately disclosed scheduler is MSI.
		p = f.p
		p.Version = DownloadBackgroundVersion
		p.ProcessQueryDisclosure = DownloadBackgroundDisclosure
		f.s.files["provision.json"], _ = json.Marshal(p)
		if VerifyInstalled(f.s, config) == nil {
			t.Fatal("old provision profile substituted")
		}
	}
}
