package windowsupdatesetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	job "localrmm/internal/windowsupdatejob"
	"testing"
	"time"
)

func downloadBackgroundFixture(t *testing.T) (*setupFixture, CoordinatedMaterial) {
	t.Helper()
	f, m := reusableBackgroundFixture(t, false)
	p, e := NewDownloadBackgroundPlan(f.p.Offer, f.p.Artifact, f.p.Identity, f.p.Observer)
	if e != nil {
		t.Fatal(e)
	}
	f.p, e = NewCoordinatedPlan(p, m.Roster.Plan.PlanDigest)
	if e != nil {
		t.Fatal(e)
	}
	b := job.Binding{ManagerID: f.p.Offer.ManagerID, DeviceID: f.p.Offer.DeviceID, IncarnationDigest: f.p.Offer.IncarnationDigest, ExecutorID: m.ExecutorID, ExecutorKeyID: m.Roster.WUA.ExecutorKeyDigest, GrantID: m.GrantID, KeyID: m.Roster.WUA.ManagerKeyDigest}
	c := job.Consent{Version: job.DownloadConsentVersion, ReusableAcknowledged: true, BackgroundAcknowledged: true, DownloadScope: job.DownloadScope, DownloadAcknowledged: true, Scope: job.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: f.p.Offer.ExpiresAt, MutationPlanDigest: f.p.MutationPlanDigest, PeerBindingDigest: m.Roster.MSI.BindingDigest}
	m.Roster.WUA = job.MutationParticipant(c)
	return f, m
}
func TestDownloadBackgroundRequiresSeparateFreshAcknowledgement(t *testing.T) {
	f, m := downloadBackgroundFixture(t)
	applyDownload := func(ack bool) (job.SetupRegistration, error) {
		return apply(context.Background(), f.p, f.payload, Approval{Digest: f.p.Digest(), Install: true, Relay: true, ProcessQuery: true, Background: true, Reusable: true, Download: ack}, f.h, func() (ed25519.PrivateKey, string, string, error) {
			return bytes.Clone(m.Key), m.ExecutorID, m.GrantID, nil
		}, func() time.Time { return f.now }, m)
	}
	if _, e := applyDownload(false); e == nil || f.created != 0 {
		t.Fatal("missing download approval changed state")
	}
	r, e := applyDownload(true)
	if e != nil {
		t.Fatal(e)
	}
	c := f.config(t)
	if !r.Consent.DownloadEnabled() || !r.Consent.DownloadAcknowledged || r.Consent.ExpiresAt != f.p.Offer.ExpiresAt || VerifyInstalled(f.s, c) != nil || len(f.s.files["activation.json"]) != 0 {
		t.Fatal("wrong fresh scope/automatic activation")
	}
	oldF, oldM := reusableBackgroundFixture(t, false)
	oldR, e := applyReusableBackground(oldF, oldM, true, false)
	if e != nil {
		t.Fatal(e)
	}
	if job.ValidMutationRoster(c.Mutation, oldR.Consent) {
		t.Fatal("new roster promoted old consent")
	}
	for _, change := range []func(*Plan){func(p *Plan) { p.Version = ReusableBackgroundVersion }, func(p *Plan) { p.DownloadDisclosure = "" }, func(p *Plan) { p.ProcessQueryDisclosure = ReusableBackgroundDisclosure }, func(p *Plan) {
		p.ScheduleScope = job.ScheduleScope
		p.ScheduleDisclosure = ReusableBackgroundScheduleDisclosure
	}} {
		p := f.p
		change(&p)
		if p.Validate() == nil {
			t.Fatal("mixed profile admitted")
		}
	}
}
