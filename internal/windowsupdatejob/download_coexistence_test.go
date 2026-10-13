package windowsupdatejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

func coexistenceManager(t *testing.T, scheduled bool) *workflowFixture {
	t.Helper()
	f := downloadManager(t)
	f.consent.Version = DownloadCoexistenceConsentVersion
	if scheduled {
		f.consent.ScheduleScope = ScheduleScope
		f.consent.ScheduleAcknowledged = true
	}
	r, err := NewRecordWithExecutor(f.consent, f.key.Public().(ed25519.PublicKey), executorKey().Public().(ed25519.PublicKey), f.at.Unix())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := EncodeRecord(r)
	consent, _ := json.Marshal(f.consent)
	f.store.files = map[string][]byte{"jobs.json": raw, "started.json": consent, "receipt.json": consent}
	f.m, err = Open(f.store, f.guard, f.source, f.key, func() time.Time { return f.at })
	if err != nil {
		t.Fatal(err)
	}
	if err = f.m.ConfigureOperatorPolicy(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if err = f.m.ConfigureDownloadPolicy(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if err = f.m.ConfigureSchedulePolicy(context.Background(), func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestDownloadCoexistenceConsentDoesNotPromoteManualV7(t *testing.T) {
	for _, scheduled := range []bool{false, true} {
		f := coexistenceManager(t, scheduled)
		if !f.consent.Reusable() || !f.consent.Background() || !f.consent.DownloadEnabled() || f.consent.Validate() != nil {
			t.Fatal("fresh combined profile rejected")
		}
		for _, change := range []func(*Consent){func(c *Consent) { c.DownloadAcknowledged = false }, func(c *Consent) { c.DownloadScope = "" }, func(c *Consent) { c.ScheduleAcknowledged = !scheduled }, func(c *Consent) { c.BackgroundAcknowledged = false }, func(c *Consent) { c.ReusableAcknowledged = false }} {
			c := f.consent
			change(&c)
			if c.Validate() == nil {
				t.Fatal("combined consent missing acknowledgement admitted")
			}
		}
	}
	old := downloadManager(t).consent
	before, _ := json.Marshal(old)
	if old.Validate() != nil {
		t.Fatal("old manual profile changed")
	}
	old.ScheduleScope = ScheduleScope
	old.ScheduleAcknowledged = true
	if old.Validate() == nil {
		t.Fatal("manual v7 gained scheduling")
	}
	old.ScheduleScope = ""
	old.ScheduleAcknowledged = false
	after, _ := json.Marshal(old)
	if !bytes.Equal(before, after) {
		t.Fatal("old manual bytes changed")
	}
}

func TestDownloadCoexistencePurposeCannotEnterScheduler(t *testing.T) {
	f := coexistenceManager(t, true)
	ctx := context.Background()
	device := f.consent.Binding.DeviceID
	if err := f.m.RequestDownload(ctx, device, f.actor, f.id, f.source.value.Selection); err != nil {
		t.Fatal(err)
	}
	p := *f.m.record.Jobs[0].Preview
	before := bytes.Clone(f.store.files["jobs.json"])
	if err := f.m.Schedule(ctx, device, f.actor, f.id, p.Digest, f.at.Unix()+120, f.at.Unix()+240, true); err == nil {
		t.Fatal("manual download scheduled")
	}
	if !bytes.Equal(before, f.store.files["jobs.json"]) || f.m.record.Sequence != 0 {
		t.Fatal("download schedule rejection consumed occurrence")
	}
	a := ScheduleApproval{Version: ScheduleVersion, Baseline: p, ApprovedAt: f.at.Unix(), StartAt: f.at.Unix() + 120, EndAt: f.at.Unix() + 240, AuthorityExpiresAt: f.consent.ExpiresAt, Generation: 1}
	a.Digest = scheduleDigest(a)
	if a.Validate() == nil {
		t.Fatal("download baseline admitted by schedule contract")
	}
	if err := f.m.Report(ctx, backgroundSharedReport(t, f, f.at.Unix(), false, 1)); err != nil {
		t.Fatal(err)
	}
	if err := f.m.ApproveDownload(ctx, device, f.actor, f.id, p.Digest, true); err != nil {
		t.Fatal("manual approval lost", err)
	}
	if f.m.record.Jobs[0].Schedule != nil || f.m.record.Sequence != 1 {
		t.Fatal("manual download acquired schedule")
	}
}

func TestDownloadCoexistenceSchedulerScopesRemainIndependent(t *testing.T) {
	for _, scheduled := range []bool{false, true} {
		f := coexistenceManager(t, scheduled)
		ctx := context.Background()
		view, err := f.m.View(ctx, f.consent.Binding.DeviceID, f.actor)
		if err != nil || !view.DownloadEnabled || !view.BackgroundExecutor || view.BackgroundScheduling != scheduled || view.SchedulingAvailable != scheduled {
			t.Fatal("scope promoted or dropped", scheduled, view, err)
		}
		f.m.operatorAllowed = func(string) bool { return false }
		view, err = f.m.View(ctx, f.consent.Binding.DeviceID, f.actor)
		if err != nil || view.SchedulingAvailable || !f.m.operationAllowed(f.actor, true) || f.m.operationAllowed(f.actor, false) {
			t.Fatal("download capability implied install/schedule", view, err)
		}
		f.m.operatorAllowed = func(string) bool { return true }
		f.m.downloadAllowed = func(string) bool { return false }
		if f.m.operationAllowed(f.actor, true) || !f.m.operationAllowed(f.actor, false) || f.m.schedulingAvailable(f.actor) != scheduled {
			t.Fatal("install/schedule implied download")
		}
	}
}
