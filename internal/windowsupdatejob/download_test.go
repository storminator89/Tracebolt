package windowsupdatejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"testing"
	"time"
)

func downloadReady(r Readiness) Readiness {
	r.Purpose = DownloadPurpose
	r.Downloaded = No
	r.DownloadMetadataKnown = true
	r.DownloadOrigins = "https://download.example.test"
	r.DownloadMinBytes = 10
	r.DownloadMaxBytes = 20
	r.DownloadSource = "default"
	r.InstallerBusy = Unknown
	r.RebootRequiredBefore = Unknown
	r.CanRequestUserInput = Unknown
	r.CanRequireSource = Unknown
	r.RequiresNetwork = Unknown
	r.RebootBehavior = "unknown"
	return r
}
func downloadManager(t *testing.T) *workflowFixture {
	t.Helper()
	f := reusableManagerFixture(t, false)
	f.consent.Version = DownloadConsentVersion
	f.consent.DownloadScope = DownloadScope
	f.consent.DownloadAcknowledged = true
	r, e := NewRecordWithExecutor(f.consent, f.key.Public().(ed25519.PublicKey), executorKey().Public().(ed25519.PublicKey), f.at.Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := EncodeRecord(r)
	c, _ := json.Marshal(f.consent)
	f.store.files = map[string][]byte{"jobs.json": raw, "started.json": c, "receipt.json": c}
	f.source.value = downloadReady(f.source.value)
	f.m, e = Open(f.store, f.guard, f.source, f.key, func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func TestDownloadFreshConsentAndRequiredMetadata(t *testing.T) {
	f := downloadManager(t)
	if !f.consent.Background() || !f.consent.Reusable() || f.consent.Validate() != nil || f.source.value.Reason() != "ready" {
		t.Fatal("fresh contract")
	}
	for _, version := range []string{ConsentVersion, ScheduledConsentVersion, CoordinatedConsentVersion, BackgroundConsentVersion, ScheduledBackgroundConsentVersion, ReusableConsentVersion} {
		c := f.consent
		c.Version = version
		if c.Validate() == nil {
			t.Fatal("old consent promoted", version)
		}
	}
	for _, change := range []func(*Readiness){func(r *Readiness) { r.DownloadMetadataKnown = false }, func(r *Readiness) { r.EULAAccepted = No }, func(r *Readiness) { r.EULAAccepted = Unknown }, func(r *Readiness) { r.BundledCount = 1 }, func(r *Readiness) { r.BundledCount = -1 }, func(r *Readiness) { r.Downloaded = Yes }, func(r *Readiness) { r.DownloadMinBytes = 21 }, func(r *Readiness) { r.DownloadMaxBytes = MaxDownloadMetadataBytes + 1 }, func(r *Readiness) { r.DownloadSource = "" }, func(r *Readiness) { r.DownloadOrigins += "/secret?token=hidden" }} {
		r := f.source.value
		change(&r)
		if r.Reason() == "ready" {
			t.Fatal("unsafe metadata admitted", r)
		}
	}
	for _, origin := range []string{"https://example.test", "https://[2001:db8::1]:8443", "http://example.test:8080\nhttps://example.test"} {
		if !ValidDownloadOrigins(origin) {
			t.Fatal("valid origin", origin)
		}
	}
	for _, origin := range []string{"https://user:secret@example.test", "https://example.test/", "https://example.test?token=secret", "https://example.test#token", "https://EXAMPLE.test", "ftp://example.test", "https://example.test:443", "https://example.test\nhttps://example.test"} {
		if ValidDownloadOrigins(origin) {
			t.Fatal("unsafe origin", origin)
		}
	}
}
func TestDownloadPurposeCannotApproveOrClaimAsInstall(t *testing.T) {
	f := downloadManager(t)
	ctx := context.Background()
	device := f.consent.Binding.DeviceID
	if e := f.m.RequestDownload(ctx, device, f.actor, f.id, f.source.value.Selection); e != nil {
		t.Fatal(e)
	}
	if e := f.m.Report(ctx, backgroundSharedReport(t, f, f.at.Unix(), false, 1)); e != nil {
		t.Fatal(e)
	}
	p := f.m.record.Jobs[0].Preview
	if e := f.m.Approve(ctx, device, f.actor, f.id, p.Digest, true); e == nil {
		t.Fatal("install approval admitted download")
	}
	if e := f.m.ApproveDownload(ctx, device, f.actor, f.id, p.Digest, true); e != nil {
		t.Fatal(e)
	}
	if _, e := f.m.Claim(ctx, f.id); e == nil {
		t.Fatal("install claim admitted download")
	}
	raw, e := f.m.ClaimDownload(ctx, f.id)
	if e != nil {
		t.Fatal(e)
	}
	permit, e := Verify(raw, f.key.Public().(ed25519.PublicKey))
	if e != nil || !permit.Download() || permit.Sequence != 1 {
		t.Fatal("download permit", e)
	}
	changed := bytes.Replace(raw, []byte(DownloadPermitVersion), []byte(ReusablePermitVersion), 1)
	if _, e := Verify(changed, f.key.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("download signature substituted")
	}
	challenge := f.m.record.Jobs[0].Challenge
	changed = bytes.Replace(challenge, []byte(DownloadRelayVersion), []byte(RelayVersion), 1)
	if _, e := VerifyChallenge(changed, f.key.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("download challenge substituted")
	}
	if _, e = f.m.ClaimDownload(ctx, f.id); e == nil {
		t.Fatal("download delivery replayed")
	}
}
func TestDownloadStartFenceCannotAuthorizeInstallation(t *testing.T) {
	at := time.Unix(1800000000, 0)
	ctx := withInstallStartFence(withMutationPurpose(context.Background(), true), at.Unix(), at.Unix()+10, at.Unix()+10, at.Unix()+10)
	if CheckDownloadStart(ctx, at) != nil || CheckNativeDownloadStart(ctx, at) != nil {
		t.Fatal("download fence rejected")
	}
	if CheckInstallStart(ctx, at) == nil || CheckNativeInstallStart(ctx, at) == nil {
		t.Fatal("download authority installed")
	}
	install := withInstallStartFence(context.Background(), at.Unix(), at.Unix()+10, at.Unix()+10, at.Unix()+10)
	if CheckDownloadStart(install, at) == nil || CheckNativeDownloadStart(install, at) == nil {
		t.Fatal("installation authority downloaded")
	}
	if CheckNativeDownloadStart(ctx, at.Add(10*time.Second)) == nil {
		t.Fatal("expired download edge admitted")
	}
}

func TestDownloadExistingValidProfilesHaveNoAuthority(t *testing.T) {
	for _, version := range []string{ConsentVersion, ScheduledConsentVersion, CoordinatedConsentVersion, BackgroundConsentVersion, ScheduledBackgroundConsentVersion, ReusableConsentVersion} {
		t.Run(version, func(t *testing.T) {
			f := fixture(t)
			c := f.consent
			c.Version = version
			if version == CoordinatedConsentVersion || version == BackgroundConsentVersion || version == ScheduledBackgroundConsentVersion || version == ReusableConsentVersion {
				c.MutationPlanDigest = actionpermit.Digest([]byte("original plan"))
				c.PeerBindingDigest = actionpermit.Digest([]byte("original peer"))
			}
			c.BackgroundAcknowledged = c.Background()
			c.ReusableAcknowledged = c.Reusable()
			if version == ScheduledConsentVersion || version == ScheduledBackgroundConsentVersion {
				c.ScheduleScope = ScheduleScope
				c.ScheduleAcknowledged = true
			}
			if c.Validate() != nil {
				t.Fatal("old valid fixture")
			}
			r, e := NewRecordWithExecutor(c, f.key.Public().(ed25519.PublicKey), executorKey().Public().(ed25519.PublicKey), f.at.Unix())
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := EncodeRecord(r)
			consent, _ := json.Marshal(c)
			s := &memoryStore{files: map[string][]byte{"jobs.json": raw, "started.json": consent, "receipt.json": consent}}
			m, e := Open(s, f.guard, f.source, f.key, func() time.Time { return f.at })
			if e != nil {
				t.Fatal(e)
			}
			defer m.Close()
			if e = m.RequestDownload(context.Background(), c.Binding.DeviceID, f.actor, f.id, f.source.value.Selection); e != ErrAuthority {
				t.Fatal("old authority expanded", e)
			}
			if !bytes.Equal(raw, s.files["jobs.json"]) || !bytes.Equal(consent, s.files["receipt.json"]) {
				t.Fatal("old profile changed")
			}
		})
	}
}
