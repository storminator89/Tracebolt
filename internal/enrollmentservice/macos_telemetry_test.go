package enrollmentservice

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"testing"
	"time"
)

// All identities, certificates and observations in this test are disposable
// fixtures. It executes no macOS collector, service or real enrollment.
func TestMacOSBasicTLSRenewalTelemetryRetainsIdentityAndReplay(t *testing.T) {
	f, active, key := activatedRenewalFixture(t, "darwin")
	ctx := context.Background()
	cert, e := f.store.CertificateForVerification(ctx, active.InvitationID)
	if e != nil {
		t.Fatal(e)
	}
	makeFrame := func(seq uint64, at time.Time) []byte {
		frame := windowsDashboardFrame("macos", seq, at)
		frame.Observation.Architecture = "arm64"
		d := &frame.Observation.Observation
		d.ID = "local-macos"
		d.Name = "Local macOS"
		d.OS = "Invented macOS fixture"
		d.Memory = d.CPU
		return marshalWindowsDashboardFrame(t, frame, at)
	}
	raw := makeFrame(1, f.now)
	receipt, e := f.store.SaveObservation(ctx, active.InvitationID, cert.CertificateHash(), raw, f.now)
	if e != nil || receipt.Sequence != 1 {
		t.Fatal("Darwin identity did not accept macOS basic observation", e)
	}
	for _, platform := range []string{"linux", "windows"} {
		bad := marshalWindowsDashboardFrame(t, windowsDashboardFrame(platform, 2, f.now.Add(time.Second)), f.now.Add(time.Second))
		if _, e = f.store.SaveObservation(ctx, active.InvitationID, cert.CertificateHash(), bad, f.now.Add(time.Second)); !errors.Is(e, enrollmentstate.ErrProof) {
			t.Fatal("cross-platform report admitted", platform, e)
		}
	}
	f.restart(t)
	views, e := f.service.Devices(ctx, f.now)
	if e != nil || len(views) != 1 || views[0].Platform != "macos" || views[0].Name != active.Approval.DeviceID || views[0].Memory.Value != nil || views[0].Memory.Quality != "unknown" || views[0].Status != "unknown" {
		t.Fatal("durable Mac projection changed scope or quality", e)
	}
	retry, e := f.store.SaveObservation(ctx, active.InvitationID, cert.CertificateHash(), raw, f.now.Add(time.Minute))
	if e != nil || !retry.Duplicate || retry.ReceivedAt != receipt.ReceivedAt || retry.CollectedAt != receipt.CollectedAt {
		t.Fatal("Mac retry refreshed source", e)
	}
	f.now = time.Unix(active.Intent.NotAfter, 0).Add(-47 * time.Hour)
	c, b := renewalProof(t, f, active, key, cert.CertificateHash(), enrollmentcrypto.PurposeRenewalIssue, 100)
	issued, e := f.service.Renew(ctx, c.Context.Challenge, b)
	if e != nil || issued.Candidate == nil {
		t.Fatal("renewal issue", e)
	}
	c, b = renewalProof(t, f, active, key, issued.Candidate.CertificateHash, enrollmentcrypto.PurposeRenewalActivate, 101)
	renewed, e := f.service.ActivateRenewal(ctx, c.Context.Challenge, b)
	if e != nil || renewed.CredentialGeneration != 2 {
		t.Fatal("renewal activation", e)
	}
	f.now = time.Unix(active.Intent.NotAfter+1, 0)
	f.restart(t)
	next := makeFrame(2, f.now)
	if _, e = f.store.SaveObservation(ctx, active.InvitationID, cert.CertificateHash(), next, f.now); e == nil {
		t.Fatal("retired original credential authorized")
	}
	if _, e = f.store.SaveObservation(ctx, active.InvitationID, renewed.Current.CertificateHash, next, f.now); e != nil {
		t.Fatal("renewed Mac observation failed after anchor expiry", e)
	}
	_, e = f.service.Terminate(ctx, active.InvitationID, id("request", 103), active.Revision, enrollmentstate.Revoked)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.SaveObservation(ctx, active.InvitationID, renewed.Current.CertificateHash, next, f.now); e == nil {
		t.Fatal("revoked exact duplicate admitted")
	}
}
