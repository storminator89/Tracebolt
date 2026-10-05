package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstate"
	"testing"
	"time"
)

func TestDevicesCertificateExpiryUsesCommittedIssuanceOnly(t *testing.T) {
	f := newFixture(t, "tls")
	ctx := context.Background()
	pending, _ := claim(t, f)
	approved, err := f.service.Approve(ctx, pending.InvitationID, id("request", 40), pending.Claim.KeyFingerprint, pending.Revision)
	if err != nil {
		t.Fatal("fixture approval failed")
	}
	assertUnknown := func() {
		t.Helper()
		devices, err := f.service.Devices(ctx, f.now)
		if err != nil || len(devices) != 1 || devices[0].AgentCertificate == nil || devices[0].AgentCertificate.ExpiresAt != nil {
			t.Fatal("unissued certificate has an expiry")
		}
	}
	assertUnknown()
	expires := f.now.Add(6 * 24 * time.Hour)
	_, err = f.store.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: enrollmentstate.Control{InvitationID: approved.InvitationID, RequestID: id("request", 41), ExpectedRevision: approved.Revision, Now: f.now.Unix()}, IntentID: id("intent", 42), SerialHex: "0123456789abcdef0123456789abcdef", TemplateVersion: enrollmentstate.TemplateVersion, NotBefore: f.now.Add(-30 * time.Second).Unix(), NotAfter: expires.Unix()})
	if err != nil {
		t.Fatal("fixture issuance intent failed")
	}
	assertUnknown()
	if err = f.service.issue(ctx, approved.InvitationID); err != nil {
		t.Fatal("fixture issuance failed")
	}
	before, err := f.store.Get(ctx, approved.InvitationID)
	if err != nil {
		t.Fatal("fixture read failed")
	}
	for _, checked := range []time.Time{f.now, expires.Add(-time.Hour), expires, expires.Add(time.Hour)} {
		devices, err := f.service.Devices(ctx, checked)
		if err != nil || len(devices) != 1 {
			t.Fatal("operator expiry read failed")
		}
		d := devices[0]
		c := d.AgentCertificate
		if c == nil || c.Source != "guided-enrollment" || c.ExpiresAt == nil || !c.ExpiresAt.Equal(expires) || !c.CheckedAt.Equal(checked) {
			t.Fatal("read changed or inferred the committed certificate expiry")
		}
		if d.Status != "unknown" || !d.LastSeen.IsZero() {
			t.Fatal("certificate expiry read established device connectivity")
		}
	}
	after, err := f.store.Get(ctx, approved.InvitationID)
	if err != nil || before != after {
		t.Fatal("operator expiry reads changed enrollment state")
	}
}
