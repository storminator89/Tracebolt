package enrollmentservice

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
	"path/filepath"
	"testing"
	"time"
)

// The fixture uses only synthetic keys and rows in a temporary store. It follows
// the ordinary complete-profile claim, approval, issuance and activation path.
func systemInventoryClockFixture(t *testing.T) (*fixture, enrollmentstate.Snapshot) {
	t.Helper()
	f := newFixture(t, "tls")
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	f.path = filepath.Join(t.TempDir(), "private", "system-clock.db")
	f.restart(t)
	ctx := context.Background()
	pending, key := claim(t, f)
	approved, err := f.service.Approve(ctx, pending.InvitationID, id("request", 40), pending.Claim.KeyFingerprint, pending.Revision)
	if err != nil {
		t.Fatal("fixture approval failed", err)
	}
	if err := f.service.issue(ctx, approved.InvitationID); err != nil {
		t.Fatal("fixture issuance failed", err)
	}
	cert, err := f.store.CertificateForVerification(ctx, approved.InvitationID)
	if err != nil {
		t.Fatal("fixture certificate unavailable", err)
	}
	c := challenge(t, f, pending.InvitationID, pending.Claim.ClaimID, "activation")
	message, err := enrollmentcrypto.ActivationSigningMessage(c.Context, cert.Intent(), id("request", 41), cert.CertificateHash(), f.now)
	if err != nil {
		t.Fatal("fixture activation message failed", err)
	}
	raw, err := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "deviceId": approved.Approval.DeviceID, "intentId": cert.Intent().IntentID, "certificateHash": cert.CertificateHash(), "requestId": id("request", 41), "challenge": c.Context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))})
	if err != nil {
		t.Fatal(err)
	}
	active, err := f.service.Activate(ctx, c.Context.Challenge, raw)
	if err != nil || active.State != enrollmentstate.Activated {
		t.Fatal("fixture activation failed", err)
	}
	generation, err := systemwire.GenerationID(active.Approval.DeviceID, 1)
	if err != nil {
		t.Fatal(err)
	}
	observation := systeminventory.Empty(generation, f.now, systeminventory.ReasonReadFailed)
	count := uint64(0)
	meta := systeminventory.SectionMeta{GenerationID: generation, ObservedAt: f.now, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: &count, CountExact: true}
	observation.Services = systeminventory.ServiceSection{Meta: meta, Items: []systeminventory.Service{}}
	observation.Sockets = systeminventory.SocketSection{Meta: meta, Items: []systeminventory.Socket{}}
	raw, err = systemwire.Encode(1, observation)
	if err != nil {
		t.Fatal("fixture observation encoding failed", err)
	}
	if _, err := f.store.SaveSystemObservation(ctx, active.InvitationID, cert.CertificateHash(), raw, f.now); err != nil {
		t.Fatal("fixture observation save failed", err)
	}
	return f, active
}

func TestSystemInventoryServicePropagatesTrustedClockAcrossReadBoundaries(t *testing.T) {
	for _, boundary := range []string{"transaction", "after_commit"} {
		for _, horizon := range []string{"fresh", "stale", "retention_expiry", "identity_expiry"} {
			t.Run(boundary+"/"+horizon, func(t *testing.T) {
				f, active := systemInventoryClockFixture(t)
				at := f.now
				checked := at.Add(time.Second)
				want := "fresh"
				switch horizon {
				case "stale":
					checked, want = at.Add(enrollmentstore.SystemMaxAge+time.Second), "stale"
				case "retention_expiry":
					checked, want = at.Add(enrollmentstore.SystemRetention), "expired"
				case "identity_expiry":
					checked, want = time.Unix(active.Intent.NotAfter, 0).UTC(), "expired"
				}
				calls := 0
				f.service.now = func() time.Time {
					calls++
					if boundary == "after_commit" && calls == 1 {
						return at
					}
					return checked
				}
				// A caller's stale clock must not replace the service dependency.
				ctx := enrollmentstore.WithSystemViewClock(context.Background(), func() time.Time { return at })
				view, err := f.service.SystemInventoryView(ctx, active.Approval.DeviceID, at)
				if err != nil || calls < 2 || view.Status != want || !view.ServerNow.Equal(checked) {
					t.Fatalf("trusted clock not applied at %s: status=%q calls=%d err=%v", boundary, view.Status, calls, err)
				}
				if view.Sequence == nil || *view.Sequence != 1 || view.ReceivedAt == nil || !view.ReceivedAt.Equal(at) {
					t.Fatal("clock recheck changed the durable sequence or original receipt")
				}
				if want == "expired" {
					if view.Latest != nil || view.LastComplete.Services != nil || view.LastComplete.Sockets != nil {
						t.Fatal("expired metadata escaped the service boundary")
					}
				} else if view.Latest == nil || !view.Latest.CollectedAt.Equal(at) || view.LastComplete.Services == nil || view.LastComplete.Services.Status != want || !view.LastComplete.Services.Meta.ObservedAt.Equal(at) || view.LastComplete.Sockets == nil || view.LastComplete.Sockets.Status != want {
					t.Fatal("clock recheck changed source times or lost current sections")
				}
				// Read-time aging must not perform cleanup or rewrite stored facts.
				stored, err := f.store.SystemView(context.Background(), active.Approval.DeviceID, at)
				if err != nil || stored.Status != "fresh" || stored.Latest == nil || stored.LastComplete.Services == nil || stored.LastComplete.Sockets == nil {
					t.Fatal("read-time aging mutated retained observations", err)
				}
			})
		}
	}
}
