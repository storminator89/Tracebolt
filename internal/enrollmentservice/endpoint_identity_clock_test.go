package enrollmentservice

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
	"strings"
	"testing"
	"time"
)

// Reuse the complete-profile synthetic enrollment fixture. A later ordinary
// observation deliberately has a newer receipt than the endpoint extension.
func endpointIdentityClockFixture(t *testing.T, nearCertificateExpiry bool) (*fixture, enrollmentstate.Snapshot, time.Time, time.Time) {
	t.Helper()
	f, active := systemInventoryClockFixture(t)
	collected := f.now.Add(5 * time.Second)
	if nearCertificateExpiry {
		collected = time.Unix(active.Intent.NotAfter, 0).UTC().Add(-time.Minute)
	}
	received := collected.Add(15 * time.Second)
	generation, err := systemwire.GenerationID(active.Approval.DeviceID, 2)
	if err != nil {
		t.Fatal(err)
	}
	observation := systeminventory.Empty(generation, collected, systeminventory.ReasonReadFailed)
	identity := endpointidentity.Empty(generation, collected, endpointidentity.ReasonNotCollected)
	hostname := "synthetic-private-endpoint-clock-host"
	identity.ReportedHostname = endpointidentity.Hostname{Coverage: endpointidentity.Complete, Reason: endpointidentity.ReasonNone, Value: &hostname}
	raw, err := systemwire.EncodeEndpoint(2, observation, identity)
	if err != nil {
		t.Fatal("fixture endpoint encoding failed", err)
	}
	if _, err = f.store.SaveSystemObservation(context.Background(), active.InvitationID, active.Issuance.CertificateHash, raw, received); err != nil {
		t.Fatal("fixture endpoint save failed", err)
	}
	ordinaryAt := received.Add(10 * time.Second)
	generation, err = systemwire.GenerationID(active.Approval.DeviceID, 3)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = systemwire.Encode(3, systeminventory.Empty(generation, ordinaryAt, systeminventory.ReasonReadFailed))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SaveSystemObservation(context.Background(), active.InvitationID, active.Issuance.CertificateHash, raw, ordinaryAt); err != nil {
		t.Fatal("fixture ordinary observation failed", err)
	}
	return f, active, collected, received
}

func TestEndpointIdentityServicePropagatesTrustedClockAcrossReadBoundaries(t *testing.T) {
	for _, boundary := range []string{"transaction", "after_commit"} {
		for _, horizon := range []string{"fresh", "fresh_boundary", "stale", "retention_expiry", "certificate_expiry"} {
			t.Run(boundary+"/"+horizon, func(t *testing.T) {
				f, active, collected, received := endpointIdentityClockFixture(t, horizon == "certificate_expiry")
				at := received.Add(10 * time.Second)
				checked, want := at.Add(time.Second), "fresh"
				switch horizon {
				case "fresh_boundary":
					checked = collected.Add(enrollmentstore.SystemMaxAge)
				case "stale":
					checked, want = collected.Add(enrollmentstore.SystemMaxAge+time.Nanosecond), "stale"
				case "retention_expiry":
					checked, want = collected.Add(enrollmentstore.SystemRetention), "expired"
				case "certificate_expiry":
					checked, want = time.Unix(active.Intent.NotAfter, 0).UTC(), "expired"
					if !checked.Before(collected.Add(enrollmentstore.SystemMaxAge)) {
						t.Fatal("certificate fixture must expire while its observation is fresh")
					}
				}
				calls, callerCalls := 0, 0
				f.service.now = func() time.Time {
					calls++
					if boundary == "after_commit" && calls == 1 {
						return at
					}
					return checked
				}
				ctx := enrollmentstore.WithSystemViewClock(context.Background(), func() time.Time {
					callerCalls++
					return at
				})
				view, err := f.service.EndpointIdentityView(ctx, active.Approval.DeviceID, at)
				if err != nil || calls < 2 || callerCalls != 0 || view.Status != want || !view.ServerNow.Equal(checked) {
					t.Fatalf("trusted clock not applied at %s: status=%q calls=%d callerCalls=%d err=%v", boundary, view.Status, calls, callerCalls, err)
				}
				if boundary == "transaction" && horizon == "certificate_expiry" {
					// An identity already expired when authorized keeps the existing
					// status-only contract. Only post-commit expiry retains a receipt
					// that was authorized before the certificate boundary.
					if view.Sequence != nil || view.ReceivedAt != nil || view.ExpiresAt != nil {
						t.Fatal("expired identity exposed unauthorized endpoint receipt")
					}
				} else if view.Sequence == nil || *view.Sequence != 2 || view.ReceivedAt == nil || !view.ReceivedAt.Equal(received) || view.ExpiresAt == nil || !view.ExpiresAt.Equal(collected.Add(enrollmentstore.SystemRetention)) {
					t.Fatal("read clock replaced the original extension receipt or capture-based retention")
				}
				if want == "expired" {
					if view.Latest != nil {
						t.Fatal("expired endpoint values escaped the service boundary")
					}
				} else if view.Latest == nil || !view.Latest.CollectedAt.Equal(collected) || view.Latest.ReportedHostname.Value == nil || *view.Latest.ReportedHostname.Value != "synthetic-private-endpoint-clock-host" {
					t.Fatal("read clock changed endpoint source age or lost synthetic payload")
				}
				raw, err := json.Marshal(view)
				if err != nil || strings.Contains(string(raw), "readState") || strings.Contains(string(raw), "certificateNotAfter") || strings.Contains(string(raw), "observationAt") {
					t.Fatal("private read-time authority escaped the DTO", err)
				}
				stored, err := f.store.EndpointIdentityView(context.Background(), active.Approval.DeviceID, at)
				if err != nil || stored.Status != "fresh" || stored.Latest == nil || !stored.Latest.CollectedAt.Equal(collected) || stored.Sequence == nil || *stored.Sequence != 2 || stored.ReceivedAt == nil || !stored.ReceivedAt.Equal(received) {
					t.Fatal("read-time aging mutated retained endpoint observations", err)
				}
			})
		}
	}
}

func TestEndpointIdentityServiceCancellationSuppressesMetadata(t *testing.T) {
	for _, boundary := range []string{"before_read", "transaction", "after_commit"} {
		t.Run(boundary, func(t *testing.T) {
			f, active, collected, received := endpointIdentityClockFixture(t, false)
			at := received.Add(10 * time.Second)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			f.service.now = func() time.Time {
				calls++
				if boundary == "transaction" && calls == 1 || boundary == "after_commit" && calls == 2 {
					cancel()
				}
				return at
			}
			if boundary == "before_read" {
				cancel()
			}
			view, err := f.service.EndpointIdentityView(ctx, active.Approval.DeviceID, at)
			if !errors.Is(err, context.Canceled) || view.SchemaVersion != "" || view.DeviceID != "" || view.Sequence != nil || view.ReceivedAt != nil || view.ExpiresAt != nil || view.Latest != nil {
				t.Fatal("canceled service read exposed endpoint metadata", err)
			}
			stored, err := f.store.EndpointIdentityView(context.Background(), active.Approval.DeviceID, at)
			if err != nil || stored.Status != "fresh" || stored.Latest == nil || !stored.Latest.CollectedAt.Equal(collected) {
				t.Fatal("canceled endpoint read mutated retained metadata", err)
			}
		})
	}
}
