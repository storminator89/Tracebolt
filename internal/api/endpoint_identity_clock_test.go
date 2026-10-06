package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentstore"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEndpointIdentityFinalOutputRechecksIdentityAndSession(t *testing.T) {
	for _, activate := range []bool{false, true} {
		state := "issued"
		if activate {
			state = "activated"
		}
		for _, crossing := range []string{"success", "final_clock_expiry", "session_check_expiry", "session_revoked", "after_commit_cancel", "final_clock_cancel", "final_clock_revoked"} {
			t.Run(state+"/"+crossing, func(t *testing.T) {
				start := time.Now().UTC().Truncate(time.Second)
				checked := start
				calls := 0
				var onClock func(int)
				now := func() time.Time {
					calls++
					if onClock != nil {
						onClock(calls)
					}
					return checked
				}
				service := overviewServiceFixtureWithClock(t, "https://overview.invalid", now)
				identity := inventoryIdentityClockFixture(t, service, start, activate)
				expiry := time.Unix(identity.Intent.NotAfter, 0).UTC()
				calls = 0
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				onClock = func(call int) {
					// Initial API timestamp, post-load refresh, post-commit refresh,
					// then the final trusted output timestamp.
					if crossing == "final_clock_expiry" && call >= 4 {
						checked = expiry
					}
					if crossing == "after_commit_cancel" && call == 3 || crossing == "final_clock_cancel" && call == 4 {
						cancel()
					}
				}
				activeChecks := 0
				r := httptest.NewRequest("GET", "/api/devices/"+identity.Approval.DeviceID+"/inventory/endpoint-identity", nil)
				r = r.WithContext(context.WithValue(ctx, operatorRequestKey{}, operatorRequest{active: func() bool {
					activeChecks++
					if crossing == "session_check_expiry" {
						checked = expiry
					}
					return crossing != "session_revoked" && !(crossing == "final_clock_revoked" && calls >= 4)
				}}))
				h := operatorHandler{app: setup(t), enrollment: service}
				w := httptest.NewRecorder()
				h.endpointIdentity(w, r)
				if crossing == "session_revoked" || crossing == "after_commit_cancel" || crossing == "final_clock_cancel" || crossing == "final_clock_revoked" {
					wantCode := http.StatusUnauthorized
					if crossing == "after_commit_cancel" {
						// Store detects cancellation before returning a DTO; retain the
						// existing inventory error mapping for that failure.
						wantCode = http.StatusServiceUnavailable
					}
					if w.Code != wantCode || strings.Contains(w.Body.String(), "tracebolt.endpoint-identity-view") || strings.Contains(w.Body.String(), identity.Approval.DeviceID) {
						t.Fatal("revoked or canceled request exposed endpoint metadata", w.Code)
					}
					return
				}
				var view enrollmentstore.EndpointIdentityView
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || activeChecks != 2 || calls < 4 {
					t.Fatalf("authorized endpoint response or final checks missing: status=%d activeChecks=%d clocks=%d", w.Code, activeChecks, calls)
				}
				want := "unknown"
				if activate {
					want = "not_collected"
				}
				if crossing != "success" {
					want = "expired"
				}
				if view.Status != want || !view.ServerNow.Equal(checked) || view.DeviceID != identity.Approval.DeviceID || view.SchemaVersion != "tracebolt.endpoint-identity-view.v1" {
					t.Fatalf("final output used stale authority: status=%q want=%q clocks=%d", view.Status, want, calls)
				}
				if view.Latest != nil || view.ReceivedAt != nil || view.Sequence != nil || view.ExpiresAt != nil {
					t.Fatal("uncollected extension manufactured observations")
				}
				if strings.Contains(w.Body.String(), "readState") || strings.Contains(w.Body.String(), "certificateNotAfter") || strings.Contains(w.Body.String(), "observationAt") {
					t.Fatal("private endpoint read authority escaped the DTO")
				}
			})
		}
	}
}
