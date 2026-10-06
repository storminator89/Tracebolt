package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Recorder only: real synthetic service authority, no listener or collection.
func TestCompletePackageMetadataFinalOutputRechecksIdentityAndSession(t *testing.T) {
	for _, crossing := range []string{"success", "final_clock_expiry", "session_check_expiry", "session_revoked", "after_commit_cancel"} {
		t.Run(crossing, func(t *testing.T) {
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
			active := inventoryIdentityClockFixture(t, service, start, true)
			expiry := time.Unix(active.Intent.NotAfter, 0).UTC()
			calls = 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			onClock = func(call int) {
				if crossing == "final_clock_expiry" && call >= 4 {
					checked = expiry
				}
				if crossing == "after_commit_cancel" && call == 3 {
					cancel()
				}
			}
			activeChecks := 0
			r := httptest.NewRequest("GET", "/api/devices/"+active.Approval.DeviceID+"/inventory/packages", nil)
			r = r.WithContext(context.WithValue(ctx, operatorRequestKey{}, operatorRequest{active: func() bool {
				activeChecks++
				if crossing == "session_check_expiry" {
					checked = expiry
				}
				return crossing != "session_revoked"
			}}))
			h := operatorHandler{app: setup(t), enrollment: service}
			w := httptest.NewRecorder()
			h.completePackages(w, r)
			if crossing != "success" {
				want := 409
				if crossing == "session_revoked" || crossing == "after_commit_cancel" {
					want = 401
				}
				if w.Code != want || strings.Contains(w.Body.String(), "tracebolt.complete-package-view") || strings.Contains(w.Body.String(), active.Approval.DeviceID) {
					t.Fatal("expired authority or canceled request exposed metadata", w.Code)
				}
				return
			}
			var view completePackageView
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || activeChecks != 1 || calls < 4 || view.Status != "awaiting" || !view.ServerNow.Equal(checked) || view.DeviceID != active.Approval.DeviceID || view.Complete != nil || view.Transfer != nil || view.Failure != nil {
				t.Fatal("authorized awaiting metadata lost", w.Code)
			}
			if strings.Contains(w.Body.String(), "readState") || strings.Contains(w.Body.String(), "certificateNotAfter") {
				t.Fatal("private authority escaped DTO")
			}
		})
	}
}
