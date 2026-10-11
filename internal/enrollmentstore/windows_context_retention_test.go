package enrollmentstore

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsupdates"
	"testing"
	"time"
)

func TestWindowsContextRetentionMaintenanceAndTermination(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "original-expiry", true: "termination"}[terminal], func(t *testing.T) {
			_, s, _, identity, cert := activeWindowsStoreTTL(t, "http-test", 48*time.Hour)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			if _, err := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), windowsUpdatesStoreFrame(t, 1, at), at); err != nil {
				t.Fatal(err)
			}
			var failed lanstore.Frame
			later := at.Add(30 * time.Second)
			if json.Unmarshal(windowsUpdatesStoreFrame(t, 2, later), &failed) != nil {
				t.Fatal("fixture")
			}
			failed.WindowsUpdates.Quality = "unavailable"
			failed.WindowsUpdates.Reason = windowsupdates.ErrBudget.Error()
			failed.WindowsUpdates.Rows = []windowsupdates.Update{}
			failed.WindowsUpdates.ObservedCount = 0
			failed.WindowsUpdates.CountExact = false
			raw, _ := json.Marshal(failed)
			if _, err := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, later); err != nil {
				t.Fatal(err)
			}
			view, err := s.WindowsInventoryView(ctx, identity.Approval.DeviceID, later)
			if err != nil || view.RetainedContext == nil || view.RetainedContext.Updates == nil || !view.RetainedContext.Updates.CollectedAt.Equal(at) || view.Updates.Reason != windowsupdates.ErrBudget.Error() {
				t.Fatal("source capture or failure lost", err)
			}
			count := func() int {
				t.Helper()
				var n int
				if s.db.QueryRow(`SELECT count(*) FROM enrollment_windows_context_retained`).Scan(&n) != nil {
					t.Fatal("cache query")
				}
				return n
			}
			if count() != 1 {
				t.Fatal("missing bounded cache row")
			}
			if terminal {
				ctl := control(identity, 20)
				ctl.Now = later.Add(time.Minute).Unix()
				if _, err = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: ctl, State: enrollmentstate.Revoked}); err != nil {
					t.Fatal(err)
				}
				if count() != 0 {
					t.Fatal("termination left private cache")
				}
			} else {
				if err = s.MaintainWindowsContext(ctx, 0, at.Add(24*time.Hour-time.Nanosecond)); err != nil || count() != 1 {
					t.Fatal("premature cache expiry", err)
				}
				expired := at.Add(24 * time.Hour)
				if err = s.MaintainWindowsContext(ctx, 1, expired); err != nil || count() != 0 {
					t.Fatal("cache did not expire on original clock", err)
				}
				if receipt, err := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, expired); err != nil || !receipt.Duplicate || count() != 0 {
					t.Fatal("exact retry repopulated expired cache", err)
				}
				view, err = s.WindowsInventoryView(ctx, identity.Approval.DeviceID, expired)
				if err != nil || view.RetainedContext != nil || view.Updates == nil || !view.Updates.CollectedAt.Equal(later) {
					t.Fatal("expiry changed current attempt", err)
				}
			}
		})
	}
}
