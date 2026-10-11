package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowssecuritycoverage"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWindowsSecurityCoverageOperatorSessionAndResponseTimeExpiry(t *testing.T) {
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	seq := uint64(1)
	for _, kind := range []string{"fresh", "stale", "expired", "revoked-session", "canceled-request"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			active := true
			id := "agent_" + strings.Repeat("1", 32)
			view := enrollmentstore.EmptyWindowsInventoryView(id, at)
			view.Status = "fresh"
			view.Sequence = &seq
			view.ReceivedAt = &at
			view.Snapshot = &windowsmanaged.Snapshot{CollectedAt: at}
			label := "Private provider label"
			storage := windowssecuritycoverage.Empty(windowssecuritycoverage.Request{Consent: windowssecuritycoverage.Consent{GrantID: strings.Repeat("3", 32)}, GenerationID: "sample_" + strings.Repeat("1", 32), CollectedAt: at}, windowssecuritycoverage.ErrUnavailable.Error())
			count := uint32(1)
			storage.Antivirus = windowssecuritycoverage.Antivirus{Quality: "observed", ReportedCount: &count, Rows: []windowssecuritycoverage.Product{{Index: 0, Name: &label, State: "on", SignatureStatus: "up-to-date"}}}
			storage.TPM = windowssecuritycoverage.TPM{Quality: "observed", Presence: "present", Version: "2.0"}

			view.SecurityCoverage = &storage
			old := storage
			old.CollectedAt = at.Add(-time.Hour)
			view.RetainedContext = &enrollmentstore.WindowsContextRetained{SecurityCoverage: &old}

			f := &windowsUpdatesViewFixture{now: at, view: view}
			f.afterRead = func() {
				switch kind {
				case "stale":
					f.now = at.Add(3 * time.Minute)
				case "expired":
					f.now = at.Add(24 * time.Hour)
				case "revoked-session":
					active = false
				case "canceled-request":
					cancel()
				}
			}
			r := httptest.NewRequest("GET", "/api/devices/"+id+"/windows-inventory", nil).WithContext(context.WithValue(ctx, operatorRequestKey{}, operatorRequest{active: func() bool { return active }}))
			w := httptest.NewRecorder()
			h := operatorHandler{app: setup(t)}
			h.writeWindowsInventoryView(w, r, f, id)
			if f.reads != 1 {
				t.Fatal("GET polled source or repeated retained read")
			}
			if kind == "revoked-session" || kind == "canceled-request" {
				if w.Code != 401 || strings.Contains(w.Body.String(), "Private provider label") || strings.Contains(w.Body.String(), "securityCoverage") {
					t.Fatal("session lost during read exposed private updates")
				}
				return
			}
			if w.Code != 200 {
				t.Fatal("retained view failed", w.Code)
			}
			var got enrollmentstore.WindowsInventoryView
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.ReceivedAt == nil || !got.ReceivedAt.Equal(at) {
				t.Fatal("response recheck refreshed receipt")
			}
			switch kind {
			case "fresh":
				if got.SecurityCoverage == nil || got.SecurityCoverage.Antivirus.Rows[0].Name == nil || got.Status != "fresh" {
					t.Fatal("cached evidence changed")
				}
			case "stale":
				if got.SecurityCoverage == nil || !got.SecurityCoverage.CollectedAt.Equal(at) || got.Status != "stale" {
					t.Fatal("stale capture refreshed")
				}
			case "expired":
				if got.SecurityCoverage != nil || got.RetainedContext != nil || strings.Contains(w.Body.String(), "Private provider label") || got.Status != "unavailable" {
					t.Fatal("private capture survived original 24h limit")
				}
			}
		})
	}
}
