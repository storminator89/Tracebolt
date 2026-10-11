package api

import (
	"context"
	"encoding/json"
	"fmt"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsfullsoftware"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func softwareHistoryOperatorData(t *testing.T, f windowsEventOperatorFixture) {
	t.Helper()
	c := fullSoftwareOperatorData(t, f, 1)
	c.HistoryScope = windowsfullsoftware.HistoryScope
	c.GrantID = strings.Repeat("b", 32)
	c.Revision++
	apply := func(m windowsfullsoftware.Message) {
		raw, e := windowsfullsoftware.EncodeMessage(m)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.ApplyWindowsFullSoftware(enrollmentstore.WithWindowsFullSoftwareIngressOrigin(context.Background(), f.snap.Binding.Origin), f.snap.InvitationID, f.snap.Issuance.CertificateHash, m, raw, f.at); e != nil {
			t.Fatal(e)
		}
	}
	apply(windowsfullsoftware.Message{SchemaVersion: windowsfullsoftware.MessageVersion, Operation: "scope", DeviceID: f.snap.Approval.DeviceID, Consent: c})
	rows := []windowsfullsoftware.Row{}
	for i := 1; i <= 2; i++ {
		name := "PrivateSyntheticHistory"
		rows = append(rows, windowsfullsoftware.Row{RegistrationID: fmt.Sprintf("%064x", i), RegistryView: "64", Name: &name, NameQuality: "observed", VersionQuality: "unavailable", PublisherQuality: "unavailable"})
	}
	for seq := uint64(2); seq <= 3; seq++ {
		r := rows
		if seq == 3 {
			r = []windowsfullsoftware.Row{}
		}
		messages, e := windowsfullsoftware.Build(f.snap.Approval.DeviceID, c, seq, windowsfullsoftware.Capture{StartedAt: f.at, FinishedAt: f.at, Rows: r, Complete: true})
		if e != nil {
			t.Fatal(e)
		}
		for _, m := range messages {
			apply(m)
		}
	}
}
func TestSoftwareHistoryProtectedOperatorPages(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(fmt.Sprintf("named=%v", named), func(t *testing.T) { testSoftwareHistoryProtectedOperatorPages(t, named) })
	}
}
func testSoftwareHistoryProtectedOperatorPages(t *testing.T, named bool) {
	f := newWindowsEventOperatorFixtureFor(t, named)
	softwareHistoryOperatorData(t, f)
	path := "/api/devices/" + f.snap.Approval.DeviceID + "/windows-software-history/query"
	q := windowsfullsoftware.Query{Sort: "observed-desc", Limit: 1}
	if r, _ := f.call(t, "POST", path, q, "", nil); r.StatusCode != 403 {
		t.Fatal("CSRF", r.StatusCode)
	}
	if r, _ := f.call(t, "POST", path, q, f.csrf, func(r *http.Request) { r.Header.Set("Origin", "https://wrong.example") }); r.StatusCode != 403 {
		t.Fatal("Origin", r.StatusCode)
	}
	if r, _ := f.call(t, "GET", path, nil, "", nil); r.StatusCode != 405 {
		t.Fatal("GET", r.StatusCode)
	}
	if r, _ := f.call(t, "POST", path+"?search=private", q, f.csrf, nil); r.StatusCode != 404 && r.StatusCode != 400 {
		t.Fatal("private URL", r.StatusCode)
	}
	r, v := f.call(t, "POST", path, q, f.csrf, nil)
	raw, _ := json.Marshal(v)
	var p windowsfullsoftware.HistoryPage
	if r.StatusCode != 200 || json.Unmarshal(raw, &p) != nil || p.Status != "ready" || p.MatchingCount != 2 || len(p.Rows) != 1 || p.NextCursor == "" {
		t.Fatal("history page", r.StatusCode, v)
	}
	q.Cursor = p.NextCursor
	r, v = f.call(t, "POST", path, q, f.csrf, nil)
	if r.StatusCode != 200 || v["offset"] != float64(1) {
		t.Fatal("page two", r.StatusCode, v)
	}
	q.Cursor = ""
	q.Search = "privatesynthetichistory"
	r, v = f.call(t, "POST", path, q, f.csrf, nil)
	if r.StatusCode != 200 || v["matchingCount"] != float64(2) {
		t.Fatal("retained search", r.StatusCode, v)
	}
}
func TestSoftwareHistoryOperatorLateBoundaryHidesRows(t *testing.T) {
	for _, kind := range []string{"cursor-expiry", "logout", "session-expiry", "identity-revocation"} {
		t.Run(kind, func(t *testing.T) {
			f := newWindowsEventOperatorFixture(t)
			softwareHistoryOperatorData(t, f)
			path := "/api/devices/" + f.snap.Approval.DeviceID + "/windows-software-history/query"
			// Measure the successful path first. The final API clock sample is
			// immediately outside its two live-transaction guard samples; a
			// revocation write must not recursively acquire the same connection.
			f.clock.arm(nil)
			probe, _ := f.call(t, "POST", path, windowsfullsoftware.Query{Sort: "observed-desc", Limit: 100}, f.csrf, nil)
			if probe.StatusCode != 200 || f.clock.count() < 3 {
				t.Fatal("successful disclosure clock path unavailable")
			}
			outsideFinalGuard := f.clock.count() - 2
			var triggered atomic.Bool
			f.clock.arm(func(n int) {
				if n == outsideFinalGuard {
					triggered.Store(true)
					switch kind {
					case "cursor-expiry":
						f.clock.set(f.at.Add(16 * time.Minute))
					case "logout":
						f.server.Config.Handler.(*operatorHandler).auth.Logout(f.token)
					case "session-expiry":
						f.authNow.Store(f.at.Add(time.Hour))
					case "identity-revocation":
						if _, e := f.service.Terminate(context.Background(), f.snap.InvitationID, "request_"+strings.Repeat("f", 32), f.snap.Revision, enrollmentstate.Revoked); e != nil {
							t.Fatal(e)
						}
					}
				}
			})
			r, v := f.call(t, "POST", path, windowsfullsoftware.Query{Sort: "observed-desc", Limit: 100}, f.csrf, nil)
			raw, _ := json.Marshal(v)
			if !triggered.Load() || r.StatusCode == 200 || strings.Contains(string(raw), "PrivateSyntheticHistory") || v["rows"] != nil {
				t.Fatal("late boundary leak", r.StatusCode, f.clock.count(), v)
			}
		})
	}
}
