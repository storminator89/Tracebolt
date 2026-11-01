package api

import (
	"context"
	"encoding/json"
	"fmt"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsusersoftware"
	"net/http"
	"strings"
	"testing"
	"time"
)

func userSoftwareOperatorData(t *testing.T, f windowsEventOperatorFixture, n int) windowsusersoftware.Consent {
	t.Helper()
	ctx := context.Background()
	if e := f.service.InitializeWindowsUserSoftware(ctx); e != nil {
		t.Fatal(e)
	}
	c := windowsusersoftware.Consent{SchemaVersion: windowsusersoftware.ConsentVersion, Scope: windowsusersoftware.Scope, SenderBinding: windowsusersoftware.SenderBinding(f.snap.Binding.Profile, f.snap.Binding.Origin, f.snap.Issuance.CertificateHash, f.snap.Approval.DeviceID), GrantID: strings.Repeat("a", 32), Revision: 1, Enabled: true, ChangedAt: f.at}
	apply := func(m windowsusersoftware.Message) {
		raw, e := windowsusersoftware.EncodeMessage(m)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.ApplyWindowsUserSoftware(enrollmentstore.WithWindowsUserSoftwareIngressOrigin(ctx, f.snap.Binding.Origin), f.snap.InvitationID, f.snap.Issuance.CertificateHash, m, raw, f.at); e != nil {
			t.Fatal(e)
		}
	}
	apply(windowsusersoftware.Message{SchemaVersion: windowsusersoftware.MessageVersion, Operation: "scope", DeviceID: f.snap.Approval.DeviceID, Consent: c})
	rows := make([]windowsusersoftware.Row, n)
	for i := range rows {
		name := fmt.Sprintf("PrivateSyntheticSoftware%05d", i)
		version := fmt.Sprintf("%05d", i)
		publisher := "Synthetic 東京"
		rows[i] = windowsusersoftware.Row{RegistrationID: fmt.Sprintf("%064x", i+1), Source: "hkcu", Name: &name, NameQuality: "observed", Version: &version, VersionQuality: "observed", Publisher: &publisher, PublisherQuality: "observed"}
	}
	messages, e := windowsusersoftware.Build(f.snap.Approval.DeviceID, c, 1, windowsusersoftware.Capture{AccountContextID: strings.Repeat("d", 64), AccountLabel: "Selected account dddddddd", CaptureNonce: strings.Repeat("e", 64), HKCUStatus: "complete", MSIXStatus: "unsupported", StartedAt: f.at, FinishedAt: f.at, Rows: rows, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range messages {
		apply(m)
	}
	return c
}
func TestWindowsUserSoftwareProtectedOperatorFullPaging(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(fmt.Sprintf("named=%v", named), func(t *testing.T) {
			f := newWindowsEventOperatorFixtureFor(t, named)
			// Traverse a generation larger than 2048 rows once. The named
			// reader still crosses chunk and page boundaries and exercises every
			// operator/cursor check without repeating the large traversal.
			rows, laterRow := 2051, "02049"
			if named {
				rows, laterRow = 201, "00200"
			}
			userSoftwareOperatorData(t, f, rows)
			path := "/api/devices/" + f.snap.Approval.DeviceID + "/windows-selected-user-software/query"
			q := windowsusersoftware.Query{Sort: "name-asc", Limit: 100}
			if r, _ := f.call(t, "POST", path, q, "", nil); r.StatusCode != 403 {
				t.Fatal("missing CSRF accepted", r.StatusCode)
			}
			if r, _ := f.call(t, "POST", path, q, f.csrf, func(r *http.Request) { r.Header.Set("Origin", "https://wrong.example") }); r.StatusCode != 403 {
				t.Fatal("foreign Origin", r.StatusCode)
			}
			if r, _ := f.call(t, "GET", path, nil, "", nil); r.StatusCode != 405 {
				t.Fatal("GET query accepted", r.StatusCode)
			}
			if r, _ := f.call(t, "POST", path+"?search=private", q, f.csrf, nil); r.StatusCode != 404 && r.StatusCode != 400 {
				t.Fatal("private URL query accepted", r.StatusCode)
			}
			total := 0
			firstCursor := ""
			for {
				r, v := f.call(t, "POST", path, q, f.csrf, nil)
				if r.StatusCode != 200 {
					t.Fatal(r.StatusCode, v)
				}
				raw, _ := json.Marshal(v)
				if len(raw) > windowsusersoftware.MaxPageBytes {
					t.Fatal("page too large")
				}
				var p windowsusersoftware.Page
				if json.Unmarshal(raw, &p) != nil || p.Status != "ready" || p.MatchingCount != rows || p.Offset != total {
					t.Fatal("bad page", p.Status)
				}
				total += len(p.Rows)
				if firstCursor == "" {
					firstCursor = p.NextCursor
				}
				if p.NextCursor == "" {
					break
				}
				q.Cursor = p.NextCursor
			}
			if total != rows {
				t.Fatal("not complete")
			}
			q.Cursor = ""
			q.Search = laterRow
			r, v := f.call(t, "POST", path, q, f.csrf, nil)
			if r.StatusCode != 200 || v["matchingCount"] != float64(1) || !strings.Contains(fmt.Sprint(v["rows"]), laterRow) {
				t.Fatal("later row not searchable", r.StatusCode)
			}
			q.Cursor = firstCursor
			if r, _ = f.call(t, "POST", path, q, f.csrf, nil); r.StatusCode != 409 {
				t.Fatal("query not cursor bound")
			}
			q.Cursor = "aaa.bbb"
			if r, _ = f.call(t, "POST", path, q, f.csrf, nil); r.StatusCode != 400 {
				t.Fatal("malformed cursor", r.StatusCode)
			}
		})
	}
}
func TestWindowsUserSoftwareOperatorFinalBoundaryHidesRows(t *testing.T) {
	for _, kind := range []string{"cursor-expiry", "logout", "session-expiry", "identity-revocation"} {
		t.Run(kind, func(t *testing.T) {
			f := newWindowsEventOperatorFixture(t)
			userSoftwareOperatorData(t, f, 1)
			path := "/api/devices/" + f.snap.Approval.DeviceID + "/windows-selected-user-software/query"
			f.clock.arm(func(n int) {
				if n == 7 {
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
			r, v := f.call(t, "POST", path, windowsusersoftware.Query{Sort: "name-asc", Limit: 100}, f.csrf, nil)
			raw, _ := json.Marshal(v)
			if r.StatusCode == 200 || strings.Contains(string(raw), "PrivateSyntheticSoftware") || v["rows"] != nil {
				t.Fatal("late boundary leaked rows", r.StatusCode, f.clock.count(), v)
			}
		})
	}
}
