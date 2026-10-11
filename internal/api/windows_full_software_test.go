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
	"testing"
	"time"
)

func fullSoftwareOperatorData(t *testing.T, f windowsEventOperatorFixture, n int) windowsfullsoftware.Consent {
	t.Helper()
	ctx := context.Background()
	if e := f.service.InitializeWindowsFullSoftware(ctx); e != nil {
		t.Fatal(e)
	}
	c := windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: windowsfullsoftware.Scope, SenderBinding: windowsfullsoftware.SenderBinding(f.snap.Binding.Profile, f.snap.Binding.Origin, f.snap.Issuance.CertificateHash, f.snap.Approval.DeviceID), GrantID: strings.Repeat("a", 32), Revision: 1, Enabled: true, ChangedAt: f.at}
	apply := func(m windowsfullsoftware.Message) {
		raw, e := windowsfullsoftware.EncodeMessage(m)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.ApplyWindowsFullSoftware(enrollmentstore.WithWindowsFullSoftwareIngressOrigin(ctx, f.snap.Binding.Origin), f.snap.InvitationID, f.snap.Issuance.CertificateHash, m, raw, f.at); e != nil {
			t.Fatal(e)
		}
	}
	apply(windowsfullsoftware.Message{SchemaVersion: windowsfullsoftware.MessageVersion, Operation: "scope", DeviceID: f.snap.Approval.DeviceID, Consent: c})
	rows := make([]windowsfullsoftware.Row, n)
	for i := range rows {
		name := fmt.Sprintf("PrivateSyntheticSoftware%05d", i)
		version := fmt.Sprintf("%05d", i)
		publisher := "Synthetic 東京"
		rows[i] = windowsfullsoftware.Row{RegistrationID: fmt.Sprintf("%064x", i+1), RegistryView: "64", Name: &name, NameQuality: "observed", Version: &version, VersionQuality: "observed", Publisher: &publisher, PublisherQuality: "observed"}
	}
	messages, e := windowsfullsoftware.Build(f.snap.Approval.DeviceID, c, 1, windowsfullsoftware.Capture{StartedAt: f.at, FinishedAt: f.at, Rows: rows, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range messages {
		apply(m)
	}
	return c
}
func TestWindowsFullSoftwareProtectedOperatorFullPaging(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(fmt.Sprintf("named=%v", named), func(t *testing.T) {
			f := newWindowsEventOperatorFixtureFor(t, named)
			fullSoftwareOperatorData(t, f, 2051)
			path := "/api/devices/" + f.snap.Approval.DeviceID + "/windows-full-software/query"
			q := windowsfullsoftware.Query{Sort: "name-asc", Limit: 100}
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
				if len(raw) > windowsfullsoftware.MaxPageBytes {
					t.Fatal("page too large")
				}
				var p windowsfullsoftware.Page
				if json.Unmarshal(raw, &p) != nil || p.Status != "ready" || p.MatchingCount != 2051 || p.Offset != total {
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
			if total != 2051 {
				t.Fatal("not complete")
			}
			q.Cursor = ""
			q.Search = "02049"
			r, v := f.call(t, "POST", path, q, f.csrf, nil)
			if r.StatusCode != 200 || v["matchingCount"] != float64(1) || !strings.Contains(fmt.Sprint(v["rows"]), "02049") {
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
func TestWindowsFullSoftwareOperatorFinalBoundaryHidesRows(t *testing.T) {
	for _, kind := range []string{"cursor-expiry", "logout", "session-expiry", "identity-revocation"} {
		t.Run(kind, func(t *testing.T) {
			f := newWindowsEventOperatorFixture(t)
			fullSoftwareOperatorData(t, f, 1)
			path := "/api/devices/" + f.snap.Approval.DeviceID + "/windows-full-software/query"
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
			r, v := f.call(t, "POST", path, windowsfullsoftware.Query{Sort: "name-asc", Limit: 100}, f.csrf, nil)
			raw, _ := json.Marshal(v)
			if r.StatusCode == 200 || strings.Contains(string(raw), "PrivateSyntheticSoftware") || v["rows"] != nil {
				t.Fatal("late boundary leaked rows", r.StatusCode, f.clock.count(), v)
			}
		})
	}
}
