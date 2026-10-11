package api

import (
	"context"
	"encoding/json"
	"fmt"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsnetworkcontext"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func networkContextOperatorData(t *testing.T, f windowsEventOperatorFixture, n int) windowsnetworkcontext.Consent {
	t.Helper()
	ctx := context.Background()
	if e := f.service.InitializeWindowsNetworkContext(ctx); e != nil {
		t.Fatal(e)
	}
	c := windowsnetworkcontext.Consent{SchemaVersion: windowsnetworkcontext.ConsentVersion, Scope: windowsnetworkcontext.Scope, SenderBinding: windowsnetworkcontext.SenderBinding(f.snap.Binding.Profile, f.snap.Binding.Origin, f.snap.Issuance.CertificateHash, f.snap.Approval.DeviceID), GrantID: strings.Repeat("a", 32), Revision: 1, Enabled: true, ChangedAt: f.at}
	apply := func(m windowsnetworkcontext.Message) {
		raw, e := windowsnetworkcontext.EncodeMessage(m)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.ApplyWindowsNetworkContext(enrollmentstore.WithWindowsNetworkContextIngressOrigin(ctx, f.snap.Binding.Origin), f.snap.InvitationID, f.snap.Issuance.CertificateHash, m, raw, f.at); e != nil {
			t.Fatal(e)
		}
	}
	apply(windowsnetworkcontext.Message{SchemaVersion: windowsnetworkcontext.MessageVersion, Operation: "scope", DeviceID: f.snap.Approval.DeviceID, Consent: c})
	rows := make([]windowsnetworkcontext.Row, n)
	for i := range rows {
		rows[i] = windowsnetworkcontext.Row{ID: uint32(i + 1), Kind: "route", InterfaceIndex: uint32(i%256 + 1), Route: &windowsnetworkcontext.Route{Destination: netip.MustParsePrefix(fmt.Sprintf("2001:db8::%d/128", i)).String(), NextHop: "::", Metric: uint32(i), Protocol: 2}}

	}
	messages, e := windowsnetworkcontext.Build(f.snap.Approval.DeviceID, c, 1, windowsnetworkcontext.Capture{StartedAt: f.at, FinishedAt: f.at, Rows: rows, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range messages {
		apply(m)
	}
	return c
}
func TestWindowsNetworkContextProtectedOperatorFullPaging(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(fmt.Sprintf("named=%v", named), func(t *testing.T) {
			f := newWindowsEventOperatorFixtureFor(t, named)
			networkContextOperatorData(t, f, 2051)
			path := "/api/devices/" + f.snap.Approval.DeviceID + "/windows-network-context/query"
			q := windowsnetworkcontext.Query{Kind: "all", Sort: "source-asc", Limit: 100}
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
				if len(raw) > windowsnetworkcontext.MaxPageBytes {
					t.Fatal("page too large")
				}
				var p windowsnetworkcontext.Page
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
			q.Search = "::2049/"
			r, v := f.call(t, "POST", path, q, f.csrf, nil)
			if r.StatusCode != 200 || v["matchingCount"] != float64(1) || !strings.Contains(fmt.Sprint(v["rows"]), "::2049/") {
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
func TestWindowsNetworkContextOperatorFinalBoundaryHidesRows(t *testing.T) {
	for _, kind := range []string{"cursor-expiry", "logout", "session-expiry", "identity-revocation"} {
		t.Run(kind, func(t *testing.T) {
			f := newWindowsEventOperatorFixture(t)
			networkContextOperatorData(t, f, 1)
			path := "/api/devices/" + f.snap.Approval.DeviceID + "/windows-network-context/query"
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
			r, v := f.call(t, "POST", path, windowsnetworkcontext.Query{Kind: "all", Sort: "source-asc", Limit: 100}, f.csrf, nil)
			raw, _ := json.Marshal(v)
			if r.StatusCode == 200 || strings.Contains(string(raw), "2001:db8:") || v["rows"] != nil {
				t.Fatal("late boundary leaked rows", r.StatusCode, f.clock.count(), v)
			}
		})
	}
}
