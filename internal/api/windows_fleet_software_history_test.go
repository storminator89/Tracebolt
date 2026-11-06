package api

import (
	"encoding/json"
	"localrmm/internal/windowsfullsoftware"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWindowsFleetSoftwareHistoryUsesExistingProtectedReadRoute(t *testing.T) {
	const path = "/api/fleet/windows-software/query"
	if !namedReadRoute(httptest.NewRequest("POST", path, nil)) {
		t.Fatal("existing route rejected")
	}
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "shared", true: "named"}[named], func(t *testing.T) {
			f := newWindowsEventOperatorFixtureFor(t, named)
			softwareHistoryOperatorData(t, f)
			q := windowsfullsoftware.FleetQuery{View: "history"}
			if r, old := f.call(t, "POST", path, windowsfullsoftware.FleetQuery{Name: "Private"}, f.csrf, nil); r.StatusCode != 200 || old["schemaVersion"] != windowsfullsoftware.FleetPageVersion {
				t.Fatal("legacy three-field query changed", r.StatusCode, old)
			}

			for _, tc := range []struct {
				csrf   string
				change func(*http.Request)
			}{{"", nil}, {f.csrf, func(r *http.Request) { r.Header.Set("Origin", "https://wrong.example") }}} {
				if r, _ := f.call(t, "POST", path, q, tc.csrf, tc.change); r.StatusCode != 403 {
					t.Fatal("request guards", r.StatusCode)
				}
			}
			r, v := f.call(t, "POST", path, q, f.csrf, nil)
			var p windowsfullsoftware.FleetHistoryPage
			raw, _ := json.Marshal(v)
			if r.StatusCode != 200 || json.Unmarshal(raw, &p) != nil || p.SchemaVersion != windowsfullsoftware.FleetHistoryPageVersion || len(p.Items) != 1 || p.Items[0].History.MatchingCount != 2 {
				t.Fatal("history projection", r.StatusCode, v)
			}
			if strings.Contains(string(raw), "RosterDigest") || strings.Contains(string(raw), "SessionID") || strings.Contains(string(raw), f.token) {
				t.Fatal("server guard leakage")
			}
			if p.Items[0].History.NextCursor != "" || p.Items[0].History.CursorExpiresAt == nil || !p.Items[0].History.CursorExpiresAt.Equal(*p.CursorExpiresAt) {
				t.Fatal("nested cross-domain continuation")
			}
			for _, bad := range []any{windowsfullsoftware.FleetQuery{View: "history", Version: "x"}, map[string]any{"name": "Private", "version": "", "cursor": "", "view": ""}, map[string]any{"name": "Private", "version": "", "cursor": "", "view": nil}, map[string]any{"name": "", "version": "", "cursor": "", "view": "history", "install": true}} {
				if r, _ := f.call(t, "POST", path, bad, f.csrf, nil); r.StatusCode != 400 {
					t.Fatal("unexpected query accepted", r.StatusCode)
				}
			}
			q.Cursor = p.Items[0].DetailCursor
			if r, _ := f.call(t, "POST", "/api/devices/"+p.Items[0].DeviceID+"/windows-software-history/query", windowsfullsoftware.Query{Sort: "observed-desc", Limit: 20, Cursor: q.Cursor}, f.csrf, nil); r.StatusCode == 200 {
				t.Fatal("fleet cursor accepted by ordinary history")
			}
			f.server.Config.Handler.(*operatorHandler).auth.Logout(f.token)
			if r, v := f.call(t, "POST", path, q, f.csrf, nil); r.StatusCode != 401 || v["items"] != nil {
				t.Fatal("logout exposed history", r.StatusCode, v)
			}
		})
	}
}
