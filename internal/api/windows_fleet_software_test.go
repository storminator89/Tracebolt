package api

import (
	"encoding/json"
	"localrmm/internal/windowsfullsoftware"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWindowsFleetSoftwareReadRoute(t *testing.T) {
	path := "/api/fleet/windows-software/query"
	if !namedReadRoute(httptest.NewRequest("POST", path, nil)) {
		t.Fatal("named read capability excluded")
	}
	for _, target := range []string{path + "?name=private", path + "/extra", "/api/fleet/windows-software/install"} {
		if namedReadRoute(httptest.NewRequest("POST", target, nil)) {
			t.Fatal("unreviewed route granted", target)
		}
	}
	h := &operatorHandler{}
	for _, tc := range []struct {
		method, path string
		want         int
	}{{"GET", path, 405}, {"POST", path + "?name=private", 404}, {"POST", path, 404}} {
		w := httptest.NewRecorder()
		h.windowsFleetSoftwareQuery(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.want {
			t.Fatalf("%s %s: %d", tc.method, tc.path, w.Code)
		}
	}
}

// This existing TLS fixture is a hosted integration gate; inert source/store
// checks do not claim that listeners or browsers ran in a restricted executor.
func TestWindowsFleetSoftwareProtectedOperatorQuery(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{true: "named", false: "shared"}[named], func(t *testing.T) {
			f := newWindowsEventOperatorFixtureFor(t, named)
			fullSoftwareOperatorData(t, f, 24)
			path := "/api/fleet/windows-software/query"
			q := windowsfullsoftware.FleetQuery{Name: "privatesyntheticsoftware", Version: "000"}
			for _, tc := range []struct {
				csrf   string
				change func(*http.Request)
			}{{"", nil}, {f.csrf, func(r *http.Request) { r.Header.Set("Origin", "https://wrong.example") }}} {
				if r, _ := f.call(t, "POST", path, q, tc.csrf, tc.change); r.StatusCode != 403 {
					t.Fatal("request guard", r.StatusCode)
				}
			}
			r, v := f.call(t, "POST", path, q, f.csrf, nil)
			if r.StatusCode != 200 {
				t.Fatal(r.StatusCode, v)
			}
			raw, _ := json.Marshal(v)
			var p windowsfullsoftware.FleetPage
			if json.Unmarshal(raw, &p) != nil || len(raw) > windowsfullsoftware.MaxPageBytes || p.TotalDevices != 1 || len(p.Items) != 1 || p.Items[0].MatchingCount != 24 || len(p.Items[0].Rows) != 3 {
				t.Fatal("fleet response", v)
			}
			if strings.Contains(string(raw), "RosterDigest") || strings.Contains(string(raw), "SessionID") || strings.Contains(string(raw), f.token) {
				t.Fatal("server-only guard exposed")
			}
			q.Cursor = p.Items[0].DetailCursor
			r, v = f.call(t, "POST", path, q, f.csrf, nil)
			if r.StatusCode != 200 || v["mode"] != "device" {
				t.Fatal("exact drill-down", r.StatusCode, v)
			}
			f.server.Config.Handler.(*operatorHandler).auth.Logout(f.token)
			if r, v = f.call(t, "POST", path, q, f.csrf, nil); r.StatusCode != 401 || v["items"] != nil {
				t.Fatal("logout exposed software", r.StatusCode, v)
			}
		})
	}
}
