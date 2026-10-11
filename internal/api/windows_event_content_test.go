package api

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestWindowsEventOperatorTLSRoutesAndNamedReadExclusion(t *testing.T) {
	o := newOperatorFixture(t, time.Minute)
	path := "/api/devices/agent_" + strings.Repeat("1", 32) + "/windows-event-content"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous event view")
	}
	o.login(t)
	for _, tc := range []struct {
		method, path string
		change       func(*http.Request)
		want         int
	}{{"GET", path, nil, 409}, {"GET", path + "?recordId=secret", nil, 400}, {"POST", path, nil, 405}, {"GET", path + "/create", nil, 405}, {"POST", path + "/arbitrary", nil, 404}, {"GET", path, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }, 403}, {"GET", path, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403}} {
		r, _ := o.call(t, tc.method, tc.path, nil, "", tc.change)
		if r.StatusCode != tc.want {
			t.Fatalf("%s %s got %d want %d", tc.method, tc.path, r.StatusCode, tc.want)
		}
		if r.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable private API")
		}
	}
	for _, suffix := range []string{"/create", "/cancel", "/query"} {
		r, _ := http.NewRequest("POST", "https://manager.example"+path+suffix, nil)
		if namedReadRoute(r) {
			t.Fatal("named read account got content authority")
		}
	}
}
func TestWindowsEventSessionBindingIsDomainSeparatedOpaque(t *testing.T) {
	a := windowsEventSessionBinding("session-secret")
	if len(a) != 64 || strings.Contains(a, "session-secret") || a == windowsEventSessionBinding("other") {
		t.Fatal("unsafe session binding")
	}
}
