package api

import (
	"context"
	"localrmm/internal/model"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestResourceHistoryOperatorBoundary(t *testing.T) {
	o := newOperatorFixture(t, time.Minute)
	id := "agent_" + strings.Repeat("1", 32)
	o.app.mu.Lock()
	o.app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: id}}, nil }
	o.app.mu.Unlock()
	path := "/api/devices/" + id + "/resource-history"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous history exposed")
	}
	o.login(t)
	r, v := o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || v["schemaVersion"] != "tracebolt.resource-history.v1" || v["deviceId"] != id || v["status"] != "not_configured" || len(v["points"].([]any)) != 0 {
		t.Fatal("unconfigured result", r.StatusCode, v)
	}
	for _, tc := range []struct {
		method, path string
		change       func(*http.Request)
		want         int
	}{{"POST", path, nil, 405}, {"GET", path + "?", nil, 400}, {"GET", path + "?range=99", nil, 400}, {"GET", path + "/extra", nil, 404}, {"GET", strings.Replace(path, id, "hostname", 1), nil, 404}, {"GET", path, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }, 403}, {"GET", path, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403}} {
		r, _ := o.call(t, tc.method, tc.path, nil, "", tc.change)
		if r.StatusCode != tc.want {
			t.Fatalf("%s %s got %d want %d", tc.method, tc.path, r.StatusCode, tc.want)
		}
	}
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("cacheable protected history")
	}
}
func TestResourceHistorySessionRecheckAndNamedRead(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	id := namedDeviceID
	o.app.mu.Lock()
	o.app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: id}}, nil }
	o.app.mu.Unlock()
	if r, _ := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil); r.StatusCode != 200 {
		t.Fatal("login")
	}
	if r, _ := o.call(t, "GET", "/api/devices/"+id+"/resource-history", nil, "", nil); r.StatusCode != 200 {
		t.Fatal("named read blocked", r.StatusCode)
	}
	app := setup(t)
	var active atomic.Bool
	active.Store(true)
	app.lanDevices = func() ([]model.Device, error) { active.Store(false); return []model.Device{{ID: id}}, nil }
	h := operatorHandler{app: app}
	r := httptest.NewRequest("GET", "/api/devices/"+id+"/resource-history", nil)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{active: active.Load}))
	w := httptest.NewRecorder()
	h.resourceHistory(w, r)
	if w.Code != 401 || strings.Contains(w.Body.String(), "tracebolt.resource-history") {
		t.Fatal("expired session leaked history")
	}
}

func TestResourceHistoryIsAbsentFromDevelopmentAPI(t *testing.T) {
	app := setup(t)
	r := httptest.NewRequest("GET", "/api/devices/"+namedDeviceID+"/resource-history", nil)
	w := httptest.NewRecorder()
	app.api(w, r)
	if w.Code != 404 || strings.Contains(w.Body.String(), "tracebolt.resource-history") {
		t.Fatal("history exposed outside operator boundary")
	}
}
