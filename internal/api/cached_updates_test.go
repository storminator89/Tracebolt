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

func TestCachedUpdatesOperatorGuardsAndBoundedUnknown(t *testing.T) {
	o := newOperatorFixture(t, time.Minute)
	id := "agent_" + strings.Repeat("1", 32)
	o.app.mu.Lock()
	o.app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: id}}, nil }
	o.app.mu.Unlock()
	path := "/api/devices/" + id + "/inventory/cached-updates"
	response, _ := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 401 {
		t.Fatal("anonymous metadata exposed")
	}
	o.login(t)
	response, value := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 200 || value["schemaVersion"] != "tracebolt.cached-updates-view.v1" || value["deviceId"] != id || value["status"] != "unknown" || value["latest"] != nil || value["sequence"] != nil || value["receivedAt"] != nil || value["expiresAt"] != nil {
		t.Fatal("safe unavailable DTO", response.StatusCode, value)
	}
	for _, tc := range []struct {
		method, path string
		change       func(*http.Request)
		want         int
	}{
		{"POST", path, nil, 405}, {"GET", path + "?leak=1", nil, 400}, {"GET", path + "/extra", nil, 404},
		{"GET", strings.Replace(path, id, "reported-host", 1), nil, 404},
		{"GET", path, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }, 403},
		{"GET", path, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
	} {
		response, _ := o.call(t, tc.method, tc.path, nil, "", tc.change)
		if response.StatusCode != tc.want {
			t.Fatalf("guard %s %s got%d", tc.method, tc.path, response.StatusCode)
		}
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("metadata response cacheable")
	}
}
func TestCachedUpdatesRechecksSessionAfterRead(t *testing.T) {
	app := setup(t)
	id := "agent_" + strings.Repeat("2", 32)
	var active atomic.Bool
	active.Store(true)
	app.mu.Lock()
	app.lanDevices = func() ([]model.Device, error) { active.Store(false); return []model.Device{{ID: id}}, nil }
	app.mu.Unlock()
	h := operatorHandler{app: app}
	r := httptest.NewRequest("GET", "/api/devices/"+id+"/inventory/cached-updates", nil)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{active: active.Load}))
	w := httptest.NewRecorder()
	h.cachedUpdates(w, r)
	if w.Code != 401 || strings.Contains(w.Body.String(), "tracebolt.cached-updates-view") {
		t.Fatal("expired session exposed metadata")
	}
}
