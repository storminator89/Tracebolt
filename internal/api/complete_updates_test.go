package api

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/model"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompleteUpdatesOperatorGuardsAndBoundedUnknown(t *testing.T) {
	o := newOperatorFixture(t, time.Minute)
	id := "agent_" + strings.Repeat("1", 32)
	o.app.mu.Lock()
	o.app.lanDevices = func() ([]model.Device, error) { return []model.Device{{ID: id}}, nil }
	o.app.mu.Unlock()
	path := "/api/devices/" + id + "/inventory/complete-updates"
	response, _ := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 401 {
		t.Fatal("anonymous metadata exposed")
	}
	o.login(t)
	response, value := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 200 || value["schemaVersion"] != "tracebolt.complete-update-view.v1" || value["deviceId"] != id || value["status"] != "not_configured" || value["complete"] != nil || value["transfer"] != nil || value["failure"] != nil {
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
func TestCompleteUpdatesRechecksSessionAfterRead(t *testing.T) {
	app := setup(t)
	id := "agent_" + strings.Repeat("2", 32)
	var active atomic.Bool
	active.Store(true)
	app.mu.Lock()
	app.lanDevices = func() ([]model.Device, error) { active.Store(false); return []model.Device{{ID: id}}, nil }
	app.mu.Unlock()
	h := operatorHandler{app: app}
	r := httptest.NewRequest("GET", "/api/devices/"+id+"/inventory/complete-updates", nil)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{active: active.Load}))
	w := httptest.NewRecorder()
	h.completeUpdates(w, r)
	if w.Code != 401 || strings.Contains(w.Body.String(), "tracebolt.cached-updates-view") {
		t.Fatal("expired session exposed metadata")
	}
}

func TestCompleteUpdatesUnavailableKeepsExplicitFailure(t *testing.T) {
	at := time.Date(2026, 10, 5, 5, 0, 0, 0, time.UTC)
	view, e := completeUpdatesView(enrollmentstore.CompleteUpdatesStatus{DeviceID: "agent_fixture", ServerNow: at.Add(time.Second), Status: "unavailable", Failure: &enrollmentstore.InventoryFailureReceipt{Failure: enrollmentstore.InventoryFailureReport{Sequence: 1, GenerationID: "sample_" + strings.Repeat("a", 32), AttemptedAt: at, Reason: "source_missing"}, ReceivedAt: at.Add(time.Second)}})
	if e != nil || view.Status != "unavailable" || view.Failure == nil || view.Failure.Reason != "source_missing" || view.Complete != nil {
		t.Fatal("source failure became API error or invented complete", e)
	}
}
