package api

import (
	"context"
	"errors"
	"localrmm/internal/health"
	"localrmm/internal/model"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fixtureHealthSource struct {
	now   time.Time
	input health.Input
	err   error
}

func (f *fixtureHealthSource) Now() time.Time { return f.now }
func (f *fixtureHealthSource) HealthInputs(context.Context, map[string][]string, time.Time) ([]health.Input, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []health.Input{f.input}, nil
}
func TestHealthOperatorAuthenticationCSRFAndDeviceAuthority(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	id := "agent_" + strings.Repeat("a", 32)
	path := "/api/devices/" + id + "/health"
	now := time.Now().UTC()
	source := &fixtureHealthSource{now: now, input: health.Input{DeviceID: id, Authorized: true}}
	o.app.health = &healthMonitor{store: o.app.store, source: source}
	response, _ := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 401 {
		t.Fatal("unauthenticated history readable")
	}
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	response, view := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 200 || view["status"] != "unknown" || len(view["checks"].([]any)) != 2 {
		t.Fatal(response.StatusCode, view)
	}
	response, _ = o.call(t, "POST", path+"/maintenance", map[string]int{"minutes": 60}, "", nil)
	if response.StatusCode != 403 {
		t.Fatal("missing CSRF accepted")
	}
	response, view = o.call(t, "POST", path+"/maintenance", map[string]int{"minutes": 60}, csrf, nil)
	if response.StatusCode != 200 || view["status"] != "maintenance" {
		t.Fatal(response.StatusCode, view)
	}
	response, _ = o.call(t, "POST", path+"/maintenance", map[string]int{"minutes": 1440}, csrf, nil)
	if response.StatusCode != 400 {
		t.Fatal("unbounded maintenance accepted")
	}
	response, _ = o.call(t, "POST", path+"/services", map[string]any{"services": []string{"sshd.service;reboot"}}, csrf, nil)
	if response.StatusCode != 400 {
		t.Fatal("invalid service accepted")
	}
	response, view = o.call(t, "POST", path+"/services", map[string]any{"services": []string{"sshd.service"}}, csrf, nil)
	if response.StatusCode != 200 || len(view["checks"].([]any)) != 3 {
		t.Fatal(response.StatusCode, view)
	}
	response, _ = o.call(t, "GET", "/api/devices/agent_"+strings.Repeat("b", 32)+"/health", nil, "", nil)
	if response.StatusCode != 404 {
		t.Fatal("another device accessible")
	}
	source.input.Authorized = false
	response, _ = o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 404 {
		t.Fatal("revoked history accessible")
	}
	response, _ = o.call(t, "POST", path+"/services", map[string]any{"services": []string{}}, csrf, nil)
	if response.StatusCode != 404 {
		t.Fatal("revoked settings mutable")
	}
	response, _ = o.call(t, "GET", path+"/acknowledge", nil, "", nil)
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal("wrong method accepted")
	}
}
func TestHealthMonitorPersistsWithoutUIAndPreservesHistoryOnSourceFailure(t *testing.T) {
	app := setup(t)
	now := time.Now().UTC()
	value := 95.0
	id := "agent_" + strings.Repeat("a", 32)
	f := &fixtureHealthSource{}
	m := &healthMonitor{store: app.store, source: f}
	for i := 0; i <= 4; i++ {
		at := now.Add(time.Duration(i) * 30 * time.Second)
		f.now = at
		f.input = health.Input{DeviceID: id, Authorized: true, ReceivedAt: at, Disk: model.Metric{Value: &value, Unit: "%", Quality: "healthy", CollectedAt: at}}
		if e := m.evaluate(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	s, e := app.store.HealthState(context.Background(), id)
	if e != nil || len(s.Incidents) != 1 {
		t.Fatal("background did not create incident", e)
	}
	f.err = errors.New("source temporarily unavailable")
	if m.evaluate(context.Background()) == nil {
		t.Fatal("source failure swallowed")
	}
	after, _ := app.store.HealthState(context.Background(), id)
	if len(after.Incidents) != 1 || after.Incidents[0].ID != s.Incidents[0].ID {
		t.Fatal("read error lost history")
	}
	app.health = m
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = app.RunHealthMonitor(ctx, nil); e != nil {
		t.Fatal("monitor did not stop")
	}
}
