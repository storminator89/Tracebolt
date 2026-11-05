package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"localrmm/internal/health"
	"localrmm/internal/operatorauth"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func maintenanceAPIFixture(t *testing.T) (operatorFixture, *fixtureHealthSource, string, string) {
	t.Helper()
	o := newOperatorFixture(t, time.Hour)
	id := "agent_" + strings.Repeat("a", 32)
	now := time.Now().UTC().Truncate(time.Second)
	source := &fixtureHealthSource{now: now, input: health.Input{DeviceID: id, Authorized: true}}
	o.app.health = &healthMonitor{store: o.app.store, source: source}
	_, login := o.login(t)
	return o, source, "/api/devices/" + id + "/health/maintenance-schedule", login["csrfToken"].(string)
}
func maintenanceAPICommand(now time.Time, n int, revision string, action, window string) map[string]any {
	id := fmt.Sprintf("maintenance_%032x", n)
	if window == "" {
		window = id
	}
	command := map[string]any{"requestId": id, "expectedRevision": revision, "action": action, "windowId": window, "startsAt": nil, "endsAt": nil}
	if action == "schedule" {
		command["startsAt"] = now.Add(5 * time.Minute).Format(time.RFC3339)
		command["endsAt"] = now.Add(20 * time.Minute).Format(time.RFC3339)
	}
	return command
}
func TestScheduledMaintenanceAPIWireAndExactReconciliation(t *testing.T) {
	o, source, path, csrf := maintenanceAPIFixture(t)
	response, v := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 200 || v["revision"] != "0" || v["canManage"] != true || v["remainingSlots"] != float64(64) || v["window"] != nil || v["lastRequest"] != nil {
		t.Fatal(response.StatusCode, v)
	}
	command := maintenanceAPICommand(source.now, 1, "0", "schedule", "")
	response, v = o.call(t, "POST", path, command, csrf, nil)
	if response.StatusCode != 200 || v["revision"] != "1" || v["remainingSlots"] != float64(63) || v["window"].(map[string]any)["state"] != "pending" {
		t.Fatal(response.StatusCode, v)
	}
	raw, _ := json.Marshal(v)
	t.Log("SCHEDULE_FIXTURE=" + string(raw))
	source.now = source.now.Add(time.Second)
	response, replay := o.call(t, "POST", path, command, csrf, nil)
	if response.StatusCode != 200 || replay["revision"] != "1" || replay["window"].(map[string]any)["endsAt"] != command["endsAt"] {
		t.Fatal("retry changed original window", replay)
	}
	altered := maintenanceAPICommand(source.now, 1, "0", "schedule", "")
	if response, _ = o.call(t, "POST", path, altered, csrf, nil); response.StatusCode != 409 {
		t.Fatal("altered retry")
	}
	if response, _ = o.call(t, "POST", strings.TrimSuffix(path, "-schedule"), map[string]int{"minutes": 0}, csrf, nil); response.StatusCode != 409 {
		t.Fatal("legacy generic stop bypass", response.StatusCode)
	}
	cancel := maintenanceAPICommand(source.now, 2, "1", "cancel", command["windowId"].(string))
	response, v = o.call(t, "POST", path, cancel, csrf, nil)
	if response.StatusCode != 200 || v["window"].(map[string]any)["state"] != "canceled" || v["revision"] != "2" {
		t.Fatal(response.StatusCode, v)
	}
	response, v = o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 200 || v["lastRequest"].(map[string]any)["requestId"] != cancel["requestId"] {
		t.Fatal("GET reconciliation", v)
	}
}
func TestScheduledMaintenanceAPIStatesPermissionAndCanonicalRoutes(t *testing.T) {
	o, source, path, csrf := maintenanceAPIFixture(t)
	command := maintenanceAPICommand(source.now, 1, "0", "schedule", "")
	for _, tc := range []struct {
		method, path string
		want         int
	}{{"HEAD", path, 405}, {"DELETE", path, 405}, {"GET", path + "?extra=1", 400}, {"GET", path + "/extra", 404}} {
		response, _ := o.call(t, tc.method, tc.path, nil, "", nil)
		if response.StatusCode != tc.want {
			t.Fatalf("%s %s got%d", tc.method, tc.path, response.StatusCode)
		}
	}
	if response, _ := o.call(t, "POST", path, command, "wrong", nil); response.StatusCode != 403 {
		t.Fatal("missing CSRF")
	}
	if response, _ := o.call(t, "POST", path, command, csrf, nil); response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	source.now = source.now.Add(5 * time.Minute)
	response, v := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 200 || v["window"].(map[string]any)["state"] != "active" {
		t.Fatal(v)
	}
	source.now = source.now.Add(15 * time.Minute)
	response, v = o.call(t, "GET", path, nil, "", nil)
	window := v["window"].(map[string]any)
	if response.StatusCode != 200 || window["state"] != "expired" || window["closedAt"] != window["endsAt"] {
		t.Fatal(v)
	}
	source.now = source.now.Add(-time.Minute)
	if response, _ = o.call(t, "GET", path, nil, "", nil); response.StatusCode != 409 {
		t.Fatal("rollback revived a spent window", response.StatusCode)
	}
	source.now = source.now.Add(time.Minute)
	source.input.Authorized = false
	if response, _ = o.call(t, "GET", path, nil, "", nil); response.StatusCode != 404 {
		t.Fatal("authority loss", response.StatusCode)
	}
	named, _ := namedOperatorFixture(t)
	named.app.health = o.app.health
	_, login := named.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	source.input.Authorized = true
	response, v = named.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 200 || v["canManage"] != false {
		t.Fatal("named read", response.StatusCode, v)
	}
	if response, _ = named.call(t, "POST", path, command, login["csrfToken"].(string), nil); response.StatusCode != 403 {
		t.Fatal("maintenance capability expanded")
	}
}

type endingMaintenanceSource struct {
	fixtureHealthSource
	before func()
}

func (f *endingMaintenanceSource) HealthInputs(ctx context.Context, s map[string][]string, now time.Time) ([]health.Input, error) {
	if f.before != nil {
		f.before()
	}
	return f.fixtureHealthSource.HealthInputs(ctx, s, now)
}
func TestScheduledMaintenanceAPINoCommitAfterSessionExpiryDuringAdmission(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	id := "agent_" + strings.Repeat("a", 32)
	now := time.Now().UTC().Truncate(time.Second)
	var authNow atomic.Int64
	authNow.Store(now.UnixNano())
	auth, e := operatorauth.New(operatorauth.Config{PasswordHash: testOperatorHash(), TTL: time.Minute, Now: func() time.Time { return time.Unix(0, authNow.Load()).UTC() }})
	if e != nil {
		t.Fatal(e)
	}
	o.server.Config.Handler.(*operatorHandler).auth = auth
	_, login := o.login(t)
	source := &endingMaintenanceSource{fixtureHealthSource: fixtureHealthSource{now: now, input: health.Input{DeviceID: id, Authorized: true}}, before: func() { authNow.Store(now.Add(time.Minute).UnixNano()) }}
	o.app.health = &healthMonitor{store: o.app.store, source: source}
	response, _ := o.call(t, "POST", "/api/devices/"+id+"/health/maintenance-schedule", maintenanceAPICommand(now, 1, "0", "schedule", ""), login["csrfToken"].(string), nil)
	if response.StatusCode != 401 {
		t.Fatal("expired commit", response.StatusCode)
	}
	state, e := o.app.store.HealthState(context.Background(), id)
	if e != nil || state.Schedule != nil {
		t.Fatal("expired mutation committed", e)
	}
}

func TestScheduledMaintenanceAPIStrictSixFieldCommand(t *testing.T) {
	o, source, path, csrf := maintenanceAPIFixture(t)
	valid, _ := json.Marshal(maintenanceAPICommand(source.now, 1, "0", "schedule", ""))
	base := string(valid)
	for _, raw := range []string{strings.Replace(base, `"expectedRevision":"0"`, `"expectedRevision":"00"`, 1), strings.Replace(base, `"requestId":`, `"extra":null,"requestId":`, 1), strings.Replace(base, `"requestId":`, `"requestId":"maintenance_11111111111111111111111111111111","requestId":`, 1), strings.Replace(base, `"expectedRevision":"0"`, `"expectedRevision":0`, 1), strings.Replace(base, `"windowId":"maintenance_00000000000000000000000000000001"`, `"windowId":null`, 1), strings.Replace(base, `Z"`, `+00:00"`, 1), base + ` {}`, strings.Repeat(" ", 2049) + base} {
		response, _ := o.call(t, "POST", path, nil, csrf, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(raw))
			r.ContentLength = int64(len(raw))
		})
		want := 400
		if len(raw) > 2048 {
			want = 413
		}
		if response.StatusCode != want {
			t.Fatalf("strict framing got%d want%d body%s", response.StatusCode, want, raw)
		}
	}
	response, view := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 200 || view["revision"] != "0" {
		t.Fatal("malformed command committed", view)
	}
}
