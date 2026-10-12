package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/store"
	"localrmm/internal/windowscontact"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

const notificationsPath = "/api/fleet/windows-notifications"

func readNotifications(t *testing.T, o operatorFixture) windowsNotificationView {
	t.Helper()
	r, value := o.call(t, "GET", notificationsPath, nil, "", nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, value)
	}
	raw, _ := json.Marshal(value)
	var v windowsNotificationView
	if e := json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func TestWindowsNotificationsHTTPExplicitSourceDestinationAndUnchangedV1(t *testing.T) {
	o, settings := alarmSettingsOperatorFixture(t, false, false)
	m, f := incidentInboxFixture(t, o)
	if r, _ := o.call(t, "GET", notificationsPath, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous read")
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	initial := readNotifications(t, o)
	if len(initial.Targets) != 5 || initial.DeliveryEnabled {
		t.Fatal(initial)
	}
	_, v := o.call(t, "GET", "/api/alerts/settings", nil, "", nil)
	if r, v := o.call(t, "POST", "/api/alerts/settings", alarmSettingsInput(v["revision"].(string)), csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	view := readNotifications(t, o)
	if !view.DeliveryEnabled || view.DestinationHost != "receiver.example.test" {
		t.Fatal(view)
	}
	row := view.Targets[2]
	body := map[string]any{"key": row.Key, "revision": row.Revision, "enabled": true, "destinationBinding": view.DestinationBinding, "payloadAcknowledged": true}
	before, e := m.store.WindowsIncidentSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []struct {
		name   string
		mutate func(*http.Request)
		code   int
	}{{"csrf", func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, 403}, {"origin", func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }, 403}, {"query", func(r *http.Request) { r.URL.RawQuery = "all=1" }, 400}} {
		if r, _ := o.call(t, "POST", notificationsPath+"/policy", body, csrf, change.mutate); r.StatusCode != change.code {
			t.Fatal(change.name, r.StatusCode)
		}
	}
	body["payloadAcknowledged"] = false
	if r, _ := o.call(t, "POST", notificationsPath+"/policy", body, csrf, nil); r.StatusCode != 400 {
		t.Fatal("implicit Windows sharing")
	}
	body["payloadAcknowledged"] = true
	if r, v := o.call(t, "POST", notificationsPath+"/policy", body, csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	if r, _ := o.call(t, "POST", notificationsPath+"/policy", body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("replayed source enablement")
	}
	view = readNotifications(t, o)
	if !view.Targets[2].Enabled || !view.Targets[2].Effective || view.Counts.Queued != 0 {
		t.Fatal("implicit history broadcast", view)
	}
	after, e := m.store.WindowsIncidentSnapshot(context.Background())
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("source changed v1 histories", e)
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), "secret-fixture") || strings.Contains(string(raw), "invitationId") || strings.Contains(string(raw), "certificateHash") {
		t.Fatal("private material leaked")
	}
	// The same hostname with a fresh destination generation requires new review.
	current, e := settings.View(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = settings.Change(context.Background(), alarmdelivery.SettingsChange{ExpectedRevision: current.Revision, Operation: "replace", Endpoint: "https://receiver.example.test/other", PayloadSharingAcknowledged: true}, "shared-administrator"); e != nil {
		t.Fatal(e)
	}
	view = readNotifications(t, o)
	if view.Targets[2].Effective || !view.Targets[2].Enabled {
		t.Fatal("source silently transferred to changed recipient")
	}
	body["revision"] = uint64(1)
	if r, _ := o.call(t, "POST", notificationsPath+"/policy", body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("stale destination accepted")
	}
	f.inputs[0].InvitationID = "invite_" + strings.Repeat("a", 32)
	view = readNotifications(t, o)
	if view.Targets[2].Revision != 0 || view.Targets[2].Enabled || view.Targets[2].Key == row.Key {
		t.Fatal("replacement inherited policy")
	}
}
func TestWindowsNotificationsNamedAlarmAdminReadOnly(t *testing.T) {
	o, _ := alarmSettingsOperatorFixture(t, true, true)
	installCapacityFixture(t, o)
	_, session := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	view := readNotifications(t, o)
	body := map[string]any{"key": view.Targets[0].Key, "revision": 0, "enabled": true, "destinationBinding": strings.Repeat("a", 64), "payloadAcknowledged": true}
	if r, _ := o.call(t, "POST", notificationsPath+"/policy", body, session["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("named alarm permission widened Windows source grant")
	}
}

type notificationFakeTransport struct{ calls []alarmdelivery.Payload }

func (f *notificationFakeTransport) Send(_ context.Context, p alarmdelivery.Payload) alarmdelivery.Result {
	f.calls = append(f.calls, p)
	return alarmdelivery.Result{Outcome: alarmdelivery.Accepted, Code: "provider_accepted"}
}
func TestWindowsNotificationsQueueAdapterUsesExistingWorkerWithoutLinuxAdmission(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installCapacityFixture(t, o)
	ctx := context.Background()
	binding := alarmdelivery.Binding{ManagerInstanceID: "fixture", Profile: "tls", DestinationID: "fixture", Generation: "one", Fingerprint: strings.Repeat("a", 64)}
	q := NewWindowsNotificationQueue(o.app.store, f)
	if e := q.ConfigureAlarms(ctx, &binding, f.now); e != nil {
		t.Fatal(e)
	}
	target := maintenanceTarget(f.inputs[0], "disk")
	if _, e := q.ChangeWindowsNotificationPolicy(ctx, target, 0, true, binding.Key(), f.Now, func(time.Time) error { return nil }); e != nil {
		t.Fatal(e)
	}
	openCapacityFixture(t, m, f)
	transport := &notificationFakeTransport{}
	worker, e := alarmdelivery.NewWorker(q, binding, transport, f.Now)
	if e != nil {
		t.Fatal(e)
	}
	if e = worker.Step(ctx); e != nil {
		t.Fatal(e)
	}
	if len(transport.calls) != 1 || transport.calls[0].SchemaVersion != store.WindowsNotificationSchema {
		t.Fatal("explicit Windows dispatch adapter", transport.calls)
	}
	status, e := o.app.store.AlarmStatus(ctx)
	if e != nil || status.ProviderAccepted != 0 || status.Queued != 0 {
		t.Fatal("Windows contaminated Linux counters", status, e)
	}
	windows, e := o.app.store.WindowsNotifications(ctx)
	if e != nil || windows.Counts.ProviderAccepted != 1 {
		t.Fatal(windows, e)
	}
}

func (f *fixtureWindowsCapacitySource) WithWindowsNotificationAuthority(ctx context.Context, expected windowscontact.Input, fn func(func(time.Time) error) error) error {
	return f.WithWindowsIncidentAuthority(ctx, expected, func(authority func(time.Time) error) error {
		guard := func(at time.Time) error {
			for _, in := range f.inputs {
				if in.DeviceID == expected.DeviceID && (in.Sequence != expected.Sequence || !in.ReceivedAt.Equal(expected.ReceivedAt)) {
					return store.ErrWindowsNotificationConflict
				}
			}
			return authority(at)
		}
		if e := guard(f.now); e != nil {
			return e
		}
		return fn(guard)
	})
}
