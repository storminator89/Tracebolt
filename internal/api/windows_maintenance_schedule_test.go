package api

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

const maintenanceSchedulePath = "/api/fleet/windows-maintenance-schedule"

func readMaintenanceSchedule(t *testing.T, o operatorFixture) windowsMaintenanceScheduleView {
	t.Helper()
	r, value := o.call(t, "GET", maintenanceSchedulePath, nil, "", nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, value)
	}
	raw, _ := json.Marshal(value)
	var v windowsMaintenanceScheduleView
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("decode")
	}
	return v
}
func TestWindowsMaintenanceScheduleAPILifecycleAndLegacyIsolation(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := incidentInboxFixture(t, o)
	if r, _ := o.call(t, "GET", maintenanceSchedulePath, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous")
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	before := readMaintenance(t, o)
	incidents, _ := m.store.WindowsIncidentSnapshot(context.Background())
	v := readMaintenanceSchedule(t, o)
	if len(v.Targets) != 6 || v.Targets[0].RemainingSlots != 16 {
		t.Fatal(v)
	}
	target := v.Targets[0]
	body := map[string]any{"key": target.Key, "revision": 0, "startsAt": f.now.Add(5 * time.Minute).Format(time.RFC3339Nano), "endsAt": f.now.Add(10 * time.Minute).Format(time.RFC3339Nano), "intent": "planned-work"}
	if r, _ := o.call(t, "POST", maintenanceSchedulePath+"/schedule", body, "", nil); r.StatusCode != 403 {
		t.Fatal("csrf")
	}
	if r, value := o.call(t, "POST", maintenanceSchedulePath+"/schedule", body, csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, value)
	}
	v = readMaintenanceSchedule(t, o)
	if v.Targets[0].Revision != 1 || v.Targets[0].RemainingSlots != 15 {
		t.Fatal(v)
	}
	if r, _ := o.call(t, "POST", maintenanceSchedulePath+"/schedule", body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("replay")
	}
	if after := readMaintenance(t, o); !reflect.DeepEqual(before, after) {
		t.Fatal("legacy v1 changed")
	}
	after, _ := m.store.WindowsIncidentSnapshot(context.Background())
	if !reflect.DeepEqual(incidents, after) {
		t.Fatal("incident mutation")
	}
	cancel := map[string]any{"key": target.Key, "revision": 1, "windowId": 1}
	if r, value := o.call(t, "POST", maintenanceSchedulePath+"/cancel", cancel, csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, value)
	}
	v = readMaintenanceSchedule(t, o)
	if v.Targets[0].Windows[0].CancelledAt == nil {
		t.Fatal("cancel not saved")
	}
	f.now = f.now.Add(time.Minute)
	body["revision"] = 2
	body["startsAt"] = f.now.Add(2 * time.Minute).Format(time.RFC3339Nano)
	body["endsAt"] = f.now.Add(5 * time.Minute).Format(time.RFC3339Nano)
	if r, value := o.call(t, "POST", maintenanceSchedulePath+"/schedule", body, csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, value)
	}
	f.now = f.now.Add(3 * time.Minute)
	cancel["revision"] = 3
	cancel["windowId"] = 3
	if r, _ := o.call(t, "POST", maintenanceSchedulePath+"/cancel", cancel, csrf, nil); r.StatusCode != 409 {
		t.Fatal("late cancel")
	}
	if r, value := o.call(t, "POST", maintenanceSchedulePath+"/end", cancel, csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, value)
	}
}
func TestWindowsMaintenanceScheduleAPIStrictInputs(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	_, f := incidentInboxFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	v := readMaintenanceSchedule(t, o)
	body := map[string]any{"key": v.Targets[0].Key, "revision": 0, "startsAt": f.now.Add(5 * time.Minute).Format(time.RFC3339Nano), "endsAt": f.now.Add(10 * time.Minute).Format(time.RFC3339Nano), "intent": "planned-work"}
	for _, kind := range []string{"extra", "offset", "fraction", "missing", "null"} {
		t.Run(kind, func(t *testing.T) {
			b := map[string]any{}
			for k, x := range body {
				b[k] = x
			}
			switch kind {
			case "extra":
				b["arbitrary"] = true
			case "offset":
				b["startsAt"] = strings.Replace(b["startsAt"].(string), "Z", "+00:00", 1)
			case "fraction":
				b["startsAt"] = strings.Replace(b["startsAt"].(string), "Z", ".000Z", 1)
			case "missing":
				delete(b, "startsAt")
			case "null":
				b["startsAt"] = nil
			}
			if r, value := o.call(t, "POST", maintenanceSchedulePath+"/schedule", b, csrf, nil); r.StatusCode != 400 {
				t.Fatal(r.StatusCode, value)
			}
		})
	}
	for _, path := range []string{maintenanceSchedulePath + "?", maintenanceSchedulePath + "?x=y", maintenanceSchedulePath + "/start"} {
		r, _ := o.call(t, "GET", path, nil, "", nil)
		if r.StatusCode == 200 {
			t.Fatal("noncanonical", path)
		}
	}
}

func TestWindowsMaintenanceScheduleNamedReadAndCurrentIdentity(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	_, f := installCapacityFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	v := readMaintenanceSchedule(t, o)
	target := v.Targets[0]
	body := map[string]any{"key": target.Key, "revision": 0, "startsAt": f.now.Add(5 * time.Minute).Format(time.RFC3339Nano), "endsAt": f.now.Add(10 * time.Minute).Format(time.RFC3339Nano), "intent": "planned-work"}
	if r, result := o.call(t, "POST", maintenanceSchedulePath+"/schedule", body, csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, result)
	}
	f.inputs[0].AuthorityUntil = f.inputs[0].AuthorityUntil.Add(time.Hour)
	renewed := readMaintenanceSchedule(t, o).Targets[0]
	if renewed.Key != target.Key || renewed.Revision != 1 {
		t.Fatal("renewal lost original identity")
	}
	f.inputs[0].CertificateHash = strings.Repeat("e", 64)
	replacement := readMaintenanceSchedule(t, o).Targets[0]
	if replacement.Key == target.Key || replacement.Revision != 0 || len(replacement.Windows) != 0 {
		t.Fatal("replacement inherited")
	}
	if r, _ := o.call(t, "POST", maintenanceSchedulePath+"/schedule", body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("stale target")
	}
	f.inputs[0].Authorized = false
	if len(readMaintenanceSchedule(t, o).Targets) != 0 {
		t.Fatal("revoked rows exposed")
	}
	named, _ := namedOperatorFixture(t)
	_, nf := installCapacityFixture(t, named)
	_, session := named.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	read := readMaintenanceSchedule(t, named)
	body["key"] = read.Targets[0].Key
	body["startsAt"] = nf.now.Add(5 * time.Minute).Format(time.RFC3339Nano)
	body["endsAt"] = nf.now.Add(10 * time.Minute).Format(time.RFC3339Nano)
	if r, _ := named.call(t, "POST", maintenanceSchedulePath+"/schedule", body, session["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("named reader mutated schedule")
	}
}
