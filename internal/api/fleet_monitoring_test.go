package api

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fixtureMonitoringSource struct {
	*fixtureFleetGroupSource
	reads, leases int
	onGuard       func(int)
}

func (f *fixtureMonitoringSource) WindowsCapacityInputs(context.Context, time.Time) ([]windowscapacity.Input, error) {
	f.reads++
	out := []windowscapacity.Input{}
	for _, in := range f.inputs {
		row := capacityFixtureInput(f.now)
		row.Input = in
		row.CPU = row.Disk
		row.Memory = row.Disk
		out = append(out, row)
	}
	return out, nil
}
func (f *fixtureMonitoringSource) WithWindowsMonitoringAuthority(ctx context.Context, expected []windowscontact.Input, fn func(func(time.Time) error) error) error {
	f.leases++
	started := f.now
	calls := 0
	guard := func(min time.Time) error {
		calls++
		if f.onGuard != nil {
			f.onGuard(calls)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if f.now.Before(min) || !contactReadTime(started, f.now) {
			return store.ErrFleetMonitoringConflict
		}
		for _, in := range expected {
			found := false
			for _, actual := range f.inputs {
				if actual.Authorized && actual.DeviceID == in.DeviceID && actual.InvitationID == in.InvitationID && actual.CertificateHash == in.CertificateHash && actual.AuthorityUntil == in.AuthorityUntil && f.now.Before(actual.AuthorityUntil) {
					found = true
				}
			}
			if !found {
				return store.ErrFleetMonitoringConflict
			}
		}
		return nil
	}
	if err := guard(started); err != nil {
		return err
	}
	return fn(guard)
}
func installMonitoringFixture(t *testing.T, o operatorFixture) (*windowsCapacityMonitor, *fixtureMonitoringSource, string) {
	t.Helper()
	f := &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}
	m, e := newWindowsCapacityMonitor(o.app.store, f)
	if e != nil {
		t.Fatal(e)
	}
	o.app.windowsCapacity = m
	o.server.Config.Handler.(*operatorHandler).fleetGroupSources = []fleetGroupSource{f}
	manager, _, devices, e := fleetGroupAdmission(context.Background(), []fleetGroupSource{f})
	if e != nil {
		t.Fatal(e)
	}
	id := "group_" + strings.Repeat("1", 32)
	in := f.inputs[0]
	if _, e = m.store.SaveFleetGroup(context.Background(), manager, id, "Office", []store.FleetGroupMember{{DeviceID: in.DeviceID, Identity: devices[in.DeviceID].identity}}, 0, false, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	return m, f, "/api/fleet/groups/" + id + "/monitoring"
}
func readMonitoring(t *testing.T, o operatorFixture, path string) fleetMonitoringView {
	t.Helper()
	r, v := o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	raw, _ := json.Marshal(v)
	var view fleetMonitoringView
	if e := json.Unmarshal(raw, &view); e != nil {
		t.Fatal(e)
	}
	return view
}
func monitoringBody(view fleetMonitoringView) map[string]any {
	return map[string]any{"expectedGroupRevision": view.GroupRevision, "expectedRevision": view.Revision, "consent": true, "definitions": []any{map[string]any{"metric": "disk", "enabled": true, "thresholdPercent": 85}}, "assignments": []any{map[string]any{"deviceId": view.Targets[0].DeviceID, "metric": "disk", "expectedRevision": view.Targets[0].AssignmentRevision, "expectedPolicyRevision": view.Targets[0].Policy.Revision, "inherit": true}}}
}
func TestFleetMonitoringAPIConsentSchedulerManualAndReadOnly(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f, path := installMonitoringFixture(t, o)
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous read")
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	view := readMonitoring(t, o, path)
	if len(view.Targets) != 3 || view.Revision != 0 || len(view.Definitions) != 0 {
		t.Fatal(view)
	}
	for _, v := range view.Targets {
		if v.Owned || v.Status != "manual" || v.Policy.Enabled {
			t.Fatal("default inherited", v)
		}
	}
	body := monitoringBody(view)
	if r, _ := o.call(t, "POST", path, body, "", nil); r.StatusCode != 403 {
		t.Fatal("missing CSRF")
	}
	if r, _ := o.call(t, "POST", path, body, csrf, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }); r.StatusCode != 403 {
		t.Fatal("cross origin")
	}
	body["consent"] = false
	if r, _ := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("unchecked consent accepted")
	}
	body["consent"] = true
	if r, v := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	pending := readMonitoring(t, o, path)
	if !pending.Targets[0].Owned || pending.Targets[0].Status != "pending" || pending.Targets[0].Policy.Enabled {
		t.Fatal("save immediately applied", pending)
	}
	if e := m.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
	inherited := readMonitoring(t, o, path)
	if inherited.Targets[0].Status != "inherited" || inherited.Targets[0].Policy.ThresholdPercent != 85 || inherited.Targets[1].Owned {
		t.Fatal(inherited)
	}
	before, e := m.store.FleetMonitoringAssignments(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	leases := f.leases
	if e = m.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
	after, e := m.store.FleetMonitoringAssignments(context.Background())
	if e != nil || before[0] != after[0] || f.leases != leases {
		t.Fatal("already applied assignment replayed", e)
	}
	// Identical ordinary Save remains an explicit manual override.
	policy := map[string]any{"enabled": true, "thresholdPercent": 85, "expectedRevision": 1}
	if r, v := o.call(t, "POST", "/api/devices/"+f.inputs[0].DeviceID+"/windows-capacity/policy", policy, csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	manual := readMonitoring(t, o, path)
	if manual.Targets[0].Owned || manual.Targets[0].Status != "manual-override" || manual.Targets[0].Policy.Revision != 1 {
		t.Fatal(manual)
	}
	if r, _ := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("uncertain POST replay accepted")
	}
	for _, suffix := range []string{"?", "?x=1", "/", "/other"} {
		expected := 404
		if suffix == "?" || suffix == "?x=1" {
			expected = 400
		}
		if r, _ := o.call(t, "GET", path+suffix, nil, "", nil); r.StatusCode != expected {
			t.Fatal("route alias accepted", suffix, r.StatusCode)
		}
	}
}
func TestFleetMonitoringSchedulerNoAssignmentsReadsAndRestart(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f, path := installMonitoringFixture(t, o)
	if e := m.evaluate(context.Background()); e != nil || f.reads != 0 || f.leases != 0 {
		t.Fatal("empty assignment source read", e)
	}
	_, login := o.login(t)
	view := readMonitoring(t, o, path)
	if r, v := o.call(t, "POST", path, monitoringBody(view), login["csrfToken"].(string), nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	// A new monitor reconstructs pending work exclusively from durable metadata.
	restarted, e := newWindowsCapacityMonitor(m.store, f)
	if e != nil {
		t.Fatal(e)
	}
	if e = restarted.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
	view = readMonitoring(t, o, path)
	if view.Targets[0].Status != "inherited" {
		t.Fatal(view)
	}
}
func TestFleetMonitoringFinalAuthorityRollbackAndReplacement(t *testing.T) {
	for _, failure := range []string{"expiry", "rollback", "revoked", "replacement", "session"} {
		t.Run(failure, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			m, f, path := installMonitoringFixture(t, o)
			response, login := o.login(t)
			view := readMonitoring(t, o, path)
			start := f.now
			f.onGuard = func(n int) {
				if n == 3 {
					switch failure {
					case "expiry":
						f.now = f.inputs[0].AuthorityUntil
					case "rollback":
						f.now = start.Add(-time.Second)
					case "revoked":
						f.inputs[0].Authorized = false
					case "replacement":
						f.inputs[0].CertificateHash = strings.Repeat("f", 64)
					case "session":
						auth := o.server.Config.Handler.(*operatorHandler).auth
						token := response.Cookies()[0].Value
						go auth.Logout(token)
						until := time.Now().Add(time.Second)
						for time.Now().Before(until) {
							if _, e := auth.Lookup(token); e != nil {
								break
							}
							time.Sleep(time.Millisecond)
						}
					}
				}
			}
			if r, _ := o.call(t, "POST", path, monitoringBody(view), login["csrfToken"].(string), nil); r.StatusCode == 200 {
				t.Fatal("lost final authority accepted")
			}
			a, e := m.store.FleetMonitoringAssignments(context.Background())
			if e != nil || len(a) != 0 {
				t.Fatal("failed final guard committed", a, e)
			}
		})
	}
}
func TestFleetMonitoringRenewedOriginalIdentityAndUnavailableProjection(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f, path := installMonitoringFixture(t, o)
	_, login := o.login(t)
	view := readMonitoring(t, o, path)
	if r, v := o.call(t, "POST", path, monitoringBody(view), login["csrfToken"].(string), nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	renewed := f.inputs[0].AuthorityUntil.Add(time.Hour)
	f.inputs[0].AuthorityUntil = renewed
	f.devices[0].AgentCertificate.ExpiresAt = &renewed
	if e := m.evaluate(context.Background()); e != nil {
		t.Fatal("original identity lost on renewal", e)
	}
	view = readMonitoring(t, o, path)
	if view.Targets[0].Status != "inherited" {
		t.Fatal(view)
	}
	f.inputs[0].CertificateHash = strings.Repeat("f", 64)
	f.snapshots[0].Issuance.CertificateHash = f.inputs[0].CertificateHash
	view = readMonitoring(t, o, path)
	if len(view.Targets) != 0 || view.UnavailableAssignments != 1 {
		t.Fatal("replacement exposed old owner", view)
	}
	// Even explicit new membership cannot expose a partial projection of the
	// original identity's retained disk policy alongside fresh CPU/RAM defaults.
	manager, _, devices, e := fleetGroupAdmission(context.Background(), []fleetGroupSource{f})
	if e != nil {
		t.Fatal(e)
	}
	groupID := strings.Split(path, "/")[4]
	if _, e = m.store.SaveFleetGroup(context.Background(), manager, groupID, "Office", []store.FleetGroupMember{{DeviceID: f.inputs[0].DeviceID, Identity: devices[f.inputs[0].DeviceID].identity}}, 1, false, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	view = readMonitoring(t, o, path)
	if len(view.Targets) != 0 || view.UnavailableAssignments != 1 {
		t.Fatal("partial or old identity policies escaped", view)
	}
	if e := m.evaluate(context.Background()); e != nil && !errors.Is(e, windowscapacity.ErrInvalid) {
		t.Fatal(e)
	}
}
func TestFleetMonitoringNamedReadOnly(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	_, _, path := installMonitoringFixture(t, o)
	_, login := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	view := readMonitoring(t, o, path)
	if r, _ := o.call(t, "POST", path, monitoringBody(view), login["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("named write allowed")
	}
}

func TestFleetMonitoringNestedConsentAndRevisionFieldsAreExact(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, _, path := installMonitoringFixture(t, o)
	_, login := o.login(t)
	view := readMonitoring(t, o, path)
	raw, e := json.Marshal(monitoringBody(view))
	if e != nil {
		t.Fatal(e)
	}
	cases := [][2]string{{`"enabled":true,`, ``}, {`"enabled":true`, `"enabled":null`}, {`"enabled":true`, `"enabled":false,"enabled":true`}, {`"inherit":true`, `"inherit":null`}, {`,"inherit":true`, ``}, {`"inherit":true`, `"inherit":false,"inherit":true`}, {`"expectedPolicyRevision":0,`, ``}, {`"expectedRevision":0,"inherit"`, `"expectedRevision":0,"expectedRevision":0,"inherit"`}}
	for _, pair := range cases {
		changed := strings.Replace(string(raw), pair[0], pair[1], 1)
		if changed == string(raw) {
			t.Fatalf("test mutation did not match %s", pair[0])
		}
		if r, v := o.call(t, "POST", path, json.RawMessage(changed), login["csrfToken"].(string), nil); r.StatusCode != 400 {
			t.Fatal("ambiguous nested request accepted", pair[0], r.StatusCode, v)
		}
	}
	assignments, e := m.store.FleetMonitoringAssignments(context.Background())
	if e != nil || len(assignments) != 0 {
		t.Fatal("malformed request wrote ownership", assignments, e)
	}
}
