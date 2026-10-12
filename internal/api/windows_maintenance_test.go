package api

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/store"
	"localrmm/internal/windowscontact"
)

const maintenancePath = "/api/fleet/windows-maintenance"

func readMaintenance(t *testing.T, o operatorFixture) windowsMaintenanceView {
	t.Helper()
	r, value := o.call(t, "GET", maintenancePath, nil, "", nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, value)
	}
	raw, _ := json.Marshal(value)
	var v windowsMaintenanceView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func maintenanceRow(t *testing.T, view windowsMaintenanceView, domain string) windowsMaintenanceTargetView {
	t.Helper()
	for _, target := range view.Targets {
		if target.Domain == domain {
			return target
		}
	}
	t.Fatal("missing target", domain)
	return windowsMaintenanceTargetView{}
}
func maintenanceBody(row windowsMaintenanceTargetView, now time.Time) map[string]any {
	return map[string]any{"key": row.Key, "revision": row.Revision, "endsAt": now.Add(time.Hour).Format(time.RFC3339Nano), "intent": "planned-work"}
}

func TestWindowsMaintenanceReadStartEndAndUnchangedIncidentContract(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := incidentInboxFixture(t, o)
	if r, _ := o.call(t, "GET", maintenancePath, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous read")
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	before, err := m.store.WindowsIncidentSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	inbox := readInbox(t, o, inboxPath)
	v := readMaintenance(t, o)
	if len(v.Targets) != 6 || v.SchemaVersion != "tracebolt.windows-maintenance.v1" {
		t.Fatal("target projection", v)
	}
	for i, row := range v.Targets {
		if row.Domain != store.WindowsMaintenanceDomains()[i] || row.Revision != 0 || row.ChangedAt != nil || len(row.Windows) != 0 {
			t.Fatal("new target inherited metadata", row)
		}
	}
	row := maintenanceRow(t, v, "disk")
	body := maintenanceBody(row, f.now)
	if r, _ := o.call(t, "POST", maintenancePath+"/start", body, "", nil); r.StatusCode != 403 {
		t.Fatal("missing csrf")
	}
	if r, _ := o.call(t, "POST", maintenancePath+"/start", body, csrf, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }); r.StatusCode != 403 {
		t.Fatal("cross origin")
	}
	if r, result := o.call(t, "POST", maintenancePath+"/start", body, csrf, nil); r.StatusCode != 200 || result["schemaVersion"] != v.SchemaVersion {
		t.Fatal("start", r.StatusCode, result)
	}
	row = maintenanceRow(t, readMaintenance(t, o), "disk")
	if row.Revision != 1 || len(row.Windows) != 1 || !row.Windows[0].Active(f.now) {
		t.Fatal("missing current window", row)
	}
	if r, _ := o.call(t, "POST", maintenancePath+"/start", body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("uncertain replay restarted/extended window")
	}
	endBody := map[string]any{"key": row.Key, "revision": row.Revision, "windowId": row.Windows[0].ID}
	f.now = f.now.Add(time.Second)
	if r, value := o.call(t, "POST", maintenancePath+"/end", endBody, csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, value)
	}
	ended := maintenanceRow(t, readMaintenance(t, o), "disk")
	if ended.Revision != 2 || ended.Windows[0].EndedAt == nil || ended.Windows[0].Active(f.now) || !ended.Windows[0].EndsAt.Equal(row.Windows[0].EndsAt) {
		t.Fatal("end changed original deadline", ended)
	}
	if r, _ := o.call(t, "POST", maintenancePath+"/end", endBody, csrf, nil); r.StatusCode != 409 {
		t.Fatal("stale end revision accepted")
	}
	after, err := m.store.WindowsIncidentSnapshot(context.Background())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("maintenance edited source history/acknowledgement", err)
	}
	inboxAfter := readInbox(t, o, inboxPath)
	if !reflect.DeepEqual(inbox.Counts, inboxAfter.Counts) || inbox.Total != inboxAfter.Total {
		t.Fatal("maintenance suppressed incident counts")
	}
	raw, _ := json.Marshal(readMaintenance(t, o))
	for _, private := range []string{"invitationId", "certificateHash", "sequenceFloor", "epoch"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private identity disclosed", private)
		}
	}
}

func TestWindowsMaintenanceEmptyEvidenceNamedReaderAndReplacement(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installCapacityFixture(t, o)
	_, login := o.login(t)
	row := maintenanceRow(t, readMaintenance(t, o), "all")
	if r, v := o.call(t, "POST", maintenancePath+"/start", maintenanceBody(row, f.now), login["csrfToken"].(string), nil); r.StatusCode != 200 {
		t.Fatal("maintenance required incident/evidence", r.StatusCode, v)
	}
	states, err := m.store.WindowsIncidentSnapshot(context.Background())
	if err != nil || len(states.Targets()) != 0 {
		t.Fatal("planning created source state", err)
	}
	// Current-leaf renewal preserves the original certificate anchor and key.
	f.inputs[0].AuthorityUntil = f.inputs[0].AuthorityUntil.Add(time.Hour)
	renewed := maintenanceRow(t, readMaintenance(t, o), "all")
	if renewed.Key != row.Key || renewed.Revision != 1 {
		t.Fatal("same-identity renewal lost planning metadata")
	}
	f.inputs[0].CertificateHash = strings.Repeat("e", 64)
	replacement := maintenanceRow(t, readMaintenance(t, o), "all")
	if replacement.Key == row.Key || replacement.Revision != 0 || len(replacement.Windows) != 0 {
		t.Fatal("replacement inherited maintenance")
	}
	if r, _ := o.call(t, "POST", maintenancePath+"/start", maintenanceBody(row, f.now), login["csrfToken"].(string), nil); r.StatusCode != 409 {
		t.Fatal("stale identity admitted")
	}
	f.inputs[0].Authorized = false
	if len(readMaintenance(t, o).Targets) != 0 {
		t.Fatal("revoked identity disclosed maintenance")
	}
	named, _ := namedOperatorFixture(t)
	_, _ = installCapacityFixture(t, named)
	_, session := named.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	read := readMaintenance(t, named)
	if r, _ := named.call(t, "POST", maintenancePath+"/start", maintenanceBody(read.Targets[0], read.ServerNow), session["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("named reader changed maintenance")
	}
}

func TestWindowsMaintenanceExactRequestsAndBounds(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	_, f := installCapacityFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	row := maintenanceRow(t, readMaintenance(t, o), "all")
	for _, change := range []func(map[string]any){
		func(b map[string]any) { b["unexpected"] = true },
		func(b map[string]any) { b["revision"] = 1 },
		func(b map[string]any) { b["revision"] = -1 },
		func(b map[string]any) { b["intent"] = "" },
		func(b map[string]any) { b["key"] = strings.Repeat("f", 64) },
		func(b map[string]any) { b["endsAt"] = f.now.Add(59 * time.Second).Format(time.RFC3339Nano) },
		func(b map[string]any) { b["endsAt"] = f.now.Add(24*time.Hour + time.Second).Format(time.RFC3339Nano) },
		func(b map[string]any) { b["endsAt"] = "2026-10-12T12:00:00.000Z" },
		func(b map[string]any) { b["endsAt"] = "2026-10-12T12:00:00+00:00" },
	} {
		body := maintenanceBody(row, f.now)
		change(body)
		if r, _ := o.call(t, "POST", maintenancePath+"/start", body, csrf, nil); r.StatusCode == 200 {
			t.Fatal("invalid request accepted", body)
		}
	}
	for _, path := range []string{maintenancePath + "?", maintenancePath + "?offset=0", maintenancePath + "/unknown"} {
		if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode == 200 {
			t.Fatal("invalid route/query", path)
		}
	}
	if r, _ := o.call(t, "POST", maintenancePath+"/end", map[string]any{"key": row.Key, "revision": 0, "windowId": 0}, csrf, nil); r.StatusCode != 400 {
		t.Fatal("zero window ID admitted as start")
	}
}

func TestWindowsMaintenanceAuthorityChangeBeforeCommit(t *testing.T) {
	for _, change := range []string{"revoked", "replacement", "expired", "session"} {
		t.Run(change, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			m, f := installCapacityFixture(t, o)
			response, login := o.login(t)
			row := maintenanceRow(t, readMaintenance(t, o), "all")
			f.reads = 0
			f.onRead = func(n int) {
				if n != 2 {
					return
				}
				switch change {
				case "revoked":
					f.inputs[0].Authorized = false
				case "replacement":
					f.inputs[0].CertificateHash = strings.Repeat("b", 64)
				case "expired":
					f.inputs[0].AuthorityUntil = f.now
				case "session":
					auth := o.server.Config.Handler.(*operatorHandler).auth
					token := response.Cookies()[0].Value
					go auth.Logout(token)
					until := time.Now().Add(time.Second)
					for time.Now().Before(until) {
						if _, err := auth.Lookup(token); err != nil {
							break
						}
						time.Sleep(time.Millisecond)
					}
				}
			}
			if r, _ := o.call(t, "POST", maintenancePath+"/start", maintenanceBody(row, f.now), login["csrfToken"].(string), nil); r.StatusCode == 200 {
				t.Fatal("changed authority committed")
			}
			states, err := m.store.WindowsMaintenance(context.Background())
			if err != nil || len(states) != 0 {
				t.Fatal("failed authority wrote metadata", err)
			}
		})
	}
}

func TestWindowsMaintenanceClockFloorAndFinalResponseExpiry(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installCapacityFixture(t, o)
	_, login := o.login(t)
	row := maintenanceRow(t, readMaintenance(t, o), "all")
	if r, _ := o.call(t, "POST", maintenancePath+"/start", maintenanceBody(row, f.now), login["csrfToken"].(string), nil); r.StatusCode != 200 {
		t.Fatal("start")
	}
	f.now = f.now.Add(-time.Second)
	f.inputs[0].ReceivedAt = f.now.Add(-time.Second)
	if r, _ := o.call(t, "GET", maintenancePath, nil, "", nil); r.StatusCode != 409 {
		t.Fatal("time before durable floor projected")
	}
	f.now = f.now.Add(time.Second)
	base := f.now
	expires := base.Add(time.Second)
	f.inputs[0].AuthorityUntil = expires
	clock := &capacityBoundaryClock{fixtureWindowsCapacitySource: f}
	clock.transition = func(n int) time.Time {
		if n >= 5 {
			return expires
		}
		return base
	}
	m.source = clock
	if r, _ := o.call(t, "GET", maintenancePath, nil, "", nil); r.StatusCode == 200 {
		t.Fatal("expired final response released metadata")
	}
}

type boundedMaintenanceSource struct {
	*fixtureWindowsCapacitySource
	bounded bool
}

func (f *boundedMaintenanceSource) WithWindowsIncidentAuthority(ctx context.Context, in windowscontact.Input, fn func(func(time.Time) error) error) error {
	deadline, ok := ctx.Deadline()
	f.bounded = ok && time.Until(deadline) > 0 && time.Until(deadline) <= 5*time.Second
	return f.fixtureWindowsCapacitySource.WithWindowsIncidentAuthority(ctx, in, fn)
}

func TestWindowsMaintenanceAuthorityLeaseHasBoundedRequestDeadline(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installCapacityFixture(t, o)
	bounded := &boundedMaintenanceSource{fixtureWindowsCapacitySource: f}
	m.source = bounded
	_, login := o.login(t)
	row := maintenanceRow(t, readMaintenance(t, o), "all")
	if r, value := o.call(t, "POST", maintenancePath+"/start", maintenanceBody(row, f.now), login["csrfToken"].(string), nil); r.StatusCode != 200 || !bounded.bounded {
		t.Fatal("authority lease lacks five-second request deadline", r.StatusCode, value)
	}
}
