package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
)

func groupMaintenanceEndBody(v fleetGroupMaintenanceView, domain string) map[string]any {
	for _, row := range v.Members[0].Targets {
		if row.Domain == domain {
			return map[string]any{"groupRevision": v.GroupRevision, "key": row.Key, "revision": row.Revision, "windowId": row.Windows[0].ID}
		}
	}
	panic("fixture domain missing")
}

func groupMaintenanceStartForEnd(t *testing.T, h *operatorHandler, op operatorRequest, path string) fleetGroupMaintenanceView {
	t.Helper()
	v := groupMaintenanceRead(t, h, op, path)
	if w := groupMaintenanceRequest(h, op, "POST", path+"/start", groupMaintenanceBody(v, "disk")); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	return groupMaintenanceRead(t, h, op, path)
}

func TestFleetGroupMaintenanceEndHandlerExactWindowAndClosedWire(t *testing.T) {
	h, f, op, path := groupMaintenanceHandlerFixture(t)
	v := groupMaintenanceStartForEnd(t, h, op, path)
	body := groupMaintenanceEndBody(v, "disk")
	original := v.Members[0].Targets[3].Windows[0]
	f.now = f.now.Add(time.Second)
	w := groupMaintenanceRequest(h, op, "POST", path+"/end", body)
	var ended fleetGroupMaintenanceView
	var keys map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &ended) != nil || json.Unmarshal(w.Body.Bytes(), &keys) != nil || len(keys) != 9 || keys["members"] == nil || keys["targets"] != nil {
		t.Fatal("group end changed response contract", w.Code, w.Body.String())
	}
	row := ended.Members[0].Targets[3]
	if ended.SchemaVersion != v.SchemaVersion || ended.GroupRevision != v.GroupRevision || row.Revision != 2 || row.Windows[0].EndedAt == nil || !row.Windows[0].EndedAt.Equal(f.now) || row.Windows[0].ID != original.ID || !row.Windows[0].EndsAt.Equal(original.EndsAt) || !row.Windows[0].StartedAt.Equal(original.StartedAt) || row.Windows[0].Intent != original.Intent {
		t.Fatal("exact end lost original window", row)
	}
	if w = groupMaintenanceRequest(h, op, "POST", path+"/end", body); w.Code != 409 {
		t.Fatal("replayed end accepted", w.Code)
	}
	newer := groupMaintenanceStartForEnd(t, h, op, path)
	body["revision"] = newer.Members[0].Targets[3].Revision
	if w = groupMaintenanceRequest(h, op, "POST", path+"/end", body); w.Code != 409 {
		t.Fatal("old ID ended newer window with current revision", w.Code)
	}
	if got := groupMaintenanceRead(t, h, op, path); !got.Members[0].Targets[3].Windows[0].Active(f.now) {
		t.Fatal("newer window was ended")
	}
	// The old v1 end route still accepts exactly three keys and emits four
	// top-level fields. The group-specific field cannot widen that contract.
	body = groupMaintenanceEndBody(newer, "disk")
	if w = groupMaintenanceRequest(h, op, "POST", maintenancePath+"/end", body); w.Code != 400 {
		t.Fatal("old end request widened", w.Code)
	}
	delete(body, "groupRevision")
	w = groupMaintenanceRequest(h, op, "POST", maintenancePath+"/end", body)
	keys = nil
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &keys) != nil || len(keys) != 4 || keys["targets"] == nil || keys["members"] != nil {
		t.Fatal("old end response changed", w.Code, w.Body.String())
	}
}

func TestFleetGroupMaintenanceEndHandlerExactRequestsAndRole(t *testing.T) {
	h, _, op, path := groupMaintenanceHandlerFixture(t)
	v := groupMaintenanceStartForEnd(t, h, op, path)
	for _, edit := range []func(map[string]any){
		func(b map[string]any) { delete(b, "groupRevision") },
		func(b map[string]any) { delete(b, "windowId") },
		func(b map[string]any) { b["groupRevision"] = 0 },
		func(b map[string]any) { b["groupRevision"] = store.MaxFleetGroupRevision + 1 },
		func(b map[string]any) { b["groupRevision"] = nil },
		func(b map[string]any) { b["windowId"] = 0 },
		func(b map[string]any) { b["windowId"] = store.MaxWindowsMaintenanceRevision + 1 },
		func(b map[string]any) { b["windowId"] = "1" },
		func(b map[string]any) { b["revision"] = -1 },
		func(b map[string]any) { b["revision"] = store.MaxWindowsMaintenanceRevision },
		func(b map[string]any) { b["endsAt"] = v.ServerNow.Add(time.Hour).Format(time.RFC3339Nano) },
		func(b map[string]any) { b["intent"] = "other" },
		func(b map[string]any) { b["extra"] = true },
	} {
		body := groupMaintenanceEndBody(v, "disk")
		edit(body)
		if w := groupMaintenanceRequest(h, op, "POST", path+"/end", body); w.Code != 400 {
			t.Fatal("invalid group end body accepted", body, w.Code, w.Body.String())
		}
	}
	body := groupMaintenanceEndBody(v, "disk")
	raw, _ := json.Marshal(body)
	duplicate := strings.TrimSuffix(string(raw), "}") + `,"windowId":1}`
	if w := groupMaintenanceRequest(h, op, "POST", path+"/end", body, func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(duplicate)) }); w.Code != 400 {
		t.Fatal("duplicate end field accepted", w.Code)
	}
	for _, suffix := range []string{"?", "?x=1", "/"} {
		if w := groupMaintenanceRequest(h, op, "POST", path+"/end"+suffix, body); w.Code == 200 {
			t.Fatal("query or route alias accepted", suffix)
		}
	}
	if w := groupMaintenanceRequest(h, op, "GET", path+"/end", nil); w.Code != 405 || w.Header().Get("Allow") != "POST" {
		t.Fatal("group end method guard", w.Code)
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") },
	} {
		if w := groupMaintenanceRequest(h, op, "POST", path+"/end", body, change); w.Code != 403 {
			t.Fatal("end mutation boundary weakened", w.Code)
		}
	}
	auth, err := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	named := operatorRequest{session: session, origin: op.origin, active: func() bool { _, err := auth.Lookup(session.Token); return err == nil }}
	groupMaintenanceRead(t, h, named, path)
	if w := groupMaintenanceRequest(h, named, "POST", path+"/end", body); w.Code != 403 {
		t.Fatal("named reader ended maintenance", w.Code)
	}
	if got := groupMaintenanceRead(t, h, op, path); !reflect.DeepEqual(got.Members, v.Members) {
		t.Fatal("rejected end changed retained state")
	}
}

func TestFleetGroupMaintenanceEndHandlerCommitGuards(t *testing.T) {
	for _, failure := range []string{"group-revision", "membership", "deleted", "expiry", "window-expiry", "rollback", "replacement", "revocation", "session"} {
		t.Run(failure, func(t *testing.T) {
			h, f, op, path := groupMaintenanceHandlerFixture(t)
			v := groupMaintenanceStartForEnd(t, h, op, path)
			before, err := h.app.store.WindowsMaintenance(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			f.beforeLease = func() {
				if failure == "group-revision" || failure == "membership" || failure == "deleted" {
					members := []store.FleetGroupMember{{DeviceID: f.inputs[0].DeviceID, Identity: monitoringIdentity(f.binding, f.inputs[0])}}
					if failure == "membership" || failure == "deleted" {
						members = nil
					}
					_, err := h.app.store.SaveFleetGroup(context.Background(), monitoringManager(f.binding), v.GroupID, "Changed", members, 1, failure == "deleted", func() error { return nil })
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			start := f.now
			live := true
			op.active = func() bool { return live }
			f.onGuard = func(n int) {
				if n != 3 {
					return
				}
				switch failure {
				case "expiry":
					f.now = f.inputs[0].AuthorityUntil
				case "window-expiry":
					f.now = v.Members[0].Targets[3].Windows[0].EndsAt
				case "rollback":
					f.now = start.Add(-time.Second)
				case "replacement":
					f.inputs[0].CertificateHash = strings.Repeat("e", 64)
				case "revocation":
					f.inputs[0].Authorized = false
				case "session":
					live = false
				}
			}
			if w := groupMaintenanceRequest(h, op, "POST", path+"/end", groupMaintenanceEndBody(v, "disk")); w.Code == 200 {
				t.Fatal("failed end commit guard accepted", w.Body.String())
			}
			after, err := h.app.store.WindowsMaintenance(context.Background())
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("failed end guard committed", err)
			}
		})
	}
}

func TestFleetGroupMaintenanceEndHandlerDoesNotAdoptReplacement(t *testing.T) {
	h, f, op, path := groupMaintenanceHandlerFixture(t)
	v := groupMaintenanceStartForEnd(t, h, op, path)
	original := groupMaintenanceEndBody(v, "disk")
	f.inputs[0].CertificateHash = strings.Repeat("e", 64)
	f.snapshots[0].Issuance.CertificateHash = f.inputs[0].CertificateHash
	if w := groupMaintenanceRequest(h, op, "POST", path+"/end", original); w.Code != 409 {
		t.Fatal("replacement ended old identity window", w.Code)
	}
	current := groupMaintenanceRequest(h, op, "GET", maintenancePath, nil)
	var currentView windowsMaintenanceView
	if current.Code != 200 || json.Unmarshal(current.Body.Bytes(), &currentView) != nil {
		t.Fatal(current.Code, current.Body.String())
	}
	row := currentView.Targets[3]
	if w := groupMaintenanceRequest(h, op, "POST", maintenancePath+"/start", maintenanceBody(row, f.now)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	body := map[string]any{"groupRevision": v.GroupRevision, "key": row.Key, "revision": 1, "windowId": 1}
	if w := groupMaintenanceRequest(h, op, "POST", path+"/end", body); w.Code != 409 {
		t.Fatal("replacement gained original group membership", w.Code)
	}
	f.snapshots[0].State = enrollmentstate.Revoked
	f.inputs[0].Authorized = false
	if w := groupMaintenanceRequest(h, op, "POST", path+"/end", body); w.Code != 409 {
		t.Fatal("revoked identity ended group window", w.Code)
	}
}

func TestFleetGroupMaintenanceEndHandlerRetainsEarlierPartialOutcome(t *testing.T) {
	h, f, op, path := groupMaintenanceHandlerFixture(t)
	v := groupMaintenanceStartForEnd(t, h, op, path)
	if w := groupMaintenanceRequest(h, op, "POST", path+"/start", groupMaintenanceBody(v, "cpu")); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	review := groupMaintenanceRead(t, h, op, path)
	if w := groupMaintenanceRequest(h, op, "POST", path+"/end", groupMaintenanceEndBody(review, "disk")); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	members := []store.FleetGroupMember{{DeviceID: f.inputs[0].DeviceID, Identity: monitoringIdentity(f.binding, f.inputs[0])}}
	if _, err := h.app.store.SaveFleetGroup(context.Background(), monitoringManager(f.binding), v.GroupID, "Changed", members, v.GroupRevision, false, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if w := groupMaintenanceRequest(h, op, "POST", path+"/end", groupMaintenanceEndBody(review, "cpu")); w.Code != 409 {
		t.Fatal("later stale group end accepted", w.Code)
	}
	current := groupMaintenanceRead(t, h, op, path)
	if current.GroupRevision != 2 || current.Members[0].Targets[3].Windows[0].EndedAt == nil || !current.Members[0].Targets[2].Windows[0].Active(f.now) {
		t.Fatal("later conflict rolled back earlier outcome or ended unreviewed target", current)
	}
}

func TestFleetGroupMaintenanceEndHandlerWithholdsPostCommitResponse(t *testing.T) {
	h, f, op, path := groupMaintenanceHandlerFixture(t)
	v := groupMaintenanceStartForEnd(t, h, op, path)
	live := true
	op.active = func() bool { return live }
	f.afterLease = func() { live = false }
	body := groupMaintenanceEndBody(v, "disk")
	w := groupMaintenanceRequest(h, op, "POST", path+"/end", body)
	if w.Code == 200 || strings.Contains(w.Body.String(), v.Members[0].DeviceID) {
		t.Fatal("inactive session received committed private projection", w.Code, w.Body.String())
	}
	stored, err := h.app.store.WindowsMaintenance(context.Background())
	if err != nil || len(stored) != 1 || stored[0].Revision != 2 || stored[0].Windows[0].EndedAt == nil {
		t.Fatal("fixture did not reach committed-but-unconfirmed state", err)
	}
	live = true
	f.afterLease = nil
	readback := groupMaintenanceRead(t, h, op, path)
	if readback.Members[0].Targets[3].Revision != 2 || readback.Members[0].Targets[3].Windows[0].EndedAt == nil {
		t.Fatal("GET failed to expose current ended state")
	}
	if w = groupMaintenanceRequest(h, op, "POST", path+"/end", body); w.Code != 409 {
		t.Fatal("unconfirmed end was replayable", w.Code)
	}
	after, err := h.app.store.WindowsMaintenance(context.Background())
	if err != nil || !reflect.DeepEqual(stored, after) {
		t.Fatal("readback or replay changed committed original window", err)
	}
}
