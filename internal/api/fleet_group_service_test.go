package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsservicehealth"
)

type groupServiceFixture struct {
	*fixtureGroupMaintenanceSource
	sample windowsservicehealth.Sample
}

func (f *groupServiceFixture) WindowsCapacityInputs(ctx context.Context, at time.Time) ([]windowscapacity.Input, error) {
	rows, err := f.fixtureMonitoringSource.WindowsCapacityInputs(ctx, at)
	for i := range rows {
		rows[i].Services = f.sample
	}
	return rows, err
}
func groupServiceHandlerFixture(t *testing.T) (*operatorHandler, *groupServiceFixture, operatorRequest, string) {
	h, f, op, path := groupMaintenanceHandlerFixture(t)
	source := &groupServiceFixture{fixtureGroupMaintenanceSource: f, sample: windowsservicehealth.Sample{CollectedAt: f.now, Services: windowsmanaged.Section[windowsmanaged.Service]{Quality: "healthy", Complete: true, CountExact: true, ObservedCount: 2, Rows: []windowsmanaged.Service{{Name: "FixtureService", DisplayName: "Readable fixture service", State: "running"}, {Name: "Other", State: "stopped"}}}}}
	h.app.windowsCapacity.source = source
	h.fleetGroupSources = []fleetGroupSource{source}
	return h, source, op, strings.TrimSuffix(path, "maintenance") + "service-checks"
}

// Explicit recorder-only synthetic HTTPS metadata. No server or TLS connection.
func groupServiceRequest(h *operatorHandler, op operatorRequest, method, path string, body any, changes ...func(*http.Request)) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, "https://maintenance.invalid"+path, strings.NewReader(string(raw)))
	r.Header.Set("Origin", op.origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", op.session.CSRFToken)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, op))
	for _, change := range changes {
		change(r)
	}
	w := httptest.NewRecorder()
	h.fleetGroupServiceAPI(w, r)
	return w
}
func groupServiceRead(t *testing.T, h *operatorHandler, op operatorRequest, path string) fleetGroupServiceView {
	t.Helper()
	w := groupServiceRequest(h, op, "GET", path, nil)
	var v fleetGroupServiceView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	return v
}
func groupServiceBody(v fleetGroupServiceView) map[string]any {
	return map[string]any{"groupRevision": v.GroupRevision, "expectedRevision": v.Members[0].Policy.Revision, "enabled": true, "services": []string{"FixtureService"}, "consent": true}
}

func TestFleetGroupServiceHandlerExactSelectionAndUnknown(t *testing.T) {
	h, f, op, path := groupServiceHandlerFixture(t)
	v := groupServiceRead(t, h, op, path)
	if v.SchemaVersion != "tracebolt.fleet-group-service-checks.v1" || len(v.Members) != 1 || v.Members[0].Policy.Enabled || v.Members[0].Policy.Revision != 0 {
		t.Fatal(v)
	}
	detail := path + "/" + v.Members[0].Key
	w := groupServiceRequest(h, op, "GET", detail, nil)
	var choice fleetGroupServiceChoiceView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &choice) != nil || choice.SchemaVersion != "tracebolt.fleet-group-service-choice.v1" || choice.Member.Inventory == nil || len(choice.Member.Inventory.Services) != 2 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, text := range []string{"invitationId", "certificateHash", "identity", "pid", "incidents", "checks"} {
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(w.Body.Bytes(), &raw)
		if raw[text] != nil {
			t.Fatal("unexpected private/scoped data", text)
		}
	}
	states, err := h.app.store.WindowsServiceStates(context.Background())
	if err != nil || len(states) != 0 {
		t.Fatal("read created policy", err)
	}
	if w = groupServiceRequest(h, op, "POST", detail, groupServiceBody(v)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	state, err := h.app.store.WindowsServiceState(context.Background(), v.Members[0].DeviceID)
	if err != nil || !state.Policy.Enabled || state.Policy.Revision != 1 || state.Checks[0].Status != "unknown" {
		t.Fatal("save evaluated source", state, err)
	}
	if w = groupServiceRequest(h, op, "POST", detail, groupServiceBody(v)); w.Code != 409 {
		t.Fatal("stale revision replay", w.Code)
	}
	// Original membership survives a current-leaf renewal; inventory age does not.
	f.inputs[0].AuthorityUntil = f.inputs[0].AuthorityUntil.Add(time.Hour)
	f.devices[0].AgentCertificate.ExpiresAt = &f.inputs[0].AuthorityUntil
	fresh := groupServiceRead(t, h, op, path)
	if fresh.Members[0].Key != v.Members[0].Key || fresh.Members[0].Policy.Revision != 1 {
		t.Fatal("renewal lost original policy")
	}
	f.sample.CollectedAt = f.now.Add(-121 * time.Second)
	w = groupServiceRequest(h, op, "GET", detail, nil)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &choice) != nil || choice.Member.Inventory != nil {
		t.Fatal("stale inventory presented as fresh", w.Code)
	}
	body := groupServiceBody(fresh)
	body["enabled"] = false
	if w = groupServiceRequest(h, op, "POST", detail, body); w.Code != 200 {
		t.Fatal("retained disable requires new inventory", w.Code, w.Body.String())
	}
	body["expectedRevision"] = 2
	body["enabled"] = true
	if w = groupServiceRequest(h, op, "POST", detail, body); w.Code != 409 {
		t.Fatal("missing inventory enabled policy", w.Code)
	}
	// Admitted replacement with same mutable ID is withheld by original membership.
	f.inputs[0].CertificateHash = strings.Repeat("e", 64)
	f.snapshots[0].Issuance.CertificateHash = f.inputs[0].CertificateHash
	f.devices[0].Name = "Replacement private label"
	replacement := groupServiceRead(t, h, op, path)
	if len(replacement.Members) != 0 || replacement.UnavailableMembers != 1 {
		t.Fatal("replacement adopted", replacement)
	}
	if w = groupServiceRequest(h, op, "GET", detail, nil); w.Code != 409 {
		t.Fatal("old exact key exposed replacement")
	}
}

func TestFleetGroupServiceHandlerCommitBoundaries(t *testing.T) {
	for _, failure := range []string{"group-revision", "membership", "replacement", "revoked", "expiry", "session", "rollback", "source-age"} {
		t.Run(failure, func(t *testing.T) {
			h, f, op, path := groupServiceHandlerFixture(t)
			v := groupServiceRead(t, h, op, path)
			live := true
			op.active = func() bool { return live }
			at := f.now
			if failure == "source-age" {
				f.inputs[0].ReceivedAt = at.Add(-119 * time.Second)
				f.sample.CollectedAt = f.inputs[0].ReceivedAt
			}
			f.beforeLease = func() {
				switch failure {
				case "group-revision", "membership":
					members := []store.FleetGroupMember{{DeviceID: f.inputs[0].DeviceID, Identity: monitoringIdentity(f.binding, f.inputs[0])}}
					if failure == "membership" {
						members = nil
					}
					if _, err := h.app.store.SaveFleetGroup(context.Background(), monitoringManager(f.binding), v.GroupID, "Changed", members, 1, false, func() error { return nil }); err != nil {
						t.Fatal(err)
					}
				case "replacement":
					f.inputs[0].CertificateHash = strings.Repeat("e", 64)
				case "revoked":
					f.inputs[0].Authorized = false
				}
			}
			f.onGuard = func(n int) {
				if n != 4 {
					return
				}
				switch failure {
				case "expiry":
					f.now = f.inputs[0].AuthorityUntil
				case "session":
					live = false
				case "rollback":
					f.now = at.Add(-time.Second)
				case "source-age":
					f.now = at.Add(2 * time.Second)
				}
			}
			w := groupServiceRequest(h, op, "POST", path+"/"+v.Members[0].Key, groupServiceBody(v))
			states, err := h.app.store.WindowsServiceStates(context.Background())
			if w.Code == 200 || err != nil || len(states) != 0 {
				t.Fatal("failed authority/member guard committed", w.Code, w.Body.String(), err, states)
			}
		})
	}
}

func TestFleetGroupServiceHandlerClosedRequestsAndRoles(t *testing.T) {
	h, _, op, path := groupServiceHandlerFixture(t)
	v := groupServiceRead(t, h, op, path)
	detail := path + "/" + v.Members[0].Key
	for _, edit := range []func(map[string]any){func(b map[string]any) { delete(b, "consent") }, func(b map[string]any) { b["consent"] = false }, func(b map[string]any) { b["groupRevision"] = 0 }, func(b map[string]any) { b["extra"] = true }, func(b map[string]any) { b["services"] = []string{"FixtureService", "FixtureService"} }} {
		body := groupServiceBody(v)
		edit(body)
		if w := groupServiceRequest(h, op, "POST", detail, body); w.Code != 400 {
			t.Fatal("invalid body accepted", w.Code, w.Body.String())
		}
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }} {
		if w := groupServiceRequest(h, op, "POST", detail, groupServiceBody(v), change); w.Code != 403 {
			t.Fatal("mutation boundary", w.Code)
		}
	}
	for _, suffix := range []string{"?", "?x=1", "/", "/unknown"} {
		if w := groupServiceRequest(h, op, "GET", path+suffix, nil); w.Code == 200 {
			t.Fatal("route alias admitted", suffix)
		}
	}
	if w := groupServiceRequest(h, op, "POST", path, groupServiceBody(v)); w.Code != 405 {
		t.Fatal("bulk mutation admitted")
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
	groupServiceRead(t, h, named, path)
	if w := groupServiceRequest(h, named, "POST", detail, groupServiceBody(v)); w.Code != 403 {
		t.Fatal("named read escalated", w.Code)
	}
}
