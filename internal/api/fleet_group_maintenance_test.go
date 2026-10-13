package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
)

type fixtureGroupMaintenanceSource struct {
	*fixtureMonitoringSource
	beforeLease func()
	afterLease  func()
	onNow       func(int) time.Time
	nowReads    int
}

func (f *fixtureGroupMaintenanceSource) Now() time.Time {
	f.nowReads++
	if f.onNow != nil {
		return f.onNow(f.nowReads)
	}
	return f.now
}

func (f *fixtureGroupMaintenanceSource) WithWindowsIncidentAuthority(ctx context.Context, in windowscontact.Input, fn func(func(time.Time) error) error) error {
	if f.beforeLease != nil {
		f.beforeLease()
	}
	err := f.WithWindowsMonitoringAuthority(ctx, []windowscontact.Input{in}, fn)
	if err == nil && f.afterLease != nil {
		f.afterLease()
	}
	return err
}

// Direct handler units deliberately do not claim TLS/listener acceptance. They
// use a real operator mutation gate and the existing synthetic authority lease.
func groupMaintenanceHandlerFixture(t *testing.T) (*operatorHandler, *fixtureGroupMaintenanceSource, operatorRequest, string) {
	t.Helper()
	app := setup(t)
	f := &fixtureGroupMaintenanceSource{fixtureMonitoringSource: &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}}
	m, err := newWindowsCapacityMonitor(app.store, f)
	if err != nil {
		t.Fatal(err)
	}
	app.windowsCapacity = m
	h := &operatorHandler{app: app, fleetGroupSources: []fleetGroupSource{f}}
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: testOperatorHash(), TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.Login(context.Background(), "127.0.0.1", operatorFixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	op := operatorRequest{session: session, origin: "https://maintenance.invalid", active: func() bool { _, err := auth.Lookup(session.Token); return err == nil }}
	id := "group_" + strings.Repeat("1", 32)
	_, err = app.store.SaveFleetGroup(context.Background(), monitoringManager(f.binding), id, "Office", []store.FleetGroupMember{{DeviceID: f.inputs[0].DeviceID, Identity: monitoringIdentity(f.binding, f.inputs[0])}}, 0, false, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return h, f, op, "/api/fleet/groups/" + id + "/maintenance"
}
func groupMaintenanceRequest(h *operatorHandler, op operatorRequest, method, path string, body any, changes ...func(*http.Request)) *httptest.ResponseRecorder {
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
	if strings.HasPrefix(path, maintenancePath) {
		h.windowsMaintenanceAPI(w, r)
	} else {
		h.fleetGroupMaintenanceAPI(w, r)
	}
	return w
}
func groupMaintenanceRead(t *testing.T, h *operatorHandler, op operatorRequest, path string) fleetGroupMaintenanceView {
	t.Helper()
	w := groupMaintenanceRequest(h, op, "GET", path, nil)
	var v fleetGroupMaintenanceView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	return v
}
func groupMaintenanceBody(v fleetGroupMaintenanceView, domain string) map[string]any {
	for _, row := range v.Members[0].Targets {
		if row.Domain == domain {
			body := maintenanceBody(row, v.ServerNow)
			body["groupRevision"] = v.GroupRevision
			return body
		}
	}
	panic("fixture domain missing")
}

func TestFleetGroupMaintenanceHandlerClosedWireAndOriginalMembership(t *testing.T) {
	h, f, op, path := groupMaintenanceHandlerFixture(t)
	v := groupMaintenanceRead(t, h, op, path)
	if v.SchemaVersion != "tracebolt.fleet-group-maintenance.v1" || v.GroupName != "Office" || v.GroupRevision != 1 || len(v.Members) != 1 || len(v.Members[0].Targets) != 6 || v.UnavailableMembers != 0 || v.ExcludedLinuxMembers != 0 {
		t.Fatal(v)
	}
	body := groupMaintenanceBody(v, "disk")
	if w := groupMaintenanceRequest(h, op, "POST", path+"/start", body); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	active := groupMaintenanceRead(t, h, op, path)
	if row := active.Members[0].Targets[3]; row.Revision != 1 || !row.Windows[0].Active(f.now) {
		t.Fatal(row)
	}
	if w := groupMaintenanceRequest(h, op, "POST", path+"/start", body); w.Code != 409 {
		t.Fatal("replayed group start", w.Code)
	}
	if w := groupMaintenanceRequest(h, op, "POST", path+"/start", groupMaintenanceBody(active, "all")); w.Code != 409 {
		t.Fatal("overlap", w.Code)
	}
	// The original v1 endpoint remains exact and rejects the additive field.
	if w := groupMaintenanceRequest(h, op, "POST", maintenancePath+"/start", body); w.Code != 400 {
		t.Fatal("old v1 request widened", w.Code)
	}
	old := groupMaintenanceRequest(h, op, "GET", maintenancePath, nil)
	var keys map[string]json.RawMessage
	if old.Code != 200 || json.Unmarshal(old.Body.Bytes(), &keys) != nil || len(keys) != 4 || keys["targets"] == nil || keys["members"] != nil {
		t.Fatal("old v1 response widened", old.Code, old.Body.String())
	}
	// Current-leaf renewal keeps original membership and target metadata.
	f.inputs[0].AuthorityUntil = f.inputs[0].AuthorityUntil.Add(time.Hour)
	f.devices[0].AgentCertificate.ExpiresAt = &f.inputs[0].AuthorityUntil
	if renewed := groupMaintenanceRead(t, h, op, path); renewed.Members[0].Targets[3].Revision != 1 {
		t.Fatal("renewal lost membership")
	}
	// An admitted replacement with the same display ID receives no group row.
	f.inputs[0].CertificateHash = strings.Repeat("d", 64)
	f.snapshots[0].Issuance.CertificateHash = f.inputs[0].CertificateHash
	f.devices[0].Name = "Replacement label must remain private"
	replacement := groupMaintenanceRead(t, h, op, path)
	if len(replacement.Members) != 0 || replacement.UnavailableMembers != 1 {
		t.Fatal("replacement inherited membership", replacement)
	}
	raw, _ := json.Marshal(replacement)
	for _, private := range []string{"Replacement label", f.inputs[0].DeviceID, "certificateHash", "invitationId", "identity"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private replacement disclosed", private)
		}
	}
	current := groupMaintenanceRequest(h, op, "GET", maintenancePath, nil)
	var currentView windowsMaintenanceView
	if json.Unmarshal(current.Body.Bytes(), &currentView) != nil {
		t.Fatal("fixture read")
	}
	replacementBody := maintenanceBody(currentView.Targets[0], f.now)
	replacementBody["groupRevision"] = 1
	if w := groupMaintenanceRequest(h, op, "POST", path+"/start", replacementBody); w.Code != 409 {
		t.Fatal("replacement acquired stored group membership", w.Code)
	}
}

func TestFleetGroupMaintenanceHandlerExactRequestsAndCommitGuards(t *testing.T) {
	for _, failure := range []string{"group-revision", "membership", "expiry", "rollback", "replacement", "session"} {
		t.Run(failure, func(t *testing.T) {
			h, f, op, path := groupMaintenanceHandlerFixture(t)
			v := groupMaintenanceRead(t, h, op, path)
			f.beforeLease = func() {
				if failure == "group-revision" || failure == "membership" {
					members := []store.FleetGroupMember{{DeviceID: f.inputs[0].DeviceID, Identity: monitoringIdentity(f.binding, f.inputs[0])}}
					if failure == "membership" {
						members = nil
					}
					_, err := h.app.store.SaveFleetGroup(context.Background(), monitoringManager(f.binding), v.GroupID, "Changed", members, 1, false, func() error { return nil })
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
				case "rollback":
					f.now = start.Add(-time.Second)
				case "replacement":
					f.inputs[0].CertificateHash = strings.Repeat("e", 64)
				case "session":
					live = false
				}
			}
			if w := groupMaintenanceRequest(h, op, "POST", path+"/start", groupMaintenanceBody(v, "all")); w.Code == 200 {
				t.Fatal("failed commit guard accepted", w.Body.String())
			}
			states, err := h.app.store.WindowsMaintenance(context.Background())
			if err != nil || len(states) != 0 {
				t.Fatal("failed guard committed", err)
			}
		})
	}
	h, _, op, path := groupMaintenanceHandlerFixture(t)
	v := groupMaintenanceRead(t, h, op, path)
	for _, edit := range []func(map[string]any){
		func(b map[string]any) { delete(b, "groupRevision") },
		func(b map[string]any) { b["groupRevision"] = 0 },
		func(b map[string]any) { b["groupRevision"] = store.MaxFleetGroupRevision + 1 },
		func(b map[string]any) { b["extra"] = true },
		func(b map[string]any) { b["endsAt"] = "2026-10-12T12:00:00.000Z" },
	} {
		body := groupMaintenanceBody(v, "all")
		edit(body)
		if w := groupMaintenanceRequest(h, op, "POST", path+"/start", body); w.Code != 400 {
			t.Fatal("invalid body admitted", w.Code, w.Body.String())
		}
	}
	for _, suffix := range []string{"?", "?x=1", "/end", "/start/", "/"} {
		if w := groupMaintenanceRequest(h, op, "GET", path+suffix, nil); w.Code == 200 {
			t.Fatal("route/query alias admitted", suffix)
		}
	}
}

func TestFleetGroupMaintenanceProjectionCountsBoundsAndAuthority(t *testing.T) {
	f := newFleetGroupSource()
	manager, now, devices, err := fleetGroupAdmission(context.Background(), []fleetGroupSource{f})
	if err != nil {
		t.Fatal(err)
	}
	in := capacityFixtureInput(now)
	in.Input = f.inputs[0]
	identity := monitoringIdentity(f.binding, in.Input)
	linuxID := "agent_" + strings.Repeat("2", 32)
	missingID := "agent_" + strings.Repeat("3", 32)
	linuxIdentity := strings.Repeat("b", 64)
	devices[linuxID] = fleetGroupDevice{ID: linuxID, Name: "Linux private label", Platform: "linux", identity: linuxIdentity, expires: now.Add(30 * time.Second)}
	read := fleetGroupMaintenanceRead{binding: f.binding, devices: devices, group: store.FleetGroup{Manager: manager, ID: "group_" + strings.Repeat("1", 32), Name: "Office", Revision: 1, Members: []store.FleetGroupMember{{DeviceID: in.DeviceID, Identity: identity}, {DeviceID: linuxID, Identity: linuxIdentity}, {DeviceID: missingID, Identity: strings.Repeat("c", 64)}}}}
	authority := map[string]windowscapacity.Input{in.DeviceID: in}
	v, err := projectFleetGroupMaintenance(nil, read, authority, now)
	if err != nil || len(v.Members) != 1 || v.ExcludedLinuxMembers != 1 || v.UnavailableMembers != 1 || !v.AuthorityExpiresAt.Equal(now.Add(30*time.Second)) {
		t.Fatal(v, err)
	}
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), linuxID) || strings.Contains(string(raw), missingID) || strings.Contains(string(raw), linuxIdentity) {
		t.Fatal("excluded/unavailable identity disclosed")
	}
	in.CertificateHash = strings.Repeat("d", 64)
	authority[in.DeviceID] = in
	v, err = projectFleetGroupMaintenance(nil, read, authority, now)
	if err != nil || len(v.Members) != 0 || v.UnavailableMembers != 2 {
		t.Fatal("cross-snapshot mutable ID joined", v, err)
	}
	read.group.Manager = strings.Repeat("f", 64)
	if _, err = projectFleetGroupMaintenance(nil, read, authority, now); err == nil {
		t.Fatal("cross-manager projection")
	}
	read.group.Manager = manager
	read.group.Members = make([]store.FleetGroupMember, 51)
	if _, err = projectFleetGroupMaintenance(nil, read, authority, now); err == nil {
		t.Fatal("overbound stored members")
	}
}

func TestFleetGroupMaintenanceHandlerRoleOriginCSRFFinalResponse(t *testing.T) {
	h, f, op, path := groupMaintenanceHandlerFixture(t)
	v := groupMaintenanceRead(t, h, op, path)
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") },
	} {
		if w := groupMaintenanceRequest(h, op, "POST", path+"/start", groupMaintenanceBody(v, "all"), change); w.Code != 403 {
			t.Fatal("mutation boundary weakened", w.Code)
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
	if w := groupMaintenanceRequest(h, named, "POST", path+"/start", groupMaintenanceBody(v, "all")); w.Code != 403 {
		t.Fatal("named reader changed maintenance", w.Code)
	}
	// Source time can expire only at the final post-serialization clock sample.
	base, expires := f.now, f.now.Add(time.Second)
	f.inputs[0].AuthorityUntil = expires
	f.devices[0].AgentCertificate.ExpiresAt = &expires
	f.nowReads = 0
	f.onNow = func(n int) time.Time {
		if n >= 9 {
			return expires
		}
		return base
	}
	if w := groupMaintenanceRequest(h, op, "GET", path, nil); w.Code != 409 || strings.Contains(w.Body.String(), f.inputs[0].DeviceID) {
		t.Fatal("expired final group bytes released", w.Code, f.nowReads, w.Body.String())
	}
}

func TestFleetGroupMaintenanceProjectionMaximumBoundedMembers(t *testing.T) {
	f := newFleetGroupSource()
	read := fleetGroupMaintenanceRead{binding: f.binding, devices: map[string]fleetGroupDevice{}, group: store.FleetGroup{Manager: monitoringManager(f.binding), ID: "group_" + strings.Repeat("1", 32), Name: strings.Repeat("g", 80), Revision: store.MaxFleetGroupRevision, Members: []store.FleetGroupMember{}}}
	authority := map[string]windowscapacity.Input{}
	states := []store.WindowsMaintenanceState{}
	for i := 1; i <= 26; i++ {
		in := capacityFixtureInput(f.now)
		in.DeviceID = fmt.Sprintf("agent_%032x", i)
		identity := monitoringIdentity(f.binding, in.Input)
		read.group.Members = append(read.group.Members, store.FleetGroupMember{DeviceID: in.DeviceID, Identity: identity})
		read.devices[in.DeviceID] = fleetGroupDevice{ID: in.DeviceID, Name: strings.Repeat("n", 256), Platform: "windows", identity: identity, expires: in.AuthorityUntil}
		authority[in.DeviceID] = in
		for _, domain := range store.WindowsMaintenanceDomains() {
			states = append(states, store.WindowsMaintenanceState{Target: maintenanceTarget(in, domain), Revision: 4, ChangedAt: f.now, Windows: []store.WindowsMaintenanceWindow{{ID: 4, StartedAt: f.now, EndsAt: f.now.Add(time.Hour), Intent: "planned-work"}, {ID: 3, StartedAt: f.now.Add(-2 * time.Hour), EndsAt: f.now.Add(-time.Hour), Intent: "investigation"}, {ID: 2, StartedAt: f.now.Add(-4 * time.Hour), EndsAt: f.now.Add(-3 * time.Hour), Intent: "planned-work"}, {ID: 1, StartedAt: f.now.Add(-6 * time.Hour), EndsAt: f.now.Add(-5 * time.Hour), Intent: "planned-work"}}})
		}
	}
	if _, err := projectFleetGroupMaintenance(states, read, authority, f.now); err == nil {
		t.Fatal("26 Windows members projected")
	}
	read.group.Members = read.group.Members[:25]
	for i := 1; i <= 25; i++ {
		id, identity := fmt.Sprintf("agent_%032x", 100+i), fmt.Sprintf("%064x", 100+i)
		read.group.Members = append(read.group.Members, store.FleetGroupMember{DeviceID: id, Identity: identity})
		read.devices[id] = fleetGroupDevice{ID: id, Platform: "linux", identity: identity, expires: f.now.Add(time.Hour)}
	}
	v, err := projectFleetGroupMaintenance(states, read, authority, f.now)
	if err != nil || len(v.Members) != 25 || v.ExcludedLinuxMembers != 25 {
		t.Fatal("bounded 50-member group", err)
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw)+1 > 262144 {
		t.Fatal("maximum group exceeds wire budget", len(raw), err)
	}
	for i, member := range v.Members {
		if len(member.Targets) != 6 || i > 0 && v.Members[i-1].DeviceID >= member.DeviceID {
			t.Fatal("partial or unsorted member projection")
		}
		for j, target := range member.Targets {
			if target.Domain != store.WindowsMaintenanceDomains()[j] || target.DeviceID != member.DeviceID || len(target.Windows) != 4 {
				t.Fatal("partial target projection")
			}
		}
	}
}
