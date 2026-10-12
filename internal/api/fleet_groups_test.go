package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/model"
	"localrmm/internal/store"
	"localrmm/internal/windowscontact"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fixtureFleetGroupSource struct {
	issuerEnd time.Time
	now       time.Time
	binding   enrollmentstate.Binding
	snapshots []enrollmentstate.Snapshot
	devices   []model.Device
	inputs    []windowscontact.Input
}

func (f *fixtureFleetGroupSource) IssuerValidity() (time.Time, time.Time, error) {
	end := f.issuerEnd
	if end.IsZero() {
		end = f.now.Add(30 * 24 * time.Hour)
	}
	return f.now.Add(-time.Hour), end, nil
}
func (f *fixtureFleetGroupSource) Now() time.Time                   { return f.now }
func (f *fixtureFleetGroupSource) Binding() enrollmentstate.Binding { return f.binding }
func (f *fixtureFleetGroupSource) Snapshots(context.Context) ([]enrollmentstate.Snapshot, error) {
	return append([]enrollmentstate.Snapshot{}, f.snapshots...), nil
}
func (f *fixtureFleetGroupSource) Devices(context.Context, time.Time) ([]model.Device, error) {
	return append([]model.Device{}, f.devices...), nil
}
func (f *fixtureFleetGroupSource) WindowsContactInputs(context.Context, time.Time) ([]windowscontact.Input, error) {
	return append([]windowscontact.Input{}, f.inputs...), nil
}
func newFleetGroupSource() *fixtureFleetGroupSource {
	now := time.Now().UTC().Round(0)
	in := contactFixtureInput(now)
	expires := in.AuthorityUntil
	b := enrollmentstate.Binding{InstanceID: "manager_fixture", Origin: "https://manager.invalid", Profile: "tls", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, IssuerFingerprint: strings.Repeat("a", 64)}
	return &fixtureFleetGroupSource{now: now, binding: b, snapshots: []enrollmentstate.Snapshot{{Binding: b, State: enrollmentstate.Activated, Platform: "windows", InvitationID: in.InvitationID, Approval: enrollmentstate.Approval{DeviceID: in.DeviceID}, Issuance: enrollmentstate.Issuance{CertificateHash: in.CertificateHash}}}, devices: []model.Device{{ID: in.DeviceID, Name: "Reviewed device", AgentCertificate: &model.AgentCertificate{ExpiresAt: &expires}}}, inputs: []windowscontact.Input{in}}
}
func TestFleetGroupsStableOriginalIdentityAndSafeProjection(t *testing.T) {
	f := newFleetGroupSource()
	sources := []fleetGroupSource{f}
	manager, now, devices, err := fleetGroupAdmission(context.Background(), sources)
	if err != nil || len(devices) != 1 {
		t.Fatal(err)
	}
	id := f.inputs[0].DeviceID
	g := store.FleetGroup{ID: "group_" + strings.Repeat("1", 32), Name: "Office", Revision: 1, Members: []store.FleetGroupMember{{DeviceID: id, Identity: devices[id].identity}}}
	// Renewal changes current expiry and labels, not original issued identity.
	next := f.now.Add(48 * time.Hour)
	f.devices[0].AgentCertificate.ExpiresAt = &next
	f.devices[0].Name = "New label"
	f.inputs[0].AuthorityUntil = next
	manager2, _, renewed, err := fleetGroupAdmission(context.Background(), sources)
	if err != nil || manager2 != manager || renewed[id].identity != devices[id].identity {
		t.Fatal("renewal changed group identity", err)
	}
	view := projectFleetGroups([]store.FleetGroup{g}, renewed, now)
	if len(view.Groups[0].MemberIDs) != 1 {
		t.Fatal("renewal lost membership")
	}
	raw, _ := json.Marshal(view)
	for _, private := range []string{"certificateHash", "invitation", "identity", f.snapshots[0].Issuance.CertificateHash} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private binding escaped")
		}
	}
	f.snapshots[0].Issuance.CertificateHash = strings.Repeat("d", 64)
	f.inputs[0].CertificateHash = strings.Repeat("d", 64)
	_, _, replaced, err := fleetGroupAdmission(context.Background(), sources)
	if err != nil {
		t.Fatal(err)
	}
	view = projectFleetGroups([]store.FleetGroup{g}, replaced, now)
	if len(view.Groups[0].MemberIDs) != 0 || view.Groups[0].UnavailableMembers != 1 {
		t.Fatal("replacement inherited membership")
	}
	f.snapshots[0].State = enrollmentstate.Revoked
	_, _, revoked, err := fleetGroupAdmission(context.Background(), sources)
	if err != nil || len(revoked) != 0 {
		t.Fatal("revocation still admitted")
	}
	view = projectFleetGroups([]store.FleetGroup{g}, revoked, now)
	raw, _ = json.Marshal(view)
	if strings.Contains(string(raw), "New label") || strings.Contains(string(raw), id) {
		t.Fatal("revoked identity leaked")
	}
	if _, _, _, err = fleetGroupAdmission(context.Background(), []fleetGroupSource{f, f}); err == nil {
		t.Fatal("ambiguous device ID accepted")
	}
}
func TestFleetGroupsOperatorCASRolesAndNoPolicyGrant(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	f := newFleetGroupSource()
	o.server.Config.Handler.(*operatorHandler).fleetGroupSources = []fleetGroupSource{f}
	path := "/api/fleet/groups"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous read")
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	body := map[string]any{"name": "Office", "memberIds": []string{f.inputs[0].DeviceID}, "expectedRevision": 0}
	if r, _ := o.call(t, "POST", path, body, "", nil); r.StatusCode != 403 {
		t.Fatal("missing CSRF")
	}
	if r, _ := o.call(t, "POST", path, body, csrf, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }); r.StatusCode != 403 {
		t.Fatal("wrong origin")
	}
	r, v := o.call(t, "POST", path, body, csrf, nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	group := v["groups"].([]any)[0].(map[string]any)
	id := group["id"].(string)
	body["removeUnavailableMembers"] = false
	if r, _ = o.call(t, "POST", path+"/"+id, body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("stale revision accepted")
	}
	f.snapshots[0].State = enrollmentstate.Revoked
	rename := map[string]any{"name": "Renamed", "memberIds": []string{}, "expectedRevision": 1, "removeUnavailableMembers": false}
	if r, v = o.call(t, "POST", path+"/"+id, rename, csrf, nil); r.StatusCode != 200 {
		t.Fatal("rename failed", r.StatusCode, v)
	}
	preserved := v["groups"].([]any)[0].(map[string]any)
	if preserved["unavailableMembers"] != float64(1) || len(preserved["memberIds"].([]any)) != 0 {
		t.Fatal("rename silently removed hidden member")
	}
	rename["expectedRevision"] = 2
	rename["removeUnavailableMembers"] = true
	if r, v = o.call(t, "POST", path+"/"+id, rename, csrf, nil); r.StatusCode != 200 {
		t.Fatal("explicit removal failed", r.StatusCode, v)
	}
	if v["groups"].([]any)[0].(map[string]any)["unavailableMembers"] != float64(0) {
		t.Fatal("explicit unavailable removal ignored")
	}
	if states, e := o.app.store.WindowsCapacityStates(context.Background()); e != nil || len(states) != 0 {
		t.Fatal("group enabled disk policy")
	}
	if states, e := o.app.store.WindowsResourceStates(context.Background()); e != nil || len(states) != 0 {
		t.Fatal("group enabled CPU/RAM")
	}
	for _, suffix := range []string{"?x=1", "?", "/extra/path"} {
		if r, _ = o.call(t, "GET", path+suffix, nil, "", nil); r.StatusCode == 200 {
			t.Fatal("ambiguous path accepted")
		}
	}
	named, _ := namedOperatorFixture(t)
	named.server.Config.Handler.(*operatorHandler).fleetGroupSources = []fleetGroupSource{f}
	_, nv := named.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	if r, _ = named.call(t, "GET", path, nil, "", nil); r.StatusCode != 200 {
		t.Fatal("named read denied")
	}
	if r, _ = named.call(t, "POST", path, body, nv["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("named write allowed")
	}
}

func TestFleetGroupsLinuxAdmissionAndIssuerExpiry(t *testing.T) {
	f := newFleetGroupSource()
	f.binding.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	f.snapshots[0].Binding = f.binding
	f.snapshots[0].Platform = "linux"
	_, _, devices, err := fleetGroupAdmission(context.Background(), []fleetGroupSource{f})
	if err != nil || len(devices) != 1 {
		t.Fatal("activated Linux member unavailable", err)
	}
	f.issuerEnd = f.now
	if _, _, _, err = fleetGroupAdmission(context.Background(), []fleetGroupSource{f}); err == nil {
		t.Fatal("expired issuer lent group admission")
	}
}
