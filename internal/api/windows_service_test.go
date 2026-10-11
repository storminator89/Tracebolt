package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsservicehealth"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func installServiceFixture(t *testing.T, o operatorFixture) (*windowsCapacityMonitor, *fixtureWindowsCapacitySource) {
	m, f := installCapacityFixture(t, o)
	f.inputs[0].Services = windowsservicehealth.Sample{CollectedAt: f.now, Services: windowsmanaged.Section[windowsmanaged.Service]{Quality: "healthy", Complete: true, CountExact: true, ObservedCount: 2, Rows: []windowsmanaged.Service{{Name: "FixtureService", DisplayName: "Readable fixture service", State: "stopped"}, {Name: "Other", State: "running"}}}}
	return m, f
}
func serviceInput(f *fixtureWindowsCapacitySource) windowsservicehealth.Input {
	return windowsservicehealth.Input{Input: f.inputs[0].Input, Sample: f.inputs[0].Services}
}
func advanceService(f *fixtureWindowsCapacitySource, seconds int, state string) {
	advanceCapacity(f, seconds, 95)
	f.inputs[0].Services.CollectedAt = f.now
	f.inputs[0].Services.Services.Rows[0].State = state
}
func openServiceFixture(t *testing.T, m *windowsCapacityMonitor, f *fixtureWindowsCapacitySource) {
	t.Helper()
	if _, e := m.store.ConfigureWindowsService(context.Background(), serviceInput(f), true, []string{"FixtureService"}, 0, f.now); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 5; i++ {
		if i > 0 {
			advanceService(f, 30, "stopped")
		}
		if e := m.evaluate(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
}
func TestWindowsServiceAuthenticatedDefaultOffAndPolicy(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installServiceFixture(t, o)
	path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-services"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous access")
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	if e := m.evaluate(context.Background()); e != nil || f.reads != 0 {
		t.Fatal("default off source admission", e, f.reads)
	}
	if r, v := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 200 || v["status"] != "disabled" || v["inventory"] == nil {
		t.Fatal(r.StatusCode, v)
	}
	states, e := o.app.store.WindowsServiceStates(context.Background())
	if e != nil || len(states) != 0 {
		t.Fatal("GET persisted policy")
	}
	body := map[string]any{"enabled": true, "services": []string{"FixtureService"}, "expectedRevision": 0}
	if r, _ := o.call(t, "POST", path+"/policy", body, "", nil); r.StatusCode != 403 {
		t.Fatal("missing CSRF")
	}
	if r, _ := o.call(t, "POST", path+"/policy", body, csrf, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }); r.StatusCode != 403 {
		t.Fatal("wrong origin")
	}
	if r, v := o.call(t, "POST", path+"/policy", body, csrf, nil); r.StatusCode != 200 || v["status"] != "unknown" {
		t.Fatal("save evaluated source", r.StatusCode, v)
	}
	if r, _ := o.call(t, "POST", path+"/policy", body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("revision replay")
	}
	for i := 0; i < 5; i++ {
		if i > 0 {
			advanceService(f, 30, "stopped")
		}
		if e := m.evaluate(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	before, _ := o.app.store.WindowsServiceState(context.Background(), f.inputs[0].DeviceID)
	r, v := o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || v["status"] != "attention" || len(v["incidents"].([]any)) != 1 {
		t.Fatal(r.StatusCode, v)
	}
	after, _ := o.app.store.WindowsServiceState(context.Background(), f.inputs[0].DeviceID)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("GET changed state")
	}
	raw, _ := json.Marshal(v)
	for _, private := range []string{"certificateHash", "invitationId", "epoch", "receiptFloor", "captureFloor", "since", "pid"} {
		if strings.Contains(string(raw), `"`+private+`"`) {
			t.Fatal("private data escaped", private)
		}
	}
	f.now = f.now.Add(121 * time.Second)
	if r, v := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 200 || v["status"] != "unknown" || v["inventory"] != nil {
		t.Fatal("stale source", r.StatusCode, v)
	}
	if r, v := o.call(t, "POST", path+"/policy", map[string]any{"enabled": false, "services": []string{"FixtureService"}, "expectedRevision": 1}, csrf, nil); r.StatusCode != 200 || v["status"] != "disabled" || v["incidents"].([]any)[0].(map[string]any)["closedReason"] != "policy-changed" {
		t.Fatal("stale disable failed", r.StatusCode, v)
	}
	if r, _ := o.call(t, "POST", path+"/policy", map[string]any{"enabled": true, "services": []string{"FixtureService"}, "expectedRevision": 2}, csrf, nil); r.StatusCode != 409 {
		t.Fatal("stale re-enable")
	}
}
func TestWindowsServicePolicyStrictValidationAndNamedRead(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	_, f := installServiceFixture(t, o)
	_, v := o.login(t)
	csrf := v["csrfToken"].(string)
	path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-services"
	for _, body := range []any{map[string]any{}, map[string]any{"enabled": nil, "services": []string{}, "expectedRevision": 0}, map[string]any{"enabled": true, "services": nil, "expectedRevision": 0}, map[string]any{"enabled": true, "services": []string{}, "expectedRevision": 0}, map[string]any{"enabled": true, "services": []string{"FixtureService", "FixtureService"}, "expectedRevision": 0}, map[string]any{"enabled": true, "services": []string{"FixtureService"}, "expectedRevision": 0, "command": "start"}} {
		if r, _ := o.call(t, "POST", path+"/policy", body, csrf, nil); r.StatusCode != 400 {
			t.Fatal(r.StatusCode, body)
		}
	}
	for _, suffix := range []string{"?x=1", "/extra", "/policy/extra"} {
		if r, _ := o.call(t, "GET", path+suffix, nil, "", nil); r.StatusCode != 404 && r.StatusCode != 400 {
			t.Fatal("alias", r.StatusCode)
		}
	}
	for _, names := range [][]string{{"fixtureservice"}, {"missing"}} {
		if r, _ := o.call(t, "POST", path+"/policy", map[string]any{"enabled": true, "services": names, "expectedRevision": 0}, csrf, nil); r.StatusCode != 409 {
			t.Fatal("unsupported selection")
		}
	}
	named, _ := namedOperatorFixture(t)
	_, nf := installServiceFixture(t, named)
	_, nv := named.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	np := "/api/devices/" + nf.inputs[0].DeviceID + "/windows-services"
	if r, _ := named.call(t, "GET", np, nil, "", nil); r.StatusCode != 200 {
		t.Fatal("named read denied")
	}
	if r, _ := named.call(t, "POST", np+"/policy", map[string]any{"enabled": true, "services": []string{"FixtureService"}, "expectedRevision": 0}, nv["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("named gained write")
	}
}
func TestWindowsServiceAuthorityRechecksAndFailureEpoch(t *testing.T) {
	for _, mode := range []string{"revoked", "missing", "certificate", "invitation", "expiry", "source-error", "clock-rollback", "slow-read", "session"} {
		t.Run(mode, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			m, f := installServiceFixture(t, o)
			openServiceFixture(t, m, f)
			login, _ := o.login(t)
			id := f.inputs[0].DeviceID
			f.reads = 0
			f.onRead = func(n int) {
				if n != 2 {
					return
				}
				switch mode {
				case "revoked":
					f.inputs[0].Authorized = false
				case "missing":
					f.inputs = nil
				case "certificate":
					f.inputs[0].CertificateHash = strings.Repeat("d", 64)
				case "invitation":
					f.inputs[0].InvitationID = "invite_" + strings.Repeat("d", 32)
				case "expiry":
					f.now = f.inputs[0].AuthorityUntil
				case "source-error":
					f.err = errors.New("unavailable")
				case "clock-rollback":
					f.now = f.now.Add(-time.Second)
				case "slow-read":
					f.now = f.now.Add(6 * time.Second)
				case "session":
					o.server.Config.Handler.(*operatorHandler).auth.Logout(login.Cookies()[0].Value)
				}
			}
			if r, v := o.call(t, "GET", "/api/devices/"+id+"/windows-services", nil, "", nil); r.StatusCode == 200 || v["incidents"] != nil {
				t.Fatal("released without authority", r.StatusCode, v)
			}
		})
	}
	o := newOperatorFixture(t, time.Hour)
	m, f := installServiceFixture(t, o)
	openServiceFixture(t, m, f)
	o.login(t)
	epoch := m.epoch
	f.err = errors.New("failed source")
	if e := m.evaluate(context.Background()); e == nil || m.ready || m.epoch != "" {
		t.Fatal("failed evaluation remained ready")
	}
	f.err = nil
	advanceService(f, 30, "running")
	if e := m.evaluate(context.Background()); e != nil || m.epoch == epoch {
		t.Fatal("failed evaluation continuity", e)
	}
	if r, v := o.call(t, "GET", "/api/devices/"+f.inputs[0].DeviceID+"/windows-services", nil, "", nil); r.StatusCode != 200 || v["status"] != "attention" {
		t.Fatal(r.StatusCode, v)
	}
}
func TestWindowsServiceAndPercentagesShareSingleSourcePass(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installServiceFixture(t, o)
	base := f.inputs[0]
	f.inputs = nil
	for i := 1; i <= 25; i++ {
		in := base
		in.DeviceID = fmt.Sprintf("agent_%032x", i)
		in.InvitationID = fmt.Sprintf("invite_%032x", i)
		in.CertificateHash = fmt.Sprintf("%064x", i)
		f.inputs = append(f.inputs, in)
		if _, e := m.store.ConfigureWindowsService(context.Background(), windowsservicehealth.Input{Input: in.Input, Sample: in.Services}, true, []string{"FixtureService"}, 0, f.now); e != nil {
			t.Fatal(e)
		}
		if _, e := m.store.ConfigureWindowsCapacity(context.Background(), in, true, 90, 0, f.now); e != nil {
			t.Fatal(e)
		}
	}
	f.reads = 0
	if e := m.evaluate(context.Background()); e != nil || f.reads != 1 {
		t.Fatal("competing source passes", e, f.reads)
	}
	for _, in := range f.inputs {
		st, e := m.store.WindowsServiceState(context.Background(), in.DeviceID)
		if e != nil || st.Checks[0].Status != "pending" {
			t.Fatal(e, st)
		}
	}
}
func TestWindowsServiceFinalClockCannotReleaseExpiredHistory(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installServiceFixture(t, o)
	openServiceFixture(t, m, f)
	o.login(t)
	start := f.now
	expiry := start.Add(time.Second)
	f.inputs[0].AuthorityUntil = expiry
	clock := &capacityBoundaryClock{fixtureWindowsCapacitySource: f}
	clock.transition = func(n int) time.Time {
		if n >= 4 {
			return expiry
		}
		return start
	}
	m.source = clock
	if r, _ := o.call(t, "GET", "/api/devices/"+f.inputs[0].DeviceID+"/windows-services", nil, "", nil); r.StatusCode == 200 {
		t.Fatal("expired release")
	}
}
func TestWindowsServiceFinalMutationRecheckAndUnknownSelection(t *testing.T) {
	for _, mode := range []string{"revoked", "missing", "expiry", "clock-rollback", "changed-binding", "missing-row", "duplicate-row"} {
		t.Run(mode, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			_, f := installServiceFixture(t, o)
			_, login := o.login(t)
			id := f.inputs[0].DeviceID
			f.onRead = func(n int) {
				if n != 2 {
					return
				}
				switch mode {
				case "revoked":
					f.inputs[0].Authorized = false
				case "missing":
					f.inputs = nil
				case "expiry":
					f.now = f.inputs[0].AuthorityUntil
				case "clock-rollback":
					f.now = f.now.Add(-time.Second)
				case "changed-binding":
					f.inputs[0].InvitationID = "invite_" + strings.Repeat("4", 32)
				case "missing-row":
					f.inputs[0].Services.Services.Rows = []windowsmanaged.Service{}
					f.inputs[0].Services.Services.ObservedCount = 0
				case "duplicate-row":
					f.inputs[0].Services.Services.Rows = append(f.inputs[0].Services.Services.Rows, f.inputs[0].Services.Services.Rows[0])
					f.inputs[0].Services.Services.ObservedCount = 3
				}
			}
			r, _ := o.call(t, "POST", "/api/devices/"+id+"/windows-services/policy", map[string]any{"enabled": true, "services": []string{"FixtureService"}, "expectedRevision": 0}, login["csrfToken"].(string), nil)
			if r.StatusCode == 200 {
				t.Fatal("mutation passed changed authority/source")
			}
			st, e := o.app.store.WindowsServiceState(context.Background(), id)
			if e != nil || st.Policy.Enabled || st.Policy.Revision != 0 {
				t.Fatal("failed admission persisted", e, st)
			}
		})
	}
}
func TestWindowsServicePolicyResponseLossDoesNotRepeatMutation(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	_, f := installServiceFixture(t, o)
	_, login := o.login(t)
	id := f.inputs[0].DeviceID
	f.onRead = func(n int) {
		if n == 3 {
			f.err = errors.New("lost final authority read")
		}
	}
	body := map[string]any{"enabled": true, "services": []string{"FixtureService"}, "expectedRevision": 0}
	path := "/api/devices/" + id + "/windows-services"
	if r, _ := o.call(t, "POST", path+"/policy", body, login["csrfToken"].(string), nil); r.StatusCode == 200 {
		t.Fatal("uncertain response claimed success")
	}
	f.err = nil
	f.onRead = nil
	r, v := o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || v["policy"].(map[string]any)["revision"] != float64(1) || v["status"] != "unknown" {
		t.Fatal("read reconciliation", r.StatusCode, v)
	}
	if r, _ := o.call(t, "POST", path+"/policy", body, login["csrfToken"].(string), nil); r.StatusCode != 409 {
		t.Fatal("stale uncertain mutation repeated")
	}
}
func TestWindowsServiceResponseBoundIncludesFramingNewline(t *testing.T) {
	view := windowsservicehealth.View{}
	raw, e := json.Marshal(view)
	if e != nil {
		t.Fatal(e)
	}
	view.DeviceID = strings.Repeat("x", windowsservicehealth.MaxViewBytes-len(raw)-1)
	body, e := encodeWindowsServiceView(view)
	if e != nil || len(body) != windowsservicehealth.MaxViewBytes || body[len(body)-1] != '\n' {
		t.Fatal("exact framing bound", len(body), e)
	}
	view.DeviceID += "x"
	if _, e = encodeWindowsServiceView(view); e == nil {
		t.Fatal("one-byte framing overflow accepted")
	}
}
func TestWindowsServicePolicyAcceptsEightMaximumEscapedNames(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	_, f := installServiceFixture(t, o)
	_, login := o.login(t)
	names := []string{}
	rows := []windowsmanaged.Service{}
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("%02d", i) + strings.Repeat("&", 254)
		names = append(names, name)
		rows = append(rows, windowsmanaged.Service{Name: name, DisplayName: "Readable", State: "running"})
	}
	f.inputs[0].Services.Services.Rows = rows
	f.inputs[0].Services.Services.ObservedCount = 8
	body := map[string]any{"enabled": true, "services": names, "expectedRevision": 0}
	encoded, _ := json.Marshal(body)
	if len(encoded) <= 8192 {
		t.Fatal("fixture lacks maximum JSON escaping")
	}
	path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-services/policy"
	if r, v := o.call(t, "POST", path, body, login["csrfToken"].(string), nil); r.StatusCode != 200 {
		t.Fatal("valid bounded selection rejected", r.StatusCode, v)
	}
}
