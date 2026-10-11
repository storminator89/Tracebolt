package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/model"
	"localrmm/internal/windowscapacity"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fixtureWindowsCapacitySource struct {
	now    time.Time
	inputs []windowscapacity.Input
	err    error
	reads  int
	onRead func(int)
}

func (f *fixtureWindowsCapacitySource) Now() time.Time { return f.now }
func (f *fixtureWindowsCapacitySource) WindowsCapacityInputs(ctx context.Context, _ time.Time) ([]windowscapacity.Input, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	f.reads++
	if f.onRead != nil {
		f.onRead(f.reads)
	}
	if f.err != nil {
		return nil, f.err
	}
	return append([]windowscapacity.Input{}, f.inputs...), nil
}
func capacityFixtureInput(at time.Time) windowscapacity.Input {
	v := 95.0
	return windowscapacity.Input{Input: contactFixtureInput(at), Disk: model.Metric{Value: &v, Quality: "healthy", Unit: "%", Source: "fixture quota-aware system volume", CollectedAt: at}}
}
func installCapacityFixture(t *testing.T, o operatorFixture) (*windowsCapacityMonitor, *fixtureWindowsCapacitySource) {
	t.Helper()
	at := time.Now().UTC().Round(0)
	f := &fixtureWindowsCapacitySource{now: at, inputs: []windowscapacity.Input{capacityFixtureInput(at)}}
	m, e := newWindowsCapacityMonitor(o.app.store, f)
	if e != nil {
		t.Fatal(e)
	}
	o.app.windowsCapacity = m
	return m, f
}
func advanceCapacity(f *fixtureWindowsCapacitySource, seconds int, value float64) {
	f.now = f.now.Add(time.Duration(seconds) * time.Second)
	for i := range f.inputs {
		v := value
		f.inputs[i].Disk.Value = &v
		f.inputs[i].ReceivedAt = f.now
		f.inputs[i].Disk.CollectedAt = f.now
		f.inputs[i].Sequence++
	}
}
func openCapacityFixture(t *testing.T, m *windowsCapacityMonitor, f *fixtureWindowsCapacitySource) {
	t.Helper()
	if _, e := m.store.ConfigureWindowsCapacity(context.Background(), f.inputs[0], true, 90, 0, f.now); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		if i > 0 {
			advanceCapacity(f, 30, 95)
		}
		if e := m.evaluate(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
}
func TestWindowsCapacityAuthenticatedReadOnlyAndPolicyMutation(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installCapacityFixture(t, o)
	path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-capacity"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous access")
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	if e := m.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
	states, e := o.app.store.WindowsCapacityStates(context.Background())
	if e != nil || len(states) != 0 {
		t.Fatal("disabled monitor created state")
	}
	if r, v := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 200 || v["status"] != "disabled" || v["policy"].(map[string]any)["enabled"] != false {
		t.Fatal(r.StatusCode, v)
	}
	states, _ = o.app.store.WindowsCapacityStates(context.Background())
	if len(states) != 0 {
		t.Fatal("GET created policy")
	}
	body := map[string]any{"enabled": true, "thresholdPercent": 90, "expectedRevision": 0}
	if r, _ := o.call(t, "POST", path+"/policy", body, "", nil); r.StatusCode != 403 {
		t.Fatal("missing CSRF")
	}
	if r, _ := o.call(t, "POST", path+"/policy", body, csrf, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }); r.StatusCode != 403 {
		t.Fatal("wrong Origin")
	}
	if r, v := o.call(t, "POST", path+"/policy", body, csrf, nil); r.StatusCode != 200 || v["status"] != "unknown" || v["policy"].(map[string]any)["revision"] != float64(1) {
		t.Fatal("policy save evaluated", r.StatusCode, v)
	}
	if r, _ := o.call(t, "POST", path+"/policy", body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("stale revision replay")
	}
	for i := 0; i < 3; i++ {
		if i > 0 {
			advanceCapacity(f, 30, 95)
		}
		if e := m.evaluate(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	before, _ := o.app.store.WindowsCapacityState(context.Background(), f.inputs[0].DeviceID)
	for i := 0; i < 2; i++ {
		r, v := o.call(t, "GET", path, nil, "", nil)
		if r.StatusCode != 200 || v["status"] != "pressure" || len(v["incidents"].([]any)) != 1 {
			t.Fatal(r.StatusCode, v)
		}
		raw, _ := json.Marshal(v)
		for _, private := range []string{"certificateHash", "invitationId", "epoch", "pendingObservation", "receiptFloor", "captureFloor"} {
			if strings.Contains(string(raw), private) {
				t.Fatal("private ledger escaped", private)
			}
		}
	}
	after, _ := o.app.store.WindowsCapacityState(context.Background(), f.inputs[0].DeviceID)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("GET changed history")
	}
	if r, v := o.call(t, "POST", path+"/policy", map[string]any{"enabled": false, "thresholdPercent": 90, "expectedRevision": 1}, csrf, nil); r.StatusCode != 200 || v["status"] != "disabled" || v["incidents"].([]any)[0].(map[string]any)["closedReason"] != "policy-changed" {
		t.Fatal("disable claimed recovery", r.StatusCode, v)
	}
}
func TestWindowsCapacityPolicyStrictValidationAndReadRole(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	_, f := installCapacityFixture(t, o)
	_, v := o.login(t)
	csrf := v["csrfToken"].(string)
	path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-capacity/policy"
	for _, body := range []any{map[string]any{}, map[string]any{"enabled": nil, "thresholdPercent": 90, "expectedRevision": 0}, map[string]any{"enabled": true, "thresholdPercent": 90, "expectedRevision": nil}, map[string]any{"enabled": true, "thresholdPercent": 49, "expectedRevision": 0}, map[string]any{"enabled": true, "thresholdPercent": 100, "expectedRevision": 0}, map[string]any{"enabled": true, "thresholdPercent": 90.1, "expectedRevision": 0}, map[string]any{"enabled": "true", "thresholdPercent": 90, "expectedRevision": 0}, map[string]any{"enabled": true, "thresholdPercent": 90, "expectedRevision": 0, "service": "ignored"}} {
		if r, _ := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 400 {
			t.Fatal("malformed policy", r.StatusCode, body)
		}
	}
	for _, suffix := range []string{"?x=1", "/extra"} {
		if r, _ := o.call(t, "POST", path+suffix, map[string]any{}, csrf, nil); r.StatusCode != 404 && r.StatusCode != 400 {
			t.Fatal("ambiguous route", r.StatusCode)
		}
	}
	named, _ := namedOperatorFixture(t)
	_, nf := installCapacityFixture(t, named)
	_, nv := named.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	np := "/api/devices/" + nf.inputs[0].DeviceID + "/windows-capacity"
	if r, _ := named.call(t, "GET", np, nil, "", nil); r.StatusCode != 200 {
		t.Fatal("reader denied")
	}
	if r, _ := named.call(t, "POST", np+"/policy", map[string]any{"enabled": true, "thresholdPercent": 90, "expectedRevision": 0}, nv["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("read role gained write")
	}
}
func TestWindowsCapacityAuthorityRecheckedAndMissingDevicesHidden(t *testing.T) {
	for _, kind := range []string{"revoked", "missing", "certificate", "invitation", "expiry", "source-error", "clock-rollback", "slow-read", "session"} {
		t.Run(kind, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			m, f := installCapacityFixture(t, o)
			openCapacityFixture(t, m, f)
			login, _ := o.login(t)
			id := f.inputs[0].DeviceID
			f.reads = 0
			f.onRead = func(n int) {
				if n != 2 {
					return
				}
				switch kind {
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
					f.err = errors.New("invented unavailable")
				case "clock-rollback":
					f.now = f.now.Add(-time.Second)
				case "slow-read":
					f.now = f.now.Add(6 * time.Second)
				case "session":
					o.server.Config.Handler.(*operatorHandler).auth.Logout(login.Cookies()[0].Value)
				}
			}
			if r, v := o.call(t, "GET", "/api/devices/"+id+"/windows-capacity", nil, "", nil); r.StatusCode == 200 || v["incidents"] != nil {
				t.Fatal("authority failure released history", r.StatusCode, v)
			}
		})
	}
}
func TestWindowsCapacityMonitorFailureRestartOmissionAndCancellation(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installCapacityFixture(t, o)
	openCapacityFixture(t, m, f)
	o.login(t)
	id := f.inputs[0].DeviceID
	ctx := context.Background()
	before, _ := o.app.store.WindowsCapacityState(ctx, id)
	f.err = errors.New("fixture unavailable")
	if m.evaluate(ctx) == nil || m.ready || m.epoch != "" {
		t.Fatal("failure retained continuity")
	}
	after, _ := o.app.store.WindowsCapacityState(ctx, id)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failure changed ledger")
	}
	f.err = nil
	if r, v := o.call(t, "GET", "/api/devices/"+id+"/windows-capacity", nil, "", nil); r.StatusCode != 200 || v["status"] != "unknown" || len(v["incidents"].([]any)) != 1 {
		t.Fatal("failure erased uncertainty", r.StatusCode, v)
	}
	restarted, e := newWindowsCapacityMonitor(o.app.store, f)
	if e != nil {
		t.Fatal(e)
	}
	o.app.windowsCapacity = restarted
	if r, v := o.call(t, "GET", "/api/devices/"+id+"/windows-capacity", nil, "", nil); r.StatusCode != 200 || v["status"] != "unknown" {
		t.Fatal("restart fabricated continuity", r.StatusCode, v)
	}
	f.inputs = nil
	if e := restarted.evaluate(ctx); e != nil {
		t.Fatal(e)
	}
	if r, v := o.call(t, "GET", "/api/devices/"+id+"/windows-capacity", nil, "", nil); r.StatusCode != 404 || v["policy"] != nil {
		t.Fatal("omission exposed live state", r.StatusCode, v)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if e := restarted.evaluate(canceled); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e := o.app.RunWindowsCapacityMonitor(canceled, nil); e != nil {
		t.Fatal(e)
	}
}
func TestWindowsCapacityMonitorCapacityUsesOneSourceRead(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installCapacityFixture(t, o)
	ctx := context.Background()
	base := f.inputs[0]
	f.inputs = nil
	for n := 1; n <= 25; n++ {
		in := base
		in.DeviceID = fmt.Sprintf("agent_%032x", n)
		in.InvitationID = fmt.Sprintf("invite_%032x", n)
		f.inputs = append(f.inputs, in)
		if _, e := m.store.ConfigureWindowsCapacity(ctx, in, true, 90, 0, f.now); e != nil {
			t.Fatal(e)
		}
	}
	for i := 0; i < 3; i++ {
		if i > 0 {
			advanceCapacity(f, 30, 95)
		}
		if e := m.evaluate(ctx); e != nil {
			t.Fatal(e)
		}
	}
	advanceCapacity(f, 30, 95)
	f.reads = 0
	step, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := time.Now()
	if e := m.evaluate(step); e != nil {
		t.Fatal(e)
	}
	elapsed := time.Since(start)
	if f.reads != 1 {
		t.Fatal("per-device full authority revalidation", f.reads)
	}
	states, e := m.store.WindowsCapacityStates(ctx)
	if e != nil || len(states) != 25 {
		t.Fatal(e)
	}
	for _, state := range states {
		if state.Status != "pressure" || len(state.Incidents) != 1 {
			t.Fatal("at-capacity history lost")
		}
	}
	t.Logf("25 enabled devices with retained history: one authority read, elapsed %s, fixed 5s evaluation budget", elapsed)
	f.inputs = append(f.inputs, f.inputs[0])
	before := states
	if e = m.evaluate(ctx); e == nil {
		t.Fatal("duplicate source accepted")
	}
	after, _ := m.store.WindowsCapacityStates(ctx)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("bad source partially committed")
	}
}

func TestWindowsCapacityOmissionAndRevocationResetConfirmation(t *testing.T) {
	for _, missing := range []bool{true, false} {
		t.Run(fmt.Sprint("missing=", missing), func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			m, f := installCapacityFixture(t, o)
			ctx := context.Background()
			in := f.inputs[0]
			if _, e := m.store.ConfigureWindowsCapacity(ctx, in, true, 90, 0, f.now); e != nil {
				t.Fatal(e)
			}
			if e := m.evaluate(ctx); e != nil {
				t.Fatal(e)
			}
			advanceCapacity(f, 30, 95)
			if missing {
				f.inputs = nil
			} else {
				f.inputs[0].Authorized = false
			}
			if e := m.evaluate(ctx); e != nil {
				t.Fatal(e)
			}
			state, e := m.store.WindowsCapacityState(ctx, in.DeviceID)
			if e != nil || state.Status != "unknown" || state.PendingSince != nil || state.SequenceFloor == 0 {
				t.Fatal("unavailable identity retained pending timer or erased floor", e, state)
			}
			f.inputs = []windowscapacity.Input{in}
			advanceCapacity(f, 30, 95)
			if e := m.evaluate(ctx); e != nil {
				t.Fatal(e)
			}
			state, e = m.store.WindowsCapacityState(ctx, in.DeviceID)
			if e != nil || state.Status != "pending" || len(state.Incidents) != 0 {
				t.Fatal("return borrowed pre-omission continuity", e, state)
			}
		})
	}
}
