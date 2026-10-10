package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowsresource"
)

func installResourceFixture(t *testing.T, o operatorFixture) (*windowsCapacityMonitor, *fixtureWindowsCapacitySource) {
	t.Helper()
	m, f := installCapacityFixture(t, o)
	f.inputs[0].CPU = f.inputs[0].Disk
	f.inputs[0].Memory = f.inputs[0].Disk
	return m, f
}
func advanceResources(f *fixtureWindowsCapacitySource, seconds int, cpu, memory float64) {
	advanceCapacity(f, seconds, 12)
	for i := range f.inputs {
		in := &f.inputs[i]
		in.CPU = in.Disk
		in.Memory = in.Disk
		in.CPU.Value = &cpu
		in.Memory.Value = &memory
	}
}
func resourcePath(id string, kind windowsresource.Kind) string {
	return "/api/devices/" + id + "/windows-resource/" + string(kind)
}
func openResourceFixture(t *testing.T, m *windowsCapacityMonitor, f *fixtureWindowsCapacitySource, kind windowsresource.Kind) {
	t.Helper()
	if _, err := m.store.ConfigureWindowsResource(context.Background(), f.inputs[0], kind, true, 90, 0, f.now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if i > 0 {
			advanceResources(f, 30, 95, 95)
		}
		if err := m.evaluate(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}
func TestWindowsResourceAuthenticatedIndependentPolicyPipeline(t *testing.T) {
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		t.Run(string(kind), func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			m, f := installResourceFixture(t, o)
			ctx := context.Background()
			path := resourcePath(f.inputs[0].DeviceID, kind)
			if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
				t.Fatal("anonymous resource access")
			}
			_, login := o.login(t)
			csrf := login["csrfToken"].(string)
			for _, route := range []string{path, resourcePath(f.inputs[0].DeviceID, windowsresource.CPU), resourcePath(f.inputs[0].DeviceID, windowsresource.Memory)} {
				if r, v := o.call(t, "GET", route, nil, "", nil); r.StatusCode != 200 || v["status"] != "disabled" {
					t.Fatal("implicit opt-in", r.StatusCode, v)
				}
			}
			if states, err := m.store.WindowsResourceStates(ctx); err != nil || len(states) != 0 {
				t.Fatal("GET persisted defaults", err)
			}
			if r, v := o.call(t, "POST", path+"/policy", map[string]any{"enabled": true, "thresholdPercent": 90, "expectedRevision": 0}, csrf, nil); r.StatusCode != 200 || v["status"] != "unknown" || v["metric"] != string(kind) || v["schemaVersion"] != windowsresource.SchemaVersion {
				t.Fatal("policy evaluated or lost metric", r.StatusCode, v)
			}
			for i := 0; i < 3; i++ {
				if i > 0 {
					advanceResources(f, 30, 95, 95)
				}
				if err := m.evaluate(ctx); err != nil {
					t.Fatal(err)
				}
			}
			before, err := m.store.WindowsResourceState(ctx, f.inputs[0].DeviceID, kind)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				r, v := o.call(t, "GET", path, nil, "", nil)
				if r.StatusCode != 200 || v["status"] != "pressure" || v["metric"] != string(kind) || len(v["incidents"].([]any)) != 1 {
					t.Fatal(r.StatusCode, v)
				}
				raw, _ := json.Marshal(v)
				for _, private := range []string{"certificateHash", "invitationId", "epoch", "receiptFloor", "captureFloor", "assessment"} {
					if strings.Contains(string(raw), private) {
						t.Fatal("private state escaped", private)
					}
				}
			}
			after, err := m.store.WindowsResourceState(ctx, f.inputs[0].DeviceID, kind)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("GET changed state", err)
			}
			other := windowsresource.CPU
			if kind == other {
				other = windowsresource.Memory
			}
			sibling, err := m.store.WindowsResourceState(ctx, f.inputs[0].DeviceID, other)
			if err != nil || sibling.Assessment.Policy.Enabled {
				t.Fatal("sibling policy adopted", err)
			}
			disk, err := m.store.WindowsCapacityState(ctx, f.inputs[0].DeviceID)
			if err != nil || disk.Policy.Enabled {
				t.Fatal("disk policy adopted", err)
			}
			if r, v := o.call(t, "POST", path+"/policy", map[string]any{"enabled": false, "thresholdPercent": 90, "expectedRevision": 1}, csrf, nil); r.StatusCode != 200 || v["status"] != "disabled" || v["incidents"].([]any)[0].(map[string]any)["closedReason"] != "policy-changed" {
				t.Fatal("disable claimed recovery", r.StatusCode, v)
			}
			f.reads = 0
			f.err = errors.New("must not read while disabled")
			if err := m.evaluate(ctx); err != nil || f.reads != 0 {
				t.Fatal("disabled resource read enrollment", err, f.reads)
			}
		})
	}
}
func TestWindowsResourceRouteBodyAndReadRoleBoundaries(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	_, f := installResourceFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	id := f.inputs[0].DeviceID
	for _, path := range []string{"/api/devices/" + id + "/windows-resource", "/api/devices/" + id + "/windows-resource/disk", resourcePath(id, windowsresource.CPU) + "/", resourcePath(id, windowsresource.CPU) + "?metric=memory", resourcePath(id, windowsresource.CPU) + "/policy/extra"} {
		if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 404 && r.StatusCode != 400 {
			t.Fatal("ambiguous route", path, r.StatusCode)
		}
	}
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		path := resourcePath(id, kind) + "/policy"
		for _, body := range []any{map[string]any{}, map[string]any{"enabled": true, "thresholdPercent": 90, "expectedRevision": 0, "metric": "cpu"}, map[string]any{"enabled": true, "thresholdPercent": 90.5, "expectedRevision": 0}, map[string]any{"enabled": true, "thresholdPercent": 49, "expectedRevision": 0}, map[string]any{"enabled": true, "thresholdPercent": 100, "expectedRevision": 0}} {
			if r, _ := o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 400 {
				t.Fatal("invalid body", r.StatusCode, body)
			}
		}
		if r, _ := o.call(t, "POST", path, map[string]any{"enabled": true, "thresholdPercent": 90, "expectedRevision": 0}, "", nil); r.StatusCode != 403 {
			t.Fatal("CSRF bypass", r.StatusCode)
		}
	}
	named, _ := namedOperatorFixture(t)
	_, nf := installResourceFixture(t, named)
	_, nv := named.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		path := resourcePath(nf.inputs[0].DeviceID, kind)
		if r, _ := named.call(t, "GET", path, nil, "", nil); r.StatusCode != 200 {
			t.Fatal("reader denied")
		}
		if r, _ := named.call(t, "POST", path+"/policy", map[string]any{"enabled": true, "thresholdPercent": 90, "expectedRevision": 0}, nv["csrfToken"].(string), nil); r.StatusCode != 403 {
			t.Fatal("reader wrote")
		}
	}
}
func TestWindowsResourceRechecksCurrentAuthorityBeforeWriteAndRelease(t *testing.T) {
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		for _, method := range []string{"GET", "POST"} {
			modes := []string{"revoked", "missing", "certificate", "invitation", "expiry", "source-error", "clock-rollback", "slow-read"}
			// Writes already hold the operator mutation lease. Logout is tested
			// concurrently below: a synchronous logout here would deadlock the
			// fixture on its own expected lease, not model an actual session loss.
			if method == "GET" {
				modes = append(modes, "session")
			}
			for _, mode := range modes {
				t.Run(string(kind)+"/"+method+"/"+mode, func(t *testing.T) {
					o := newOperatorFixture(t, time.Hour)
					m, f := installResourceFixture(t, o)
					if method == "GET" {
						openResourceFixture(t, m, f, kind)
					}
					login, v := o.login(t)
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
							f.inputs[0].CertificateHash = strings.Repeat("f", 64)
						case "invitation":
							f.inputs[0].InvitationID = "invite_" + strings.Repeat("f", 32)
						case "expiry":
							f.now = f.inputs[0].AuthorityUntil
						case "source-error":
							f.err = errors.New("fixture read failure")
						case "clock-rollback":
							f.now = f.now.Add(-time.Second)
						case "slow-read":
							f.now = f.now.Add(6 * time.Second)
						case "session":
							o.server.Config.Handler.(*operatorHandler).auth.Logout(login.Cookies()[0].Value)
						}
					}
					path := resourcePath(id, kind)
					var body any
					if method == "POST" {
						path += "/policy"
						body = map[string]any{"enabled": true, "thresholdPercent": 90, "expectedRevision": 0}
					}
					r, result := o.call(t, method, path, body, v["csrfToken"].(string), nil)
					if r.StatusCode == 200 || result["incidents"] != nil {
						t.Fatal("lost authority released private result", r.StatusCode, result)
					}
					if method == "POST" {
						states, err := m.store.WindowsResourceStates(context.Background())
						if err != nil || len(states) != 0 {
							t.Fatal("lost authority saved policy", err)
						}
					}
				})
			}
		}
	}
}
func TestWindowsResourceFinalClockAndNewestSourceTruth(t *testing.T) {
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		t.Run(string(kind), func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			m, f := installResourceFixture(t, o)
			openResourceFixture(t, m, f, kind)
			o.login(t)
			path := resourcePath(f.inputs[0].DeviceID, kind)
			advanceResources(f, 30, 20, 20)
			if r, v := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 200 || v["status"] != "unknown" || len(v["incidents"].([]any)) != 1 {
				t.Fatal("new accepted tuple inherited old evaluation", r.StatusCode, v)
			}
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
			if r, v := o.call(t, "GET", path, nil, "", nil); r.StatusCode == 200 || v["incidents"] != nil {
				t.Fatal("final clock released expired history")
			}
		})
	}
}
func TestWindowsResourceMonitorSharesOneSourceTransactionAtCapacity(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installResourceFixture(t, o)
	ctx := context.Background()
	base := f.inputs[0]
	f.inputs = nil
	for n := 1; n <= 25; n++ {
		in := base
		in.DeviceID = fmt.Sprintf("agent_%032x", n)
		in.InvitationID = fmt.Sprintf("invite_%032x", n)
		f.inputs = append(f.inputs, in)
		if _, err := m.store.ConfigureWindowsCapacity(ctx, in, true, 90, 0, f.now); err != nil {
			t.Fatal(err)
		}
		for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
			if _, err := m.store.ConfigureWindowsResource(ctx, in, kind, true, 90, 0, f.now); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := 0; i < 3; i++ {
		if i > 0 {
			advanceResources(f, 30, 95, 95)
		}
		f.reads = 0
		if err := m.evaluate(ctx); err != nil || f.reads != 1 {
			t.Fatal("source reads not coordinated", err, f.reads)
		}
	}
	states, err := m.store.WindowsResourceStates(ctx)
	if err != nil || len(states) != 50 {
		t.Fatal(err, len(states))
	}
	for _, state := range states {
		if state.Assessment.Status != "pressure" {
			t.Fatal("enabled resource not evaluated")
		}
	}
	f.inputs = append(f.inputs, f.inputs[0])
	if m.evaluate(ctx) == nil || m.ready {
		t.Fatal("duplicate authority accepted")
	}
	after, err := m.store.WindowsResourceStates(ctx)
	if err != nil || !reflect.DeepEqual(states, after) {
		t.Fatal("invalid source partially committed", err)
	}
}
func TestWindowsResourceMissingMetricAndMonitorRestartRemainUnknown(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installResourceFixture(t, o)
	ctx := context.Background()
	in := f.inputs[0]
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		if _, err := m.store.ConfigureWindowsResource(ctx, in, kind, true, 90, 0, f.now); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if i > 0 {
			advanceResources(f, 30, 95, 95)
		}
		if err := m.evaluate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	advanceResources(f, 30, 20, 20)
	f.inputs[0].CPU.Value = nil
	if err := m.evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	cpu, err := m.store.WindowsResourceState(ctx, in.DeviceID, windowsresource.CPU)
	if err != nil || cpu.Assessment.Status != "unknown" || cpu.Assessment.Incidents[0].ResolvedAt != nil {
		t.Fatal("missing CPU fell back to RAM/disk", err)
	}
	memory, err := m.store.WindowsResourceState(ctx, in.DeviceID, windowsresource.Memory)
	if err != nil || memory.Assessment.Status != "pressure" || memory.Assessment.RecoverySince == nil {
		t.Fatal("missing CPU contaminated RAM", err)
	}
	restarted, err := newWindowsCapacityMonitor(o.app.store, f)
	if err != nil {
		t.Fatal(err)
	}
	o.app.windowsCapacity = restarted
	o.login(t)
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		if r, v := o.call(t, "GET", resourcePath(in.DeviceID, kind), nil, "", nil); r.StatusCode != 200 || v["status"] != "unknown" {
			t.Fatal("restart borrowed confidence", r.StatusCode, v)
		}
	}
	f.inputs = nil
	if err := restarted.evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		s, err := m.store.WindowsResourceState(ctx, in.DeviceID, kind)
		if err != nil || s.Assessment.Status != "unknown" || s.Assessment.RecoverySince != nil || s.Assessment.SequenceFloor == 0 {
			t.Fatal("omission lost continuity boundaries", err)
		}
	}
}

func TestWindowsResourceLogoutRevokesBeforeWriteAndJoinsLease(t *testing.T) {
	for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
		t.Run(string(kind), func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			_, f := installResourceFixture(t, o)
			login, v := o.login(t)
			session, err := o.server.Config.Handler.(*operatorHandler).auth.Lookup(login.Cookies()[0].Value)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			f.onRead = func(n int) {
				if n == 2 {
					go func() {
						o.server.Config.Handler.(*operatorHandler).auth.Logout(login.Cookies()[0].Value)
						close(done)
					}()
					select {
					case <-session.Lifetime().Done():
					case <-time.After(time.Second):
						t.Fatal("logout did not revoke session lifetime")
					}
					select {
					case <-done:
						t.Fatal("logout bypassed active mutation lease")
					default:
					}
				}
			}
			path := resourcePath(f.inputs[0].DeviceID, kind)
			r, _ := o.call(t, "POST", path+"/policy", map[string]any{"enabled": true, "thresholdPercent": 90, "expectedRevision": 0}, v["csrfToken"].(string), nil)
			if r.StatusCode != 401 {
				t.Fatal("revoked mutation released a result", r.StatusCode)
			}
			states, err := o.app.store.WindowsResourceStates(context.Background())
			if err != nil || len(states) != 0 {
				t.Fatal("revoked policy persisted", err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("logout never joined after mutation lease release")
			}
			if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
				t.Fatal("post-logout response released")
			}
		})
	}
}
