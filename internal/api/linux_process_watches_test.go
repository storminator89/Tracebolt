package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/linuxprocesswatch"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const processWatchPath = "/api/devices/agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/linux-process-watches"

type fixtureProcessWatchSource struct {
	now       time.Time
	input     linuxprocesswatch.Input
	reads     int
	err       error
	guardHook func(int)
	nowHook   func()
}

func (f *fixtureProcessWatchSource) Now() time.Time {
	if f.nowHook != nil {
		f.nowHook()
	}
	return f.now
}
func (f *fixtureProcessWatchSource) WithLinuxProcessWatch(ctx context.Context, id string, names []string, epoch string, fn func(linuxprocesswatch.Input, func(time.Time) error) error) error {
	f.reads++
	if f.err != nil {
		return f.err
	}
	if id != f.input.DeviceID || !f.input.Authorized {
		return enrollmentstate.ErrNotFound
	}
	in := f.input
	in.Epoch = epoch
	sum := sha256.Sum256([]byte(in.Identity + epoch))
	in.SourceToken = "processsource_" + hex.EncodeToString(sum[:16])
	in.Counts = []linuxprocesswatch.Count{}
	for _, name := range names {
		c := linuxprocesswatch.Count{Name: name}
		for _, existing := range f.input.Counts {
			if existing.Name == name {
				c = existing
			}
		}
		in.Counts = append(in.Counts, c)
	}
	calls := 0
	guard := func(at time.Time) error {
		calls++
		if f.guardHook != nil {
			f.guardHook(calls)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if f.now.Before(at) || !f.now.Before(in.AuthorityUntil) {
			return enrollmentstate.ErrProof
		}
		return nil
	}
	if err := guard(f.now); err != nil {
		return err
	}
	if err := fn(in, guard); err != nil {
		return err
	}
	return guard(f.now)
}
func installProcessWatchFixture(t *testing.T, o operatorFixture) (*linuxProcessWatchMonitor, *fixtureProcessWatchSource) {
	t.Helper()
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	f := &fixtureProcessWatchSource{input: linuxprocesswatch.Input{DeviceID: "agent_" + strings.Repeat("a", 32), Identity: strings.Repeat("b", 64), Authorized: true, Available: true, Reason: "none", AuthorityUntil: at.Add(24 * time.Hour)}}
	processWatchGenerationFixture(f, 1, 0, 0)
	m, err := newLinuxProcessWatchMonitor(o.app.store, f)
	if err != nil {
		t.Fatal(err)
	}
	o.app.linuxProcessWatches = m
	return m, f
}
func processWatchGenerationFixture(f *fixtureProcessWatchSource, seq int, active, unknown uint32) {
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC).Add(time.Duration(seq) * 10 * time.Second)
	f.now = at.Add(3 * time.Second)
	f.input.Sample = &linuxprocesswatch.Generation{Sequence: fmt.Sprint(seq), GenerationID: fmt.Sprintf("sample_%032x", seq), ManifestHash: strings.Repeat("e", 64), CaptureStartedAt: at, CaptureFinishedAt: at.Add(time.Second), ReceivedAt: at.Add(2 * time.Second), TotalRows: 10, UnidentifiedRows: unknown}
	f.input.Counts = []linuxprocesswatch.Count{{Name: "daemon", ActiveCount: active}}
}
func processWatchPolicyFixture(v map[string]any, n int, enabled bool) map[string]any {
	names := []string{}
	failures := 0
	if enabled {
		names = []string{"daemon"}
		failures = 2
	}
	return map[string]any{"requestId": fmt.Sprintf("processrequest_%032x", n), "expectedRevision": v["revision"], "sourceToken": v["source"].(map[string]any)["token"], "enabled": enabled, "names": names, "consecutiveFailures": failures, "retentionAcknowledged": enabled}
}
func TestLinuxProcessWatchesAPIWholeLifecycle(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installProcessWatchFixture(t, o)
	if r, _ := o.call(t, "GET", processWatchPath, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous read", r.StatusCode)
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	response, v := o.call(t, "GET", processWatchPath, nil, "", nil)
	if response.StatusCode != 200 || v["revision"] != "0" || v["policy"].(map[string]any)["enabled"] != false {
		t.Fatal(response.StatusCode, v)
	}
	fixtures := map[string]any{"defaultOff": v}
	states, e := o.app.store.LinuxProcessWatchStates(context.Background())
	if e != nil || len(states) != 0 {
		t.Fatal("GET adopted source", e)
	}
	enable := processWatchPolicyFixture(v, 1, true)
	if r, _ := o.call(t, "POST", processWatchPath+"/policy", enable, "", nil); r.StatusCode != 403 {
		t.Fatal("missing CSRF", r.StatusCode)
	}
	response, v = o.call(t, "POST", processWatchPath+"/policy", enable, csrf, nil)
	if response.StatusCode != 200 || v["revision"] != "1" {
		t.Fatal(response.StatusCode, v)
	}
	fixtures["enabled"] = v
	if r, replay := o.call(t, "POST", processWatchPath+"/policy", enable, csrf, nil); r.StatusCode != 200 || replay["revision"] != "1" {
		t.Fatal("replay", r.StatusCode, replay)
	}
	for seq := 2; seq <= 3; seq++ {
		processWatchGenerationFixture(f, seq, 0, 0)
		if e = m.evaluate(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	response, v = o.call(t, "GET", processWatchPath, nil, "", nil)
	incidents := v["incidents"].([]any)
	if response.StatusCode != 200 || len(incidents) != 1 || incidents[0].(map[string]any)["state"] != "open" || v["revision"] != "1" {
		t.Fatal("no background incident", response.StatusCode, v)
	}
	fixtures["open"] = v
	ack := map[string]any{"requestId": fmt.Sprintf("processrequest_%032x", 2), "expectedRevision": v["revision"], "sourceToken": v["source"].(map[string]any)["token"], "incidentId": incidents[0].(map[string]any)["id"]}
	response, v = o.call(t, "POST", processWatchPath+"/acknowledge", ack, csrf, nil)
	if response.StatusCode != 200 || v["revision"] != "2" || v["incidents"].([]any)[0].(map[string]any)["acknowledgedAt"] == nil {
		t.Fatal("ack", response.StatusCode, v)
	}
	fixtures["acknowledged"] = v
	processWatchGenerationFixture(f, 4, 1, 0)
	if e = m.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
	_, v = o.call(t, "GET", processWatchPath, nil, "", nil)
	fixtures["recovering"] = v
	processWatchGenerationFixture(f, 5, 1, 0)
	if e = m.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
	_, v = o.call(t, "GET", processWatchPath, nil, "", nil)
	if v["incidents"].([]any)[0].(map[string]any)["state"] != "recovered" {
		t.Fatal("recovery", v)
	}
	fixtures["recovered"] = v
	response, v = o.call(t, "POST", processWatchPath+"/policy", processWatchPolicyFixture(v, 3, false), csrf, nil)
	if response.StatusCode != 200 || v["policy"].(map[string]any)["enabled"] != false {
		t.Fatal("disable", response.StatusCode, v)
	}
	fixtures["disabled"] = v
	raw, _ := json.MarshalIndent(fixtures, "", "  ")
	for _, private := range []string{f.input.Identity, "AuthorityUntil", "commandLine", "password", "identity", "epoch"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private field", private)
		}
	}
	if os.Getenv("TRACEBOLT_UPDATE_PROCESS_WATCH_FIXTURE") == "1" {
		if e := os.WriteFile(filepath.Join("..", "..", "web", "src", "linux-process-watches-go-fixture.json"), append(raw, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
}
func TestLinuxProcessWatchesAPIStrictBoundary(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	_, _ = installProcessWatchFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	_, v := o.call(t, "GET", processWatchPath, nil, "", nil)
	good := processWatchPolicyFixture(v, 1, true)
	for _, mode := range []string{"null", "missing", "extra", "numeric_revision", "leading_zero", "duplicate_names", "unsorted_names", "empty", "bad_request", "bad_source", "retention", "wrong_threshold", "invalid_unicode", "null_name"} {
		t.Run(mode, func(t *testing.T) {
			in := map[string]any{}
			for k, v := range good {
				in[k] = v
			}
			switch mode {
			case "null":
				in["enabled"] = nil
			case "missing":
				delete(in, "enabled")
			case "extra":
				in["shell"] = "none"
			case "numeric_revision":
				in["expectedRevision"] = 0
			case "leading_zero":
				in["expectedRevision"] = "00"
			case "duplicate_names":
				in["names"] = []string{"daemon", "daemon"}
			case "unsorted_names":
				in["names"] = []string{"z", "a"}
			case "empty":
				in["names"] = []string{}
			case "bad_request":
				in["requestId"] = "1"
			case "bad_source":
				in["sourceToken"] = "1"
			case "retention":
				in["retentionAcknowledged"] = false
			case "wrong_threshold":
				in["consecutiveFailures"] = 1
			case "invalid_unicode":
				in["names"] = []string{"x\n"}
			case "null_name":
				in["names"] = []any{nil}
			}
			if r, v := o.call(t, "POST", processWatchPath+"/policy", in, csrf, nil); r.StatusCode != 400 {
				t.Fatal(r.StatusCode, v)
			}
		})
	}
	for _, raw := range []string{`{"requestId":"a","requestId":"b"}`, `{"names":["\ud800"]}`, `{} {}`} {
		if r, v := o.call(t, "POST", processWatchPath+"/policy", nil, csrf, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(raw))
			r.ContentLength = int64(len(raw))
		}); r.StatusCode != 400 {
			t.Fatal(r.StatusCode, v)
		}
	}
	for _, q := range []struct {
		method, path string
		body         any
		status       int
	}{{"POST", processWatchPath, map[string]any{}, 405}, {"GET", processWatchPath + "/policy", nil, 405}, {"GET", processWatchPath + "/other", nil, 404}, {"GET", processWatchPath + "?names=daemon", nil, 400}, {"GET", processWatchPath, map[string]any{}, 400}} {
		if r, v := o.call(t, q.method, q.path, q.body, csrf, nil); r.StatusCode != q.status {
			t.Fatal(q, r.StatusCode, v)
		}
	}
}
func TestLinuxProcessWatchesAPINamedReadAndSourceGuard(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	_, f := installProcessWatchFixture(t, o)
	_, login := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	response, v := o.call(t, "GET", processWatchPath, nil, "", nil)
	if response.StatusCode != 200 || v["canManage"] != false {
		t.Fatal(response.StatusCode, v)
	}
	if r, _ := o.call(t, "POST", processWatchPath+"/policy", processWatchPolicyFixture(v, 1, true), login["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("named read changed policy", r.StatusCode)
	}
	f.input.Authorized = false
	if r, _ := o.call(t, "GET", processWatchPath, nil, "", nil); r.StatusCode != 404 {
		t.Fatal("revoked source", r.StatusCode)
	}
}
func TestLinuxProcessWatchesAPIGuardAndReadPurity(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installProcessWatchFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	_, v := o.call(t, "GET", processWatchPath, nil, "", nil)
	enable := processWatchPolicyFixture(v, 1, true)
	f.guardHook = func(n int) {
		if n == 3 {
			f.now = f.input.AuthorityUntil
		}
	}
	if r, _ := o.call(t, "POST", processWatchPath+"/policy", enable, csrf, nil); r.StatusCode != 404 {
		t.Fatal("expiry guard", r.StatusCode)
	}
	state, e := o.app.store.LinuxProcessWatchState(context.Background(), f.input.DeviceID)
	if e != nil || state.Revision != 0 {
		t.Fatal("guard committed", state, e)
	}
	f.guardHook = nil
	processWatchGenerationFixture(f, 1, 0, 0)
	r, v := o.call(t, "POST", processWatchPath+"/policy", enable, csrf, nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	processWatchGenerationFixture(f, 2, 0, 0)
	if e = m.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
	before, e := o.app.store.LinuxProcessWatchState(context.Background(), f.input.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	processWatchGenerationFixture(f, 3, 0, 0)
	_, v = o.call(t, "GET", processWatchPath, nil, "", nil)
	if len(v["incidents"].([]any)) != 0 || v["checks"].([]any)[0].(map[string]any)["condition"] != "unknown" {
		t.Fatal("read evaluated generation", v)
	}
	after, e := o.app.store.LinuxProcessWatchState(context.Background(), f.input.DeviceID)
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read mutated", e)
	}
	f.err = errors.New("unavailable")
	if r, _ := o.call(t, "GET", processWatchPath, nil, "", nil); r.StatusCode != 503 {
		t.Fatal("source failure", r.StatusCode)
	}
}

func TestLinuxProcessWatchesAPIConflictStaleDisableAndSourceReplacement(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installProcessWatchFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	_, v := o.call(t, "GET", processWatchPath, nil, "", nil)
	original := processWatchPolicyFixture(v, 1, true)
	r, v := o.call(t, "POST", processWatchPath+"/policy", original, csrf, nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	changed := processWatchPolicyFixture(v, 1, true)
	changed["names"] = []string{"different"}
	if r, _ := o.call(t, "POST", processWatchPath+"/policy", changed, csrf, nil); r.StatusCode != 409 {
		t.Fatal("request ID reused", r.StatusCode)
	}
	stale := processWatchPolicyFixture(v, 2, true)
	stale["expectedRevision"] = "0"
	if r, _ := o.call(t, "POST", processWatchPath+"/policy", stale, csrf, nil); r.StatusCode != 409 {
		t.Fatal("stale revision accepted", r.StatusCode)
	}
	f.input.Available = false
	f.input.Reason = "newer_attempt"
	f.input.Sample = nil
	if r, _ := o.call(t, "POST", processWatchPath+"/policy", processWatchPolicyFixture(v, 3, true), csrf, nil); r.StatusCode != 409 {
		t.Fatal("unknown source enabled", r.StatusCode)
	}
	r, v = o.call(t, "POST", processWatchPath+"/policy", processWatchPolicyFixture(v, 4, false), csrf, nil)
	if r.StatusCode != 200 || v["policy"].(map[string]any)["enabled"] != false {
		t.Fatal("unable to stop unavailable source", r.StatusCode, v)
	}
	f.input.Available = true
	f.input.Reason = "none"
	processWatchGenerationFixture(f, 2, 0, 0)
	r, v = o.call(t, "POST", processWatchPath+"/policy", processWatchPolicyFixture(v, 5, true), csrf, nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	for seq := 3; seq <= 4; seq++ {
		processWatchGenerationFixture(f, seq, 0, 0)
		if e := m.evaluate(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	f.input.Identity = strings.Repeat("f", 64)
	r, v = o.call(t, "GET", processWatchPath, nil, "", nil)
	if r.StatusCode != 200 || v["policy"].(map[string]any)["sourceMatches"] != false || v["incidents"].([]any)[0].(map[string]any)["sourceCurrent"] != false || v["checks"].([]any)[0].(map[string]any)["condition"] != "unknown" {
		t.Fatal("source replaced", r.StatusCode, v)
	}
	if e := m.evaluate(context.Background()); e != nil {
		t.Fatal(e)
	}
	_, v = o.call(t, "GET", processWatchPath, nil, "", nil)
	if v["policy"].(map[string]any)["enabled"] != false || v["incidents"].([]any)[0].(map[string]any)["state"] != "monitoring_stopped" {
		t.Fatal("identity inherited policy", v)
	}
}

func TestLinuxProcessWatchesAPIPostCommit409RequiresReadReconciliation(t *testing.T) {
	for _, mode := range []string{"clock_regression", "response_expiry"} {
		t.Run(mode, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			_, f := installProcessWatchFixture(t, o)
			_, login := o.login(t)
			csrf := login["csrfToken"].(string)
			if mode == "response_expiry" {
				f.now = f.input.Sample.CaptureStartedAt.Add(linuxprocesswatch.MaxAge - time.Second)
			}
			_, v := o.call(t, "GET", processWatchPath, nil, "", nil)
			command := processWatchPolicyFixture(v, 1, true)
			original := f.now
			calls := 0
			f.nowHook = func() {
				calls++
				if mode == "clock_regression" && calls == 2 {
					f.now = original.Add(-time.Nanosecond)
				}
				if mode == "response_expiry" && calls == 3 {
					f.now = original.Add(time.Second)
				}
			}
			response, body := o.call(t, "POST", processWatchPath+"/policy", command, csrf, nil)
			if response.StatusCode != 409 {
				t.Fatal("fixture failed to reach final response guard", response.StatusCode, body, calls)
			}
			f.nowHook = nil
			f.now = original.Add(time.Second)
			state, e := o.app.store.LinuxProcessWatchState(context.Background(), f.input.DeviceID)
			if e != nil || state.Revision != 1 || !state.Policy.Enabled {
				t.Fatal("post-commit write not present", state, e)
			}
			response, v = o.call(t, "GET", processWatchPath, nil, "", nil)
			if response.StatusCode != 200 || v["revision"] != "1" || v["policy"].(map[string]any)["enabled"] != true || v["lastRequest"].(map[string]any)["requestId"] != command["requestId"] {
				t.Fatal("GET did not reconcile original uncertain command", response.StatusCode, v)
			}
		})
	}
}
