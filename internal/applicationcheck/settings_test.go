package applicationcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const settingsOrigin = "https://manager.example.test:8443"
const settingsActor = "shared-administrator"

func settingsTarget(id, kind string) json.RawMessage {
	v := map[string]any{"kind": kind, "id": id, "allowedAddresses": []string{"8.8.8.8"}, "allowPrivateLAN": false}
	switch kind {
	case kindHTTP:
		v["url"], v["plaintextHTTPAcknowledged"] = "https://application.example.test/status", false
	case kindDNS:
		v["host"] = "application.example.test"
	case kindTCP:
		v["host"], v["port"] = "application.example.test", 443
	}
	raw, _ := json.Marshal(v)
	return raw
}
func privateSettingsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
func testSettings(t *testing.T, factory func(Config) *Monitor) (*Settings, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("protected settings are Linux-only")
	}
	dir := privateSettingsDir(t)
	if factory == nil {
		factory = func(c Config) *Monitor {
			m := New(c)
			m.check = func(context.Context, target, string, time.Time) Result {
				t.Error("unexpected outbound check")
				return Result{}
			}
			return m
		}
	}
	s, err := newSettings(dir, "", settingsOrigin, "tls", Config{}, time.Now, factory)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}
func saveSettings(t *testing.T, s *Settings, targets ...json.RawMessage) {
	t.Helper()
	if len(targets) == 0 {
		targets = []json.RawMessage{settingsTarget("app", kindHTTP)}
	}
	if err := s.Change(context.Background(), SettingsChange{ExpectedRevision: s.View().Revision, Operation: "save", IntervalSeconds: 60, Targets: targets}, settingsActor); err != nil {
		t.Fatal(err)
	}
}
func enableSettings(t *testing.T, s *Settings) {
	t.Helper()
	if err := s.Change(context.Background(), SettingsChange{ExpectedRevision: s.View().Revision, Operation: "enable", ChecksFromManagerAcknowledged: true, DestinationsAcknowledged: true, PlaintextAcknowledged: s.saved.Profile == "http-test"}, settingsActor); err != nil {
		t.Fatal(err)
	}
}
func disableSettings(t *testing.T, s *Settings) {
	t.Helper()
	if err := s.Change(context.Background(), SettingsChange{ExpectedRevision: s.View().Revision, Operation: "disable"}, settingsActor); err != nil {
		t.Fatal(err)
	}
}
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for injected lifecycle")
		var zero T
		return zero
	}
}

func TestApplicationSettingsDefaultsSaveEnableDisableAndReload(t *testing.T) {
	s, dir := testSettings(t, nil)
	initial := s.View()
	if initial.SchemaVersion != SettingsSchemaVersion || initial.Mode != "managed" || initial.Configured || initial.Enabled || initial.Blocked || !validSettingsRevision(initial.Revision) || initial.IntervalSeconds != 60 || len(initial.Targets) != 0 || initial.Targets == nil {
		t.Fatalf("bad default: %#v", initial)
	}
	if !s.Matches("", settingsOrigin, "tls") || s.Matches("other", settingsOrigin, "tls") || s.Matches("", "https://other.example.test", "tls") || s.Matches("", settingsOrigin, "http-test") || !(*Settings)(nil).Matches("", "", "") {
		t.Fatal("binding mismatch")
	}
	info, err := os.Stat(filepath.Join(dir, SettingsFile))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("settings not owner-only")
	}
	if status := s.Status(); status.Enabled || len(status.Items) != 0 || status.SchemaVersion != SchemaVersionV2 {
		t.Fatal("new managed status not inert")
	}
	saveSettings(t, s, settingsTarget("http", kindHTTP), settingsTarget("dns", kindDNS), settingsTarget("tcp", kindTCP))
	draft := s.View()
	if !draft.Configured || draft.Enabled || draft.Revision == initial.Revision || len(draft.Targets) != 3 {
		t.Fatal("save did not create disabled draft")
	}
	for i, raw := range draft.Targets {
		if _, err := parseTarget(raw, ConfigSchemaVersionV2, "tls"); err != nil {
			t.Fatalf("view target %d violates per-kind schema", i)
		}
	}
	draft.Targets[0][0] = 'x'
	if s.View().Targets[0][0] != '{' {
		t.Fatal("settings view aliases state")
	}
	enableSettings(t, s)
	if !s.View().Enabled || !s.Status().Enabled || s.Status().Items[0].Reason != "not_checked" {
		t.Fatal("explicit enable did not install fresh inert status")
	}
	reloaded, err := NewSettings(dir, "", settingsOrigin, "tls", Config{})
	if err != nil || !reloaded.View().Enabled || reloaded.Status().Items[0].ObservedAt != nil {
		t.Fatal("enabled protected state not loaded inertly")
	}
	if _, err := NewSettings(dir, "other", settingsOrigin, "tls", Config{}); err != ErrConfiguration {
		t.Fatal("manager binding ignored")
	}
	if _, err := NewSettings(dir, "", "https://other.example.test", "tls", Config{}); err != ErrConfiguration {
		t.Fatal("origin binding ignored")
	}
	if _, err := NewSettings(dir, "", settingsOrigin, "http-test", Config{}); err != ErrConfiguration {
		t.Fatal("profile binding ignored")
	}
	before := s.View().Revision
	disableSettings(t, s)
	if s.View().Enabled || !s.View().Configured || s.View().Revision == before || len(s.View().Targets) != 3 || s.Status().Enabled {
		t.Fatal("disable lost draft or failed to rotate")
	}
	before = s.View().Revision
	disableSettings(t, s)
	if s.View().Revision == before {
		t.Fatal("accepted repeated disable reused revision")
	}
	enableSettings(t, s)
	saveSettings(t, s, settingsTarget("changed", kindDNS))
	if s.View().Enabled || s.Status().Enabled || len(s.View().Targets) != 1 {
		t.Fatal("save of enabled settings must disable")
	}
	for _, text := range []string{fmt.Sprint(s), fmt.Sprintf("%#v", s), fmt.Sprint(s.config), fmt.Sprintf("%#v", s.saved), fmt.Sprintf("%+v", SettingsChange{Targets: []json.RawMessage{settingsTarget("secret", kindHTTP)}})} {
		if !strings.Contains(text, "redacted") || strings.Contains(text, "example.test") {
			t.Fatal("private configuration formatter leaked")
		}
	}
}

func TestApplicationSettingsExternalDisabledAndEnabledOverrideManaged(t *testing.T) {
	s, dir := testSettings(t, nil)
	saveSettings(t, s)
	enableSettings(t, s)
	managed, _ := os.ReadFile(filepath.Join(dir, SettingsFile))
	for _, schema := range []string{ConfigSchemaVersion, ConfigSchemaVersionV2} {
		c, err := Load(writeConfig(t, []byte(`{"schemaVersion":"`+schema+`","enabled":false}`)), "", settingsOrigin, "tls")
		if err != nil || !c.external {
			t.Fatal("disabled explicit file lost provenance")
		}
		external, err := NewSettings(dir, "", settingsOrigin, "tls", c)
		if err != nil {
			t.Fatal(err)
		}
		view := external.View()
		if view.Mode != "external" || view.Revision != "" || view.Configured || view.Enabled || view.Blocked || view.IntervalSeconds != 60 || view.Targets == nil || len(view.Targets) != 0 {
			t.Fatal("disabled external view")
		}
		if err := external.Change(context.Background(), SettingsChange{Operation: "disable"}, settingsActor); err != ErrSettingsUnavailable {
			t.Fatal("external file editable")
		}
	}
	c, err := loadFixture(t, configFixture())
	if err != nil {
		t.Fatal(err)
	}
	external, err := NewSettings("not-needed", "", settingsOrigin, "tls", c)
	if err != nil || external.View().Mode != "external" || !external.View().Enabled || len(external.View().Targets) != 1 {
		t.Fatal("enabled external config not authoritative")
	}
	if _, err = parseTarget(external.View().Targets[0], ConfigSchemaVersionV2, "tls"); err != nil {
		t.Fatal("legacy external HTTP not projected as v2 typed review")
	}
	after, _ := os.ReadFile(filepath.Join(dir, SettingsFile))
	if !bytes.Equal(managed, after) {
		t.Fatal("external settings altered managed state")
	}
	view := (*Settings)(nil).View()
	if view.Mode != "unavailable" || view.IntervalSeconds != 60 || view.Targets == nil || view.Revision != "" {
		t.Fatal("unavailable shape")
	}
	if (*Settings)(nil).Status().SchemaVersion != SchemaVersion {
		t.Fatal("nil status compatibility")
	}
}

func TestApplicationSettingsStrictChangesAndConsent(t *testing.T) {
	s, _ := testSettings(t, nil)
	saveSettings(t, s)
	baseline := s.View().Revision
	cases := []SettingsChange{
		{Operation: "save", IntervalSeconds: 59, Targets: []json.RawMessage{settingsTarget("a", kindDNS)}},
		{Operation: "save", IntervalSeconds: 3601, Targets: []json.RawMessage{settingsTarget("a", kindDNS)}},
		{Operation: "save", IntervalSeconds: 60},
		{Operation: "save", IntervalSeconds: 60, Targets: []json.RawMessage{}},
		{Operation: "save", IntervalSeconds: 60, Targets: []json.RawMessage{settingsTarget("a", kindDNS), settingsTarget("a", kindHTTP)}},
		{Operation: "save", IntervalSeconds: 60, Targets: []json.RawMessage{settingsTarget("a", kindDNS)}, ChecksFromManagerAcknowledged: true},
		{Operation: "enable", DestinationsAcknowledged: true},
		{Operation: "enable", ChecksFromManagerAcknowledged: true},
		{Operation: "enable", ChecksFromManagerAcknowledged: true, DestinationsAcknowledged: true, PlaintextAcknowledged: true},
		{Operation: "enable", ChecksFromManagerAcknowledged: true, DestinationsAcknowledged: true, Targets: []json.RawMessage{}},
		{Operation: "enable", ChecksFromManagerAcknowledged: true, DestinationsAcknowledged: true, IntervalSeconds: 60},
		{Operation: "disable", PlaintextAcknowledged: true},
		{Operation: "disable", Targets: []json.RawMessage{}},
		{Operation: "replace"},
	}
	for _, raw := range []string{
		`null`, `{}`, `{"kind":"dns","id":"app","host":"localhost","allowedAddresses":["127.0.0.1"],"allowPrivateLAN":true}`,
		`{"kind":"dns","id":"app","host":"app.test","port":443,"allowedAddresses":["8.8.8.8"],"allowPrivateLAN":false}`,
		`{"kind":"http","id":"app","url":"http://app.test/","allowedAddresses":["8.8.8.8"],"allowPrivateLAN":false,"plaintextHTTPAcknowledged":false}`,
		`{"kind":"tcp","id":"app","host":"10.0.0.1","port":22,"allowedAddresses":["10.0.0.1"],"allowPrivateLAN":false}`,
		`{"kind":"dns","id":"app","id":"other","host":"app.test","allowedAddresses":["8.8.8.8"],"allowPrivateLAN":false}`,
		`{"kind":"dns","id":"app","host":"app.test","allowedAddresses":["8.8.8.8"],"allowPrivateLAN":null}`,
	} {
		cases = append(cases, SettingsChange{Operation: "save", IntervalSeconds: 60, Targets: []json.RawMessage{json.RawMessage(raw)}})
	}
	many := SettingsChange{Operation: "save", IntervalSeconds: 60}
	for i := 0; i < MaxTargets+1; i++ {
		many.Targets = append(many.Targets, settingsTarget(fmt.Sprintf("app-%d", i), kindDNS))
	}
	cases = append(cases, many)
	for i, change := range cases {
		change.ExpectedRevision = baseline
		if err := s.Change(context.Background(), change, settingsActor); err != ErrConfiguration || s.View().Revision != baseline {
			t.Fatalf("invalid change %d accepted or mutated state: %v", i, err)
		}
	}
	if err := s.Change(context.Background(), SettingsChange{ExpectedRevision: strings.Repeat("0", 32), Operation: "disable"}, settingsActor); err != ErrSettingsConflict {
		t.Fatal("stale revision accepted")
	}
	if err := s.Change(context.Background(), SettingsChange{ExpectedRevision: baseline, Operation: "disable"}, "operator_00000000000000000000000000000000"); err != ErrConfiguration {
		t.Fatal("invalid actor accepted")
	}
	http, err := NewSettings(privateSettingsDir(t), "", "http://manager.example.test:8080", "http-test", Config{})
	if err != nil {
		t.Fatal(err)
	}
	saveSettings(t, http)
	if err := http.Change(context.Background(), SettingsChange{ExpectedRevision: http.View().Revision, Operation: "enable", ChecksFromManagerAcknowledged: true, DestinationsAcknowledged: true}, settingsActor); err != ErrConfiguration {
		t.Fatal("HTTP operator transport consent omitted")
	}
	enableSettings(t, http)
}

func TestApplicationSettingsCancelJoinBusyAndLateResults(t *testing.T) {
	started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var active atomic.Int32
	s, _ := testSettings(t, func(c Config) *Monitor {
		m := New(c)
		m.check = func(ctx context.Context, _ target, _ string, _ time.Time) Result {
			if active.Add(1) != 1 {
				t.Error("overlapping probes")
			}
			defer active.Add(-1)
			close(started)
			<-ctx.Done()
			close(cancelled)
			<-release // Deliberately late dependency: disable must join it.
			return Result{State: "ok", Reason: "old_generation"}
		}
		return m
	})
	saveSettings(t, s)
	enableSettings(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	receive(t, started)
	if err := s.Run(context.Background()); err != ErrRunning {
		t.Fatal("duplicate supervisor admitted")
	}
	old := s.monitor
	changeDone := make(chan error, 1)
	revision := s.View().Revision
	go func() {
		changeDone <- s.Change(context.Background(), SettingsChange{ExpectedRevision: revision, Operation: "disable"}, settingsActor)
	}()
	receive(t, cancelled)
	if err := s.Change(context.Background(), SettingsChange{ExpectedRevision: revision, Operation: "disable"}, settingsActor); err != ErrSettingsBusy {
		t.Fatal("concurrent mutation not rejected busy")
	}
	select {
	case <-changeDone:
		t.Fatal("disable returned before old worker joined")
	default:
	}
	close(release)
	if err := receive(t, changeDone); err != nil {
		t.Fatal(err)
	}
	if active.Load() != 0 || s.Status().Enabled || old.Status().Items[0].ObservedAt != nil {
		t.Fatal("late old generation published or worker remains")
	}
	saveSettings(t, s, settingsTarget("new", kindDNS))
	if s.Status().Enabled || len(s.Status().Items) != 0 {
		t.Fatal("old rows relabeled under saved draft")
	}
	cancel()
	if err := receive(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestApplicationSettingsCooldownAcrossRepeatedToggles(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	attempts := make(chan string, 10)
	idle := make(chan struct{}, 10)
	waits := make(chan time.Duration, 10)
	ticks := make(chan struct{})
	s, err := newSettings(privateSettingsDir(t), "", settingsOrigin, "tls", Config{}, now, func(c Config) *Monitor {
		m := New(c)
		m.now = now
		m.check = func(_ context.Context, target target, _ string, _ time.Time) Result {
			attempts <- target.ID
			return Result{State: "ok", Reason: "fixture"}
		}
		m.wait = func(ctx context.Context, _ time.Duration) bool {
			idle <- struct{}{}
			<-ctx.Done()
			return false
		}
		return m
	})
	if err != nil {
		t.Fatal(err)
	}
	s.wait = func(ctx context.Context, delay time.Duration) bool {
		waits <- delay
		select {
		case <-ctx.Done():
			return false
		case <-ticks:
			return true
		}
	}
	saveSettings(t, s)
	enableSettings(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	if receive(t, attempts) != "app" {
		t.Fatal("missing first attempt")
	}
	receive(t, idle)
	for i := 0; i < 3; i++ {
		disableSettings(t, s)
		saveSettings(t, s, settingsTarget("new", kindDNS))
		enableSettings(t, s)
		if delay := receive(t, waits); delay != time.Minute {
			t.Fatalf("cooldown changed: %s", delay)
		}
		if status := s.Status(); len(status.Items) != 1 || status.Items[0].ID != "new" || status.Items[0].ObservedAt != nil || status.Items[0].Reason != "not_checked" {
			t.Fatal("new generation inherited observation")
		}
		select {
		case <-attempts:
			t.Fatal("toggle bypassed cooldown")
		default:
		}
	}
	clock.Add(int64(time.Minute))
	ticks <- struct{}{}
	if receive(t, attempts) != "new" {
		t.Fatal("new draft did not run after cooldown")
	}
	receive(t, idle)
	cancel()
	if err := receive(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestApplicationSettingsStrictProtectedStateAndAudit(t *testing.T) {
	s, dir := testSettings(t, nil)
	saveSettings(t, s)
	enableSettings(t, s)
	path := filepath.Join(dir, SettingsFile)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var base map[string]any
	if json.Unmarshal(original, &base) != nil {
		t.Fatal("bad fixture")
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown":                   func(v map[string]any) { v["endpoint"] = "secret" },
		"missing":                   func(v map[string]any) { delete(v, "enabled") },
		"case alias":                func(v map[string]any) { v["Enabled"] = v["enabled"]; delete(v, "enabled") },
		"null targets":              func(v map[string]any) { v["targets"] = nil },
		"null audit":                func(v map[string]any) { v["audit"] = nil },
		"wrong schema":              func(v map[string]any) { v["schemaVersion"] = "tracebolt.application-checks-config.v2" },
		"bad revision":              func(v map[string]any) { v["revision"] = "lowercase-32-hex-required" },
		"bad generation":            func(v map[string]any) { v["generation"] = "" },
		"no audit approval":         func(v map[string]any) { v["audit"] = []any{} },
		"bad actor":                 func(v map[string]any) { v["audit"].([]any)[1].(map[string]any)["actor"] = "arbitrary user text" },
		"audit target injection":    func(v map[string]any) { v["audit"].([]any)[1].(map[string]any)["url"] = "https://secret.test" },
		"audit operation":           func(v map[string]any) { v["audit"].([]any)[1].(map[string]any)["operation"] = "test" },
		"audit null":                func(v map[string]any) { v["audit"].([]any)[1] = nil },
		"audit time":                func(v map[string]any) { v["audit"].([]any)[1].(map[string]any)["timestamp"] = "0001-01-01T00:00:00Z" },
		"audit revision":            func(v map[string]any) { v["audit"].([]any)[1].(map[string]any)["revision"] = strings.Repeat("0", 32) },
		"audit generation":          func(v map[string]any) { v["audit"].([]any)[1].(map[string]any)["generation"] = strings.Repeat("0", 32) },
		"enabled without enable":    func(v map[string]any) { v["audit"].([]any)[1].(map[string]any)["operation"] = "disable" },
		"unconfigured with targets": func(v map[string]any) { v["configured"] = false },
		"target extra": func(v map[string]any) {
			v["targets"].([]any)[0].(map[string]any)["headers"] = map[string]string{"secret": "secret"}
		},
		"target denied": func(v map[string]any) {
			v["targets"].([]any)[0].(map[string]any)["allowedAddresses"] = []string{"169.254.169.254"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			_ = json.Unmarshal(original, &value)
			mutate(value)
			raw, _ := json.Marshal(value)
			if os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("write")
			}
			if _, err := NewSettings(dir, "", settingsOrigin, "tls", Config{}); err != ErrConfiguration {
				t.Fatal("malformed saved settings accepted")
			}
		})
	}
	for _, raw := range [][]byte{
		append(append([]byte{}, original...), []byte(` {}`)...),
		bytes.Replace(original, []byte(`"enabled":true`), []byte(`"enabled":true,"enabled":false`), 1),
		bytes.Replace(original, []byte(`"operation":"enable"`), []byte(`"operation":"enable","operation":"disable"`), 1),
		bytes.Repeat([]byte(" "), settingsFileLimit+1),
	} {
		_ = os.WriteFile(path, raw, 0600)
		if _, err := NewSettings(dir, "", settingsOrigin, "tls", Config{}); err != ErrConfiguration {
			t.Fatal("ambiguous/oversized saved state accepted")
		}
	}
	_ = os.WriteFile(path, original, 0600)
	for i := 0; i < settingsAuditLimit+3; i++ {
		disableSettings(t, s)
	}
	raw, _ := os.ReadFile(path)
	saved, err := parseSavedSettings(raw)
	if err != nil || len(saved.Audit) != settingsAuditLimit {
		t.Fatal("audit is not bounded")
	}
	if _, err := saved.config("", settingsOrigin, "tls"); err != nil {
		t.Fatal("bounded audit no longer reloads")
	}
	audit, _ := json.Marshal(saved.Audit)
	for _, secret := range []string{"application.example.test", "8.8.8.8", "https://", "url", "targets", "error"} {
		if bytes.Contains(audit, []byte(secret)) {
			t.Fatal("audit contains target material or raw error")
		}
	}
}

func TestApplicationSettingsRejectUnsafeFilesAndParents(t *testing.T) {
	for _, kind := range []string{"mode", "symlink", "hardlink", "directory", "parent", "sidecar"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := testSettings(t, nil)
			saveSettings(t, s)
			path := filepath.Join(dir, SettingsFile)
			switch kind {
			case "mode":
				_ = os.Chmod(path, 0644)
			case "symlink":
				_ = os.Rename(path, path+".other")
				_ = os.Symlink(path+".other", path)
			case "hardlink":
				_ = os.Link(path, path+".other")
			case "directory":
				_ = os.Remove(path)
				_ = os.Mkdir(path, 0700)
			case "parent":
				_ = os.Chmod(dir, 0755)
			case "sidecar":
				_ = os.WriteFile(path+"-wal", []byte("not private"), 0644)
			}
			if _, err := NewSettings(dir, "", settingsOrigin, "tls", Config{}); err != ErrConfiguration {
				t.Fatal("unsafe state accepted")
			}
			if err := s.Change(context.Background(), SettingsChange{ExpectedRevision: s.View().Revision, Operation: "disable"}, settingsActor); err != ErrSettingsUnavailable || !s.View().Blocked || s.View().Enabled {
				t.Fatal("unsafe mutation did not block closed")
			}
		})
	}
}

func TestApplicationSettingsDurabilityFailureAndChangedDiskBlockClosed(t *testing.T) {
	for _, point := range []string{"before publication", "after publication", "activation", "changed disk", "missing disk"} {
		t.Run(point, func(t *testing.T) {
			var probes atomic.Int32
			idle := make(chan struct{}, 1)
			s, dir := testSettings(t, func(c Config) *Monitor {
				m := New(c)
				m.check = func(context.Context, target, string, time.Time) Result {
					probes.Add(1)
					return Result{State: "ok", Reason: "fixture"}
				}
				m.wait = func(ctx context.Context, _ time.Duration) bool { idle <- struct{}{}; <-ctx.Done(); return false }
				return m
			})
			saveSettings(t, s)
			enableSettings(t, s)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.Run(ctx) }()
			receive(t, idle)
			switch point {
			case "before publication":
				s.persist = func(savedSettings, bool) error { return errors.New("raw private filesystem diagnostic") }
			case "after publication":
				s.persist = func(next savedSettings, create bool) error {
					if err := s.write(next, create); err != nil {
						return err
					}
					return errors.New("directory sync/readback uncertain")
				}
			case "activation":
				s.factory = func(Config) *Monitor { return nil }
			case "changed disk":
				raw, _ := os.ReadFile(s.file)
				_ = os.WriteFile(s.file, append(raw, '\n'), 0600)
			case "missing disk":
				_ = os.Remove(s.file)
			}
			if err := s.Change(context.Background(), SettingsChange{ExpectedRevision: s.View().Revision, Operation: "disable"}, settingsActor); err != ErrSettingsUnavailable {
				t.Fatalf("uncertainty not mapped to static unavailable: %v", err)
			}
			if !s.View().Blocked || s.View().Enabled || s.Status().Enabled || probes.Load() != 1 {
				t.Fatal("failed change did not stop local checks")
			}
			if err := receive(t, done); err != ErrSettingsUnavailable {
				t.Fatal("blocked supervisor did not terminate")
			}
			if err := s.Change(context.Background(), SettingsChange{ExpectedRevision: s.View().Revision, Operation: "disable"}, settingsActor); err != ErrSettingsUnavailable {
				t.Fatal("blocked instance accepted another mutation")
			}
			if err := s.Run(context.Background()); err != ErrSettingsUnavailable {
				t.Fatal("blocked instance restarted a worker")
			}
			if point == "missing disk" {
				return
			}
			// Restart/readback, never in-memory rollback, decides committed state.
			// A pre-publication failure leaves the previous approved enabled file;
			// a post-publication/activation failure retains the committed disable.
			reload, err := NewSettings(dir, "", settingsOrigin, "tls", Config{})
			if err != nil {
				t.Fatal(err)
			}
			wantEnabled := point == "before publication" || point == "changed disk"
			if reload.View().Enabled != wantEnabled || reload.View().Blocked {
				t.Fatal("restart did not reflect protected committed envelope")
			}
		})
	}
}

func TestApplicationSettingsCancelledRequestAndPreRunDiskChange(t *testing.T) {
	s, _ := testSettings(t, nil)
	saveSettings(t, s)
	before := s.View().Revision
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Change(ctx, SettingsChange{ExpectedRevision: before, Operation: "disable"}, settingsActor); !errors.Is(err, context.Canceled) || s.View().Revision != before || s.View().Blocked {
		t.Fatal("pre-cancelled request changed state")
	}
	enableSettings(t, s)
	raw, _ := os.ReadFile(s.file)
	_ = os.WriteFile(s.file, append(raw, '\n'), 0600)
	if err := s.Run(context.Background()); err != ErrSettingsUnavailable || !s.View().Blocked || s.Status().Enabled {
		t.Fatal("changed file admitted startup checks")
	}
}

func TestApplicationSettingsInitiallyDisabledSupervisorAndPersistedResume(t *testing.T) {
	attempts := make(chan struct{}, 4)
	factory := func(c Config) *Monitor {
		m := New(c)
		m.check = func(context.Context, target, string, time.Time) Result {
			attempts <- struct{}{}
			return Result{State: "ok", Reason: "fixture"}
		}
		return m
	}
	s, dir := testSettings(t, factory)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	saveSettings(t, s)
	if s.Status().Enabled {
		t.Fatal("saving into running supervisor enabled checks")
	}
	select {
	case <-attempts:
		t.Fatal("saved draft probed")
	default:
	}
	enableSettings(t, s)
	receive(t, attempts)
	cancel()
	if err := receive(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	reloaded, err := newSettings(dir, "", settingsOrigin, "tls", Config{}, time.Now, factory)
	if err != nil {
		t.Fatal(err)
	}
	if status := reloaded.Status(); !status.Enabled || status.Items[0].ObservedAt != nil {
		t.Fatal("restart reused observations")
	}
	select {
	case <-attempts:
		t.Fatal("restart construction probed")
	default:
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- reloaded.Run(ctx) }()
	receive(t, attempts)
	cancel()
	if err := receive(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestApplicationSettingsInterruptedJoinBlocksWithoutPublishing(t *testing.T) {
	started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s, _ := testSettings(t, func(c Config) *Monitor {
		m := New(c)
		m.check = func(ctx context.Context, _ target, _ string, _ time.Time) Result {
			close(started)
			<-ctx.Done()
			close(cancelled)
			<-release
			return Result{State: "ok"}
		}
		return m
	})
	saveSettings(t, s)
	enableSettings(t, s)
	original, _ := os.ReadFile(s.file)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	receive(t, started)
	request, cancel := context.WithCancel(context.Background())
	changed := make(chan error, 1)
	go func() {
		changed <- s.Change(request, SettingsChange{ExpectedRevision: s.View().Revision, Operation: "disable"}, settingsActor)
	}()
	receive(t, cancelled)
	cancel()
	close(release)
	if err := receive(t, changed); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !s.View().Blocked || s.Status().Enabled {
		t.Fatal("interrupted stop was restarted")
	}
	if err := receive(t, done); err != ErrSettingsUnavailable {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(s.file)
	if !bytes.Equal(original, after) {
		t.Fatal("expired request published a mutation")
	}
}

func TestApplicationSettingsCancelledDuringPublicationDoesNotActivate(t *testing.T) {
	s, dir := testSettings(t, nil)
	saveSettings(t, s)
	request, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.persist = func(next savedSettings, create bool) error {
		if err := s.write(next, create); err != nil {
			return err
		}
		cancel() // Models expiry after publication, before lifecycle activation.
		return nil
	}
	if err := s.Change(request, SettingsChange{ExpectedRevision: s.View().Revision, Operation: "enable", ChecksFromManagerAcknowledged: true, DestinationsAcknowledged: true}, settingsActor); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !s.View().Blocked || s.View().Enabled || s.Status().Enabled {
		t.Fatal("expired publication activated a new generation")
	}
	if err := s.Run(context.Background()); err != ErrSettingsUnavailable {
		t.Fatal("blocked publication started probes")
	}
	// The approved enable was durably committed; a separate restart verifies it
	// inertly. This is deliberately not an in-memory rollback of durable intent.
	reloaded, err := NewSettings(dir, "", settingsOrigin, "tls", Config{})
	if err != nil || !reloaded.View().Enabled || reloaded.Status().Items[0].ObservedAt != nil {
		t.Fatal("restart did not revalidate published approval")
	}
}

func TestApplicationSettingsDisableAfterClockRollback(t *testing.T) {
	var clock atomic.Int64
	original := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock.Store(original.UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	started := make(chan struct{})
	var active atomic.Int32
	dir := privateSettingsDir(t)
	s, err := newSettings(dir, "", settingsOrigin, "tls", Config{}, now, func(c Config) *Monitor {
		m := New(c)
		m.check = func(ctx context.Context, _ target, _ string, _ time.Time) Result {
			active.Add(1)
			defer active.Add(-1)
			close(started)
			<-ctx.Done()
			return Result{}
		}
		return m
	})
	if err != nil {
		t.Fatal(err)
	}
	saveSettings(t, s)
	enableSettings(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	receive(t, started)
	clock.Add(-int64(time.Hour))
	disableSettings(t, s)
	if active.Load() != 0 || s.View().Enabled || s.View().Blocked || s.Status().Enabled {
		t.Fatal("clock rollback prevented disable")
	}
	last := s.saved.Audit[len(s.saved.Audit)-1]
	if !last.Timestamp.Equal(original.Add(-time.Hour)) || last.Operation != "disable" {
		t.Fatal("audit must retain actual corrected clock without clamping")
	}
	reloaded, err := NewSettings(dir, "", settingsOrigin, "tls", Config{})
	if err != nil || reloaded.View().Enabled || reloaded.View().Revision != s.View().Revision {
		t.Fatal("clock-corrected audit did not reload")
	}
	cancel()
	if err := receive(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestApplicationSettingsCooldownPreservesMonotonicClock(t *testing.T) {
	s, _ := testSettings(t, func(c Config) *Monitor {
		m := New(c)
		m.check = func(context.Context, target, string, time.Time) Result { return Result{} }
		return m
	})
	saveSettings(t, s)
	enableSettings(t, s)
	// The injected attempt performs no networking. The production time.Now
	// clock must retain its monotonic component in the cross-generation floor.
	_ = s.monitor.check(context.Background(), s.config.targets[0], "tls", time.Now())
	s.mu.RLock()
	next := s.nextAllowed
	s.mu.RUnlock()
	if next == next.Round(0) {
		t.Fatal("cooldown stripped the monotonic clock and admits wall-clock bypass")
	}
	if delay := next.Sub(time.Now()); delay <= 0 || delay > time.Minute {
		t.Fatal("cooldown does not retain a full bounded interval")
	}
}
