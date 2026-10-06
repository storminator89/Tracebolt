package alarmdelivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type settingsQueueFixture struct {
	binding        *Binding
	configurations int
	tests          int
	claims         int
	completed      int
	fail           bool
	attempt        *Attempt
	test           *TestStatus
}

func (q *settingsQueueFixture) ConfigureAlarms(_ context.Context, b *Binding, _ time.Time) error {
	if q.fail {
		return errors.New("fixture")
	}
	q.configurations++
	q.binding = b
	return nil
}
func (q *settingsQueueFixture) ConfigureAlarmsAudited(ctx context.Context, b *Binding, audit SettingsAudit, now time.Time) error {
	if !validSettingsActor(audit.Actor) || audit.Action == "" {
		return ErrInvalid
	}
	return q.ConfigureAlarms(ctx, b, now)
}
func (q *settingsQueueFixture) ClaimAlarm(context.Context, Binding, time.Time) (*Attempt, error) {
	q.claims++
	return q.attempt, nil
}
func (q *settingsQueueFixture) CompleteAlarm(context.Context, Binding, Attempt, Result, time.Time) error {
	q.completed++
	return nil
}
func (q *settingsQueueFixture) EnqueueAlarmTest(_ context.Context, _ Binding, id, actor string, at time.Time) (*TestStatus, error) {
	q.tests++
	q.test = &TestStatus{EventID: strings.Repeat("a", 64), State: "queued", CreatedAt: at}
	return q.test, nil
}
func (q *settingsQueueFixture) LatestAlarmTest(context.Context, Binding) (*TestStatus, error) {
	return q.test, nil
}

type settingsTransportFixture struct {
	send func(context.Context, Payload) Result
}

func (f settingsTransportFixture) Send(ctx context.Context, p Payload) Result { return f.send(ctx, p) }
func settingsFixture(t *testing.T, profile string) (*Settings, *settingsQueueFixture, *int) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux protected state")
	}
	q := &settingsQueueFixture{}
	calls := 0
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := newSettings(q, dir, "manager-fixture", profile, Config{}, func() time.Time { return time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC) }, func(Config) (Transport, error) {
		calls++
		return settingsTransportFixture{func(context.Context, Payload) Result { t.Fatal("unexpected provider transport"); return Result{} }}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return s, q, &calls
}
func settingsReplace(s *Settings) SettingsChange {
	return SettingsChange{ExpectedRevision: s.saved.Revision, Operation: "replace", Endpoint: "https://receiver.example.test/hook/secret-path?key=secret-query", PayloadSharingAcknowledged: true, PlaintextAcknowledged: s.saved.Profile == "http-test"}
}
func TestManagedSettingsDefaultOffAndWriteOnlyPersistence(t *testing.T) {
	s, q, calls := settingsFixture(t, "tls")
	ctx := context.Background()
	if e := s.Step(ctx); e != nil || q.claims != 0 || *calls != 0 {
		t.Fatal("default-off dispatched")
	}
	if e := s.Change(ctx, settingsReplace(s), "shared-administrator"); e != nil {
		t.Fatal(e)
	}
	if q.claims != 0 || q.tests != 0 || *calls != 1 {
		t.Fatal("save contacted transport or tested")
	}
	v, e := s.View(ctx)
	if e != nil || !v.Enabled || !v.Configured || v.DestinationHost != "receiver.example.test" {
		t.Fatal(v, e)
	}
	raw, _ := json.Marshal(v)
	for _, secret := range []string{"secret-path", "secret-query", "endpoint", "bearer", "manager-fixture"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("secret readback")
		}
	}
	info, e := os.Stat(s.file)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("config permissions")
	}
	oldBinding := s.config.Binding()
	oldRevision := s.saved.Revision
	restarted, e := newSettings(q, filepath.Dir(s.file), "manager-fixture", "tls", Config{}, s.now, s.transport)
	if e != nil {
		t.Fatal(e)
	}
	if restarted.config.Binding() != oldBinding || restarted.saved.Revision != oldRevision {
		t.Fatal("restart changed approved routing")
	}
	if e = s.Change(ctx, SettingsChange{ExpectedRevision: oldRevision, Operation: "disable"}, "shared-administrator"); e != nil {
		t.Fatal(e)
	}
	if s.config.Enabled() || s.config.endpoint == "" || q.binding != nil {
		t.Fatal("disable lost secret or stayed active")
	}
	if e = s.Change(ctx, SettingsChange{ExpectedRevision: s.saved.Revision, Operation: "enable", PayloadSharingAcknowledged: true}, "shared-administrator"); e != nil {
		t.Fatal(e)
	}
	if s.config.Binding() == oldBinding {
		t.Fatal("reenable reused old generation")
	}
}
func TestManagedSettingsApprovalBoundsStaleAndSecretRedaction(t *testing.T) {
	for _, name := range []string{"missing ack", "http ack", "blank", "private", "http", "port", "userinfo", "fragment", "stale", "actor", "operation"} {
		t.Run(name, func(t *testing.T) {
			profile := "tls"
			if name == "http ack" {
				profile = "http-test"
			}
			s, q, _ := settingsFixture(t, profile)
			in := settingsReplace(s)
			actor := "shared-administrator"
			switch name {
			case "missing ack":
				in.PayloadSharingAcknowledged = false
			case "http ack":
				in.PlaintextAcknowledged = false
			case "blank":
				in.Endpoint = ""
			case "private":
				in.Endpoint = "https://127.0.0.1/x"
			case "http":
				in.Endpoint = "http://receiver.example.test"
			case "port":
				in.Endpoint = "https://receiver.example.test:8443"
			case "userinfo":
				in.Endpoint = "https://user:secret@receiver.example.test"
			case "fragment":
				in.Endpoint += "#x"
			case "stale":
				in.ExpectedRevision = strings.Repeat("0", 32)
			case "actor":
				actor = "client-supplied-admin"
			case "operation":
				in.Operation = "send"
			}
			if s.Change(context.Background(), in, actor) == nil || q.configurations != 1 || s.config.Enabled() {
				t.Fatal("invalid change accepted")
			}
		})
	}
	s, _, _ := settingsFixture(t, "tls")
	in := settingsReplace(s)
	for _, x := range []any{in, &in, s.saved} {
		for _, f := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(f, x), "secret") {
				t.Fatal("secret formatting")
			}
		}
	}
	raw, _ := json.Marshal(in)
	if string(raw) != `{"redacted":true}` {
		t.Fatal("secret JSON command")
	}
}
func TestManagedSettingsFileSafetyAndFailureStopsDispatch(t *testing.T) {
	s, q, _ := settingsFixture(t, "tls")
	in := settingsReplace(s)
	if e := s.Change(context.Background(), in, "shared-administrator"); e != nil {
		t.Fatal(e)
	}
	q.fail = true
	if e := s.Change(context.Background(), SettingsChange{ExpectedRevision: s.saved.Revision, Operation: "disable"}, "shared-administrator"); e != ErrSettingsUnavailable {
		t.Fatal(e)
	}
	v, _ := s.View(context.Background())
	if !v.Blocked || v.Enabled || s.worker != nil {
		t.Fatal("uncertain storage did not stop worker")
	}
	q.fail = false
	restarted, e := newSettings(q, filepath.Dir(s.file), "manager-fixture", "tls", Config{}, s.now, s.transport)
	if e != nil || restarted.config.Enabled() {
		t.Fatal("durable disabled file lost")
	}
	for _, name := range []string{"symlink", "permissions", "tamper", "binding", "missing"} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := settingsFixture(t, "tls")
			dir := filepath.Dir(s.file)
			switch name {
			case "symlink":
				os.Rename(s.file, s.file+".old")
				os.Symlink(s.file+".old", s.file)
			case "permissions":
				os.Chmod(s.file, 0644)
			case "tamper":
				os.WriteFile(s.file, []byte(`{"schemaVersion":"bad"}`), 0600)
			case "binding":
				s.saved.ManagerID = "different"
				raw, _ := json.Marshal(s.saved)
				os.WriteFile(s.file, raw, 0600)
			case "missing":
				os.Remove(s.file)
				if e := s.Change(context.Background(), settingsReplace(s), "shared-administrator"); e == nil {
					t.Fatal("missing used file recreated")
				}
				return
			}
			if _, e := newSettings(&settingsQueueFixture{}, dir, "manager-fixture", "tls", Config{}, s.now, s.transport); e == nil {
				t.Fatal("unsafe file accepted")
			}
		})
	}
}
func TestManagedSettingsExternalPrecedenceAndMutationRefusal(t *testing.T) {
	s, q, calls := settingsFixture(t, "tls")
	external := loadWebhookFixture(t)
	other, e := newSettings(q, filepath.Dir(s.file), "manager-fixture", "tls", external, s.now, s.transport)
	if e != nil {
		t.Fatal(e)
	}
	v, _ := other.View(context.Background())
	if v.Mode != "external" || v.Revision != "" || !v.Enabled {
		t.Fatal(v)
	}
	if e = other.Change(context.Background(), settingsReplace(s), "shared-administrator"); e != ErrSettingsUnavailable {
		t.Fatal("CLI config modified")
	}
	if e = other.Test(context.Background(), "", strings.Repeat("b", 32), "shared-administrator"); e != ErrSettingsUnavailable {
		t.Fatal("CLI config test authorized")
	}
	if *calls != 1 || q.tests != 0 || q.claims != 0 {
		t.Fatal("external view/mutation triggered send")
	}
}
func TestManagedSettingsMutationNeverWaitsAcrossProviderIO(t *testing.T) {
	s, q, _ := settingsFixture(t, "tls")
	start := make(chan struct{})
	finish := make(chan struct{})
	var once sync.Once
	s.transport = func(Config) (Transport, error) {
		return settingsTransportFixture{func(context.Context, Payload) Result {
			once.Do(func() { close(start) })
			<-finish
			return Result{Accepted, "provider_accepted"}
		}}, nil
	}
	if e := s.Change(context.Background(), settingsReplace(s), "shared-administrator"); e != nil {
		t.Fatal(e)
	}
	q.attempt = &Attempt{Payload: NewTestPayload(strings.Repeat("a", 64), s.now()), Number: 1}
	done := make(chan error, 1)
	go func() { done <- s.Step(context.Background()) }()
	<-start
	if e := s.Change(context.Background(), SettingsChange{ExpectedRevision: s.saved.Revision, Operation: "disable"}, "shared-administrator"); e != ErrSettingsBusy {
		t.Fatal("configuration overlapped provider send", e)
	}
	if e := s.Test(context.Background(), s.saved.Revision, strings.Repeat("a", 32), "shared-administrator"); e != ErrSettingsBusy {
		t.Fatal("test overlapped provider send")
	}
	if v, e := s.View(context.Background()); e != nil || !v.Enabled {
		t.Fatal("status read blocked")
	}
	close(finish)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := s.Change(context.Background(), SettingsChange{ExpectedRevision: s.saved.Revision, Operation: "disable"}, "shared-administrator"); e != nil {
		t.Fatal(e)
	}
	if e := s.Step(context.Background()); e != nil || q.claims != 1 {
		t.Fatal("disabled worker sent again")
	}
}
func TestManagedSettingsTestExplicitAndRevisionBound(t *testing.T) {
	s, q, _ := settingsFixture(t, "tls")
	ctx := context.Background()
	id := strings.Repeat("b", 32)
	if e := s.Test(ctx, s.saved.Revision, id, "shared-administrator"); e != ErrSettingsUnavailable {
		t.Fatal("disabled test allowed")
	}
	if e := s.Change(ctx, settingsReplace(s), "shared-administrator"); e != nil {
		t.Fatal(e)
	}
	if e := s.Test(ctx, strings.Repeat("0", 32), id, "shared-administrator"); e != ErrSettingsConflict {
		t.Fatal("stale test allowed")
	}
	if e := s.Test(ctx, s.saved.Revision, "INVALID", "shared-administrator"); e != ErrConfiguration {
		t.Fatal("unbounded request id")
	}
	if e := s.Test(ctx, s.saved.Revision, id, "shared-administrator"); e != nil || q.tests != 1 || q.claims != 0 {
		t.Fatal("test did not enqueue exactly once")
	}
}

func TestManagedSettingsCLIOverridePreservesExplicitBrowserChoice(t *testing.T) {
	s, q, _ := settingsFixture(t, "tls")
	ctx := context.Background()
	if e := s.Change(ctx, settingsReplace(s), "shared-administrator"); e != nil {
		t.Fatal(e)
	}
	revision := s.saved.Revision
	binding := s.config.Binding()
	external, e := Load(writeWebhookConfig(t, map[string]any{"schemaVersion": ConfigSchemaVersion, "enabled": false}), "manager-fixture", "tls")
	if e != nil {
		t.Fatal(e)
	}
	override, e := newSettings(q, filepath.Dir(s.file), "manager-fixture", "tls", external, s.now, s.transport)
	if e != nil {
		t.Fatal(e)
	}
	view, _ := override.View(ctx)
	if view.Mode != "external" || view.Enabled || view.Configured {
		t.Fatal("disabled CLI override not authoritative")
	}
	restored, e := newSettings(q, filepath.Dir(s.file), "manager-fixture", "tls", Config{}, s.now, s.transport)
	if e != nil {
		t.Fatal(e)
	}
	if !restored.config.Enabled() || restored.saved.Revision != revision || restored.config.Binding() != binding {
		t.Fatal("CLI override modified browser file")
	}
}
func TestManagedSettingsSaveRecordsLastMutationForStartupAudit(t *testing.T) {
	s, q, _ := settingsFixture(t, "tls")
	ctx := context.Background()
	actor := "operator_12345678901234567890123456789012"
	if e := s.Change(ctx, settingsReplace(s), actor); e != nil {
		t.Fatal(e)
	}
	if s.saved.LastActor != actor || s.saved.LastAction != "replace" || s.saved.ChangedAt.IsZero() {
		t.Fatal("missing mutation provenance")
	}
	approval := s.saved.ApprovedBy
	q.fail = true
	if e := s.Change(ctx, SettingsChange{ExpectedRevision: s.saved.Revision, Operation: "disable"}, "shared-administrator"); e != ErrSettingsUnavailable {
		t.Fatal(e)
	}
	q.fail = false
	restarted, e := newSettings(q, filepath.Dir(s.file), "manager-fixture", "tls", Config{}, s.now, s.transport)
	if e != nil {
		t.Fatal(e)
	}
	if restarted.saved.LastActor != "shared-administrator" || restarted.saved.LastAction != "disable" || restarted.saved.ApprovedBy != approval || restarted.config.Enabled() {
		t.Fatal("disable actor/action or original approval lost on uncertain restart")
	}
}
func TestManagedSettingsSlowAttemptLeavesMutationWindow(t *testing.T) {
	s, q, _ := settingsFixture(t, "tls")
	start := make(chan struct{}, 2)
	finish := make(chan struct{})
	s.transport = func(Config) (Transport, error) {
		return settingsTransportFixture{func(context.Context, Payload) Result {
			start <- struct{}{}
			<-finish
			return Result{Accepted, "provider_accepted"}
		}}, nil
	}
	if e := s.Change(context.Background(), settingsReplace(s), "shared-administrator"); e != nil {
		t.Fatal(e)
	}
	q.attempt = &Attempt{Payload: NewTestPayload(strings.Repeat("a", 64), s.now()), Number: 1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, nil) }()
	<-start
	time.Sleep(SendInterval + 20*time.Millisecond)
	close(finish)
	select {
	case <-start:
		cancel()
		<-done
		t.Fatal("buffered ticker immediately restarted slow attempt")
	case <-time.After(100 * time.Millisecond):
	}
	if e := s.Change(context.Background(), SettingsChange{ExpectedRevision: s.saved.Revision, Operation: "disable"}, "shared-administrator"); e != nil {
		cancel()
		<-done
		t.Fatal("no idle mutation window", e)
	}
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
