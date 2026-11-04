package applicationcheck

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type incidentSpy struct {
	source func(context.Context, IncidentSource) error
	result func(context.Context, IncidentSource, IncidentObservation) error
}

func (s incidentSpy) ObserveApplicationSource(c context.Context, x IncidentSource) error {
	if s.source != nil {
		return s.source(c, x)
	}
	return nil
}
func (s incidentSpy) ObserveApplicationResult(c context.Context, x IncidentSource, r IncidentObservation) error {
	if s.result != nil {
		return s.result(c, x, r)
	}
	return nil
}
func TestIncidentSourcePrivateBindingAndOpaqueRuntime(t *testing.T) {
	c := monitorConfig()
	c.incidentGeneration = strings.Repeat("1", 32)
	m, n := New(c), New(c)
	if m.incidentSource.Key != n.incidentSource.Key || m.incidentSource.Token == n.incidentSource.Token {
		t.Fatal("restart identity")
	}
	changed := c
	changed.incidentGeneration = strings.Repeat("2", 32)
	if New(changed).incidentSource.Key == m.incidentSource.Key {
		t.Fatal("generation reused")
	}
	external := c
	external.external = true
	external.incidentGeneration = ""
	a, b := New(external), New(external)
	if a.incidentSource.Key != b.incidentSource.Key || a.incidentSource.Mode != "external" {
		t.Fatal("external restart binding")
	}
	external.targets = append([]target{}, external.targets...)
	external.targets[0].URL = "https://replacement.example/status"
	if New(external).incidentSource.Key == a.incidentSource.Key {
		t.Fatal("same ID rebound")
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.managerID = "different" }, func(c *Config) { c.origin = "https://other.example" }, func(c *Config) { c.profile = "http-test" }, func(c *Config) { c.interval = 2 * time.Minute }} {
		d := c
		mutate(&d)
		if New(d).incidentSource.Key == m.incidentSource.Key {
			t.Fatal("binding omitted")
		}
	}
	m.WithIncidentSource(func(s IncidentSource) { *s.Targets[0].Scheme = "mutated"; s.Targets[0].ID = "mutated" })
	if *m.incidentSource.Targets[0].Scheme != "https" || m.incidentSource.Targets[0].ID == "mutated" {
		t.Fatal("source alias")
	}
	c.enabled = false
	off := New(c).incidentSource
	if len(off.Targets) != 0 || off.IntervalSeconds != 0 || off.MaxAgeSeconds != 0 {
		t.Fatal("disabled draft exposed")
	}
}
func TestIncidentSourceHookOrderedOutsideStatusLockAndNoAddedProbes(t *testing.T) {
	m := New(monitorConfig())
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probes, records := 0, 0
	m.check = func(_ context.Context, target target, _ string, started time.Time) Result {
		probes++
		now = now.Add(time.Second)
		code := 200
		scheme := "https"
		if target.ID == "http-fixture" {
			scheme = "http"
		}
		return Result{Scheme: scheme, State: "ok", Reason: "http_2xx", HTTPStatus: &code}
	}
	m.incidentSink = incidentSpy{result: func(ctx context.Context, s IncidentSource, r IncidentObservation) error {
		records++
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > IncidentWriteTimeout {
			t.Fatal("unbounded hook")
		}
		v := m.Status()
		if len(v.Items) != 2 || r.TargetID != m.config.targets[records-1].ID || r.CompletedAt.Sub(r.ObservedAt) != time.Second {
			t.Fatal("source ordering")
		}
		return errors.New("synthetic storage failure")
	}}
	m.wait = func(context.Context, time.Duration) bool { cancel(); return false }
	if err := m.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if probes != 2 || records != 2 {
		t.Fatal("extra or missing probe/hook", probes, records)
	}
}
func TestIncidentSettingsDisableJoinsCancelledCompletionWithoutLockInversion(t *testing.T) {
	var sourceCalls, checks atomic.Int32
	entered, settled := make(chan struct{}), make(chan struct{})
	var settings *Settings
	sink := incidentSpy{source: func(context.Context, IncidentSource) error { sourceCalls.Add(1); return nil }, result: func(ctx context.Context, _ IncidentSource, _ IncidentObservation) error {
		_ = settings.Status()
		close(entered)
		<-ctx.Done()
		close(settled)
		return ctx.Err()
	}}
	factory := func(c Config) *Monitor {
		m := New(c)
		m.check = func(context.Context, target, string, time.Time) Result {
			checks.Add(1)
			code := 200
			return Result{Scheme: "https", State: "ok", Reason: "http_2xx", HTTPStatus: &code}
		}
		return m
	}
	var err error
	settings, err = newSettings(privateSettingsDir(t), "", settingsOrigin, "tls", Config{}, time.Now, factory, sink)
	if err != nil {
		t.Fatal(err)
	}
	saveSettings(t, settings)
	enableSettings(t, settings)
	if checks.Load() != 0 {
		t.Fatal("construction/control probed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- settings.Run(ctx) }()
	receive(t, entered)
	disableSettings(t, settings)
	select {
	case <-settled:
	default:
		t.Fatal("disable did not join completion")
	}
	if checks.Load() != 1 || settings.Status().Enabled || sourceCalls.Load() < 4 {
		t.Fatal("source transition")
	}
	cancel()
	if err := receive(t, finished); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestIncidentCancelledProbeNeverPublishesOutcome(t *testing.T) {
	m := New(monitorConfig())
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	m.incidentSink = incidentSpy{result: func(context.Context, IncidentSource, IncidentObservation) error { calls++; return nil }}
	m.check = func(context.Context, target, string, time.Time) Result {
		cancel()
		return Result{State: "network_error", Reason: "request_failed"}
	}
	if err := m.Run(ctx); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("cancelled completion published", err, calls)
	}
}
func TestIncidentPlainHTTPRejectsTLSAndCurrentSourceCorruption(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	scheme := "http"
	src := IncidentSource{Key: strings.Repeat("a", 64), Token: "appsource_" + strings.Repeat("a", 32), Mode: "managed", Enabled: true, IntervalSeconds: 60, MaxAgeSeconds: 70, Targets: []IncidentTarget{{ID: "app", Kind: "http", Scheme: &scheme}}}
	s := NewIncidentState()
	c := IncidentCommand{RequestID: "apprequest_" + strings.Repeat("1", 32), Operation: "enable", SourceToken: src.Token, TargetIDs: []string{"app"}, ConsecutiveFailures: 2, RetentionAcknowledged: true}
	if s.Apply(c, src, now) != nil {
		t.Fatal("fixture")
	}
	for i := 1; i <= 2; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		if s.Observe(src, IncidentObservation{TargetID: "app", Kind: "http", Scheme: "http", State: "tls_error", Reason: "tls_verification_failed", ObservedAt: at, CompletedAt: at}, at) != nil {
			t.Fatal("safe unsupported outcome")
		}
	}
	if len(s.Records) != 0 {
		t.Fatal("plaintext certificate case")
	}
	code := 500
	for i := 3; i <= 4; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		if s.Observe(src, IncidentObservation{TargetID: "app", Kind: "http", Scheme: "http", State: "http_error", Reason: "http_status", HTTPStatus: &code, ObservedAt: at, CompletedAt: at}, at) != nil {
			t.Fatal("valid failure")
		}
	}
	bad := s.copy()
	bad.Records[0].Opening.Reason = "tls_verification_failed"
	bad.Records[0].Opening.HTTPStatus = nil
	if bad.Validate() == nil {
		t.Fatal("stored plaintext TLS accepted")
	}
	bad = s.copy()
	other := "https"
	p := bad.Progress["app"]
	p.Check.Scheme = &other
	bad.Progress["app"] = p
	if bad.Synchronize(src, now.Add(5*time.Second)) == nil {
		t.Fatal("current source row mismatch")
	}
}

func TestIncidentCapacityPreservesOpenAndReportsTerminalOmissions(t *testing.T) {
	base := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	scheme := "https"
	src := IncidentSource{Key: strings.Repeat("a", 64), Token: "appsource_" + strings.Repeat("a", 32), Mode: "managed", Enabled: true, IntervalSeconds: 60, MaxAgeSeconds: 75, Targets: []IncidentTarget{{ID: "app", Kind: "http", Scheme: &scheme}, {ID: "db", Kind: "tcp"}}}
	s := NewIncidentState()
	command := IncidentCommand{RequestID: "apprequest_" + strings.Repeat("1", 32), Operation: "enable", SourceToken: src.Token, TargetIDs: []string{"app", "db"}, ConsecutiveFailures: 2, RetentionAcknowledged: true}
	if err := s.Apply(command, src, base); err != nil {
		t.Fatal(err)
	}
	status := 503
	for i := 1; i < 128; i++ {
		at := base.Add(time.Duration(i) * 10 * time.Second)
		one, two, three, four := at.Add(time.Second), at.Add(2*time.Second), at.Add(3*time.Second), at.Add(4*time.Second)
		s.Records = append(s.Records, incidentRecord{SourceKey: src.Key, ApplicationIncident: ApplicationIncident{ID: fmt.Sprintf("appincident_%016x", i), TargetID: "app", Kind: "http", Scheme: &scheme, State: "recovered", Opening: IncidentOpening{FirstObservedAt: one, ObservedAt: two, CompletedAt: two, Reason: "http_status", HTTPStatus: &status, Samples: 2}, LastObservedAt: four, LastCompletedAt: four, ClosedAt: &four, Recovery: &IncidentRecovery{FirstObservedAt: three, ObservedAt: four, CompletedAt: four, Samples: 2}}})
	}
	at := base.Add(1280 * time.Second)
	one, two := at.Add(time.Second), at.Add(2*time.Second)
	s.Records = append(s.Records, incidentRecord{SourceKey: src.Key, ApplicationIncident: ApplicationIncident{ID: "appincident_0000000000000080", TargetID: "db", Kind: "tcp", State: "open", Opening: IncidentOpening{FirstObservedAt: one, ObservedAt: two, CompletedAt: two, Reason: "tcp_failed", Samples: 2}, LastObservedAt: two, LastCompletedAt: two}})
	s.NextID = 129
	s.Floor = two
	if s.Validate() != nil {
		t.Fatal("capacity fixture")
	}
	for i := 1; i <= 2; i++ {
		stamp := two.Add(time.Duration(i) * time.Second)
		if err := s.Observe(src, IncidentObservation{TargetID: "app", Kind: "http", Scheme: "https", State: "http_error", Reason: "http_status", HTTPStatus: &status, ObservedAt: stamp, CompletedAt: stamp}, stamp); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.Records) != 128 || !s.EarlierOmitted || s.Records[0].ID != "appincident_0000000000000002" || s.Records[126].ID != "appincident_0000000000000080" || s.Records[127].State != "open" {
		t.Fatal("capacity erased an open case")
	}
	if err := s.Synchronize(src, two.Add(32*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(s.Records) != 2 || s.Records[0].State != "open" || s.Records[1].State != "open" {
		t.Fatal("retention dropped unresolved evidence")
	}
}

func TestIncidentSourceAdmissionCancellationCannotActivateProbeGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var probes atomic.Int32
	sink := incidentSpy{source: func(_ context.Context, source IncidentSource) error {
		if source.Enabled {
			cancel()
		}
		return nil
	}}
	factory := func(c Config) *Monitor {
		m := New(c)
		m.check = func(context.Context, target, string, time.Time) Result { probes.Add(1); return Result{} }
		return m
	}
	s, err := newSettings(privateSettingsDir(t), "", settingsOrigin, "tls", Config{}, time.Now, factory, sink)
	if err != nil {
		t.Fatal(err)
	}
	saveSettings(t, s)
	err = s.Change(ctx, SettingsChange{ExpectedRevision: s.View().Revision, Operation: "enable", ChecksFromManagerAcknowledged: true, DestinationsAcknowledged: true}, settingsActor)
	if !errors.Is(err, context.Canceled) || !s.View().Blocked || s.Status().Enabled || probes.Load() != 0 {
		t.Fatal("expired admission activated source", err, s.View(), probes.Load())
	}
	if err = s.Run(context.Background()); !errors.Is(err, ErrSettingsUnavailable) || probes.Load() != 0 {
		t.Fatal("blocked generation ran", err)
	}
}
