package applicationcheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/lanconfig"
)

func monitorConfig() Config {
	return Config{enabled: true, managerID: "fixture-manager", origin: "https://manager.example", profile: lanconfig.TLS, interval: time.Minute, targets: []target{
		{ID: "https-fixture", URL: "https://fixture.example/", AllowedAddresses: []string{"8.8.8.8"}},
		{ID: "http-fixture", URL: "http://fixture.example/", AllowedAddresses: []string{"8.8.8.8"}, PlaintextHTTPAcknowledged: true},
	}}
}

func TestMonitorConstructionAndStatusAreInert(t *testing.T) {
	m := New(monitorConfig())
	var checks, waits atomic.Int32
	m.check = func(context.Context, target, string, time.Time) Result { checks.Add(1); return Result{} }
	m.wait = func(context.Context, time.Duration) bool { waits.Add(1); return false }
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	for range 3 {
		v := m.Status()
		if !v.Enabled || v.SchemaVersion != SchemaVersion || v.Vantage != "management_server" || !v.ServerNow.Equal(now) || v.IntervalSeconds != 60 || v.MaxAgeSeconds != 75 || len(v.Items) != 2 {
			t.Fatalf("unexpected initial status: %+v", v)
		}
		for i, r := range v.Items {
			wantScheme, wantTLS := "https", "unknown"
			if i == 1 {
				wantScheme, wantTLS = "http", "not_applicable"
			}
			if r.ID != m.config.targets[i].ID || r.Scheme != wantScheme || r.State != "unknown" || r.Reason != "not_checked" || r.ObservedAt != nil || r.HTTPStatus != nil || r.TLS.State != wantTLS || r.TLS.ExpiresAt != nil {
				t.Fatalf("unrun monitor invented an observation: %+v", r)
			}
		}
	}
	if checks.Load() != 0 || waits.Load() != 0 || m.running.Load() {
		t.Fatal("construction/status scheduled work")
	}
}

func TestMonitorNilAndDisabledDoNoWork(t *testing.T) {
	var nilMonitor *Monitor
	disabled := New(Config{})
	disabled.check = func(context.Context, target, string, time.Time) Result {
		t.Error("disabled check ran")
		return Result{}
	}
	disabled.wait = func(context.Context, time.Duration) bool { t.Error("disabled timer ran"); return false }
	for _, m := range []*Monitor{nilMonitor, disabled} {
		if err := m.Run(context.Background()); err != nil {
			t.Fatalf("disabled Run: %v", err)
		}
		v := m.Status()
		if v.Enabled || v.SchemaVersion != SchemaVersion || v.Vantage != "management_server" || v.Items == nil || len(v.Items) != 0 || v.IntervalSeconds != 0 || v.MaxAgeSeconds != 0 || v.ServerNow.IsZero() {
			t.Fatalf("unexpected disabled view: %+v", v)
		}
	}
}

func TestMonitorSequentialCompletionBasedCadence(t *testing.T) {
	m := New(monitorConfig())
	start := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	now := start
	m.now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var order []string
	var starts []time.Time
	var active atomic.Int32
	m.check = func(_ context.Context, target target, profile string, observed time.Time) Result {
		if active.Add(1) != 1 {
			t.Error("checks overlap")
		}
		defer active.Add(-1)
		if profile != lanconfig.TLS || !observed.Equal(now) {
			t.Error("probe received wrong profile/start")
		}
		order = append(order, target.ID)
		starts = append(starts, observed)
		now = now.Add(3 * time.Second)
		status := 200
		return Result{ID: "must-be-overridden", Scheme: "https", State: "ok", Reason: "http_2xx", HTTPStatus: &status, TLS: TLSResult{State: "valid"}}
	}
	waits := 0
	m.wait = func(_ context.Context, duration time.Duration) bool {
		waits++
		if duration != time.Minute || active.Load() != 0 || len(order) != waits*2 {
			t.Error("timer began before complete serial sweep")
		}
		if waits == 2 {
			cancel()
			return false
		}
		now = now.Add(duration)
		return true
	}
	if err := m.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run termination: %v", err)
	}
	if !reflect.DeepEqual(order, []string{"https-fixture", "http-fixture", "https-fixture", "http-fixture"}) || waits != 2 {
		t.Fatalf("unexpected sweep order %v waits=%d", order, waits)
	}
	wantStarts := []time.Time{start, start.Add(3 * time.Second), start.Add(66 * time.Second), start.Add(69 * time.Second)}
	if !reflect.DeepEqual(starts, wantStarts) {
		t.Fatalf("timer catches up from start rather than completion: %v", starts)
	}
	view := m.Status()
	for i, result := range view.Items {
		if result.ID != m.config.targets[i].ID || result.ObservedAt == nil || !result.ObservedAt.Equal(starts[2+i]) {
			t.Fatalf("result identity/start not authoritative: %+v", result)
		}
	}
}

func TestMonitorRejectsConcurrentRunAndCanRestartAfterCancellation(t *testing.T) {
	m := New(monitorConfig())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	var calls atomic.Int32
	m.check = func(ctx context.Context, _ target, _ string, _ time.Time) Result {
		calls.Add(1)
		close(entered)
		<-ctx.Done()
		return Result{State: "unknown", Reason: "cancelled", TLS: TLSResult{State: "unknown"}}
	}
	finished := make(chan error, 1)
	go func() { finished <- m.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Run did not start")
	}
	if err := m.Run(context.Background()); !errors.Is(err, ErrRunning) {
		t.Fatalf("concurrent Run not rejected: %v", err)
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled Run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop on context cancellation")
	}
	if calls.Load() != 1 || m.running.Load() {
		t.Fatal("cancellation ran later targets or retained running guard")
	}
	for _, result := range m.Status().Items {
		if result.ObservedAt != nil || result.Reason != "not_checked" {
			t.Fatalf("cancellation published or refreshed unfinished observation: %+v", result)
		}
	}
	second, stop := context.WithCancel(context.Background())
	m.check = func(context.Context, target, string, time.Time) Result {
		calls.Add(1)
		return Result{State: "unknown", Reason: "not_checked", TLS: TLSResult{State: "unknown"}}
	}
	m.wait = func(context.Context, time.Duration) bool { stop(); return false }
	if err := m.Run(second); !errors.Is(err, context.Canceled) {
		t.Fatalf("sequential restart failed: %v", err)
	}
	if calls.Load() != 3 || m.running.Load() {
		t.Fatalf("restart work count=%d running=%v", calls.Load(), m.running.Load())
	}
}

func TestMonitorBindingMatchesExactManagerIdentity(t *testing.T) {
	var absent *Monitor
	for _, m := range []*Monitor{absent, New(Config{})} {
		if !m.Matches("any-manager", "https://any.example", lanconfig.TLS) {
			t.Error("disabled monitor unexpectedly enforces a binding")
		}
	}
	c := monitorConfig()
	m := New(c)
	if !m.Matches(c.managerID, c.origin, c.profile) {
		t.Error("configured monitor rejects exact binding")
	}
	for _, binding := range [][3]string{
		{"different-manager", c.origin, c.profile},
		{c.managerID, "https://different.example", c.profile},
		{c.managerID, c.origin, lanconfig.HTTPTest},
	} {
		if m.Matches(binding[0], binding[1], binding[2]) {
			t.Errorf("configured monitor accepts a different manager binding: %v", binding)
		}
	}
}

func TestMonitorConcurrentStatusAndPublication(t *testing.T) {
	m := New(monitorConfig())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sweeps atomic.Int32
	m.check = func(context.Context, target, string, time.Time) Result {
		status, expiry := 200, time.Now().Add(90*24*time.Hour)
		return Result{State: "ok", Scheme: "https", Reason: "http_2xx", HTTPStatus: &status, TLS: TLSResult{State: "valid", ExpiresAt: &expiry}}
	}
	m.wait = func(context.Context, time.Duration) bool {
		if sweeps.Add(1) >= 100 {
			cancel()
			return false
		}
		return true
	}
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	for range 100 {
		view := m.Status()
		if len(view.Items) != 2 {
			t.Fatal("concurrent publication changed configured item count")
		}
		for _, r := range view.Items {
			if r.HTTPStatus != nil {
				*r.HTTPStatus = 500
			}
			if r.ObservedAt != nil {
				*r.ObservedAt = time.Time{}
			}
			if r.TLS.ExpiresAt != nil {
				*r.TLS.ExpiresAt = time.Time{}
			}
		}
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fixture sweeps did not finish")
	}
	for _, r := range m.Status().Items {
		if r.State != "ok" || r.HTTPStatus == nil || *r.HTTPStatus != 200 || r.TLS.ExpiresAt == nil || r.TLS.ExpiresAt.IsZero() {
			t.Fatalf("concurrent snapshot mutation contaminated stored evidence: %+v", r)
		}
	}
}

func TestMonitorCancellationBeforeStartOrWhileWaiting(t *testing.T) {
	t.Run("before start", func(t *testing.T) {
		m := New(monitorConfig())
		m.check = func(context.Context, target, string, time.Time) Result {
			t.Error("cancelled monitor checked target")
			return Result{}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := m.Run(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-cancelled Run: %v", err)
		}
	})
	t.Run("during cadence wait", func(t *testing.T) {
		m := New(monitorConfig())
		var checks atomic.Int32
		m.check = func(context.Context, target, string, time.Time) Result {
			checks.Add(1)
			return Result{State: "unknown", Reason: "not_checked"}
		}
		entered := make(chan struct{})
		m.wait = func(ctx context.Context, d time.Duration) bool { close(entered); return wait(ctx, d) }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- m.Run(ctx) }()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("monitor did not begin wait")
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel wait: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("cadence wait ignored cancellation")
		}
		if checks.Load() != 2 {
			t.Fatalf("cancelled wait triggered another sweep: %d checks", checks.Load())
		}
	})
}

func TestMonitorFreshnessDoesNotRefreshStoredEvidence(t *testing.T) {
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		offset time.Duration
		stale  bool
	}{
		{"current", 0, false}, {"boundary", 75 * time.Second, false}, {"stale", 75*time.Second + time.Nanosecond, true}, {"future", -time.Nanosecond, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New(monitorConfig())
			m.now = func() time.Time { return base.Add(tc.offset) }
			status, expiry := 200, base.Add(90*24*time.Hour)
			m.items = []Result{
				{ID: "https-fixture", Scheme: "https", State: "ok", Reason: "http_2xx", ObservedAt: &base, HTTPStatus: &status, TLS: TLSResult{State: "valid", ExpiresAt: &expiry}},
				{ID: "http-fixture", Scheme: "http", State: "ok", Reason: "http_2xx", ObservedAt: &base, HTTPStatus: &status, TLS: TLSResult{State: "not_applicable"}},
			}
			for range 2 {
				v := m.Status()
				for i, r := range v.Items {
					if r.ObservedAt == nil || !r.ObservedAt.Equal(base) {
						t.Fatal("Status refreshed observation timestamp")
					}
					if tc.stale {
						wantTLS := "unknown"
						if i == 1 {
							wantTLS = "not_applicable"
						}
						if r.State != "unknown" || r.Reason != "stale" || r.HTTPStatus != nil || r.TLS.State != wantTLS || r.TLS.ExpiresAt != nil {
							t.Fatalf("stale/future result retained success fields: %+v", r)
						}
					} else if r.State != "ok" || r.Reason != "http_2xx" || r.HTTPStatus == nil || *r.HTTPStatus != 200 {
						t.Fatalf("fresh result hidden: %+v", r)
					}
				}
			}
			if m.items[0].State != "ok" || m.items[0].HTTPStatus == nil || m.items[0].TLS.ExpiresAt == nil {
				t.Fatal("Status mutated retained observation")
			}
		})
	}
}

func TestMonitorSnapshotCopiesAllPointers(t *testing.T) {
	m := New(monitorConfig())
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	status, expiry := 200, now.Add(90*24*time.Hour)
	m.items[0] = Result{ID: "https-fixture", Scheme: "https", State: "ok", Reason: "http_2xx", ObservedAt: &now, HTTPStatus: &status, TLS: TLSResult{State: "valid", ExpiresAt: &expiry}}
	first := m.Status()
	first.Items[0].ID, first.Items[0].State = "mutated", "http_error"
	*first.Items[0].ObservedAt = now.Add(-time.Hour)
	*first.Items[0].HTTPStatus = 500
	*first.Items[0].TLS.ExpiresAt = now.Add(-time.Hour)
	first.Items = append(first.Items, Result{ID: "injected"})
	second := m.Status()
	if len(second.Items) != 2 || second.Items[0].ID != "https-fixture" || second.Items[0].State != "ok" || !second.Items[0].ObservedAt.Equal(now) || *second.Items[0].HTTPStatus != 200 || !second.Items[0].TLS.ExpiresAt.Equal(expiry) {
		t.Fatalf("snapshot mutation reached monitor storage: %+v", second)
	}
}

func TestMonitorClonesProbeResultsAndRedactsPrivateConfiguration(t *testing.T) {
	m := New(monitorConfig())
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	status, expiry := 200, now.Add(90*24*time.Hour)
	m.check = func(context.Context, target, string, time.Time) Result {
		return Result{State: "ok", Scheme: "https", Reason: "http_2xx", HTTPStatus: &status, TLS: TLSResult{State: "valid", ExpiresAt: &expiry}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.wait = func(context.Context, time.Duration) bool { cancel(); return false }
	if err := m.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	status, expiry = 503, now.Add(-time.Hour)
	v := m.Status()
	if *v.Items[0].HTTPStatus != 200 || !v.Items[0].TLS.ExpiresAt.Equal(now.Add(90*24*time.Hour)) {
		t.Fatal("probe-owned pointers mutated stored observation")
	}
	encoded, err := json.Marshal(m)
	if err != nil || string(encoded) != `{"redacted":true}` {
		t.Fatalf("monitor marshal not redacted: %q %v", encoded, err)
	}
	statusJSON, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{fmt.Sprint(m), fmt.Sprintf("%#v", m), string(statusJSON)} {
		for _, forbidden := range []string{"fixture.example", "8.8.8.8", "manager.example", "fixture-manager", "allowedAddresses"} {
			if strings.Contains(output, forbidden) {
				t.Errorf("diagnostics/view reveal private configuration %q", forbidden)
			}
		}
	}
}

func TestMonitorAgesVerifiedCertificateWithoutRefreshingHTTP(t *testing.T) {
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                string
		expires             time.Time
		initial, atBoundary string
	}{
		{"valid to expiring", base.Add(30*24*time.Hour + time.Minute), "valid", "expiring"},
		{"expiring to expired", base.Add(time.Minute), "expiring", "expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := monitorConfig()
			config.interval = time.Hour
			m := New(config)
			m.check = func(context.Context, target, string, time.Time) Result {
				t.Error("Status initiated a fresh check")
				return Result{}
			}
			m.wait = func(context.Context, time.Duration) bool { t.Error("Status scheduled a check"); return false }
			current := base
			m.now = func() time.Time { return current }
			status := 200
			m.items[0] = Result{ID: "https-fixture", Scheme: "https", State: "ok", Reason: "http_2xx", ObservedAt: &base, HTTPStatus: &status, TLS: TLSResult{State: tc.initial, ExpiresAt: &tc.expires}}
			for _, point := range []struct {
				elapsed time.Duration
				wantTLS string
			}{
				{0, tc.initial}, {time.Minute - time.Nanosecond, tc.initial}, {time.Minute, tc.atBoundary}, {time.Minute + time.Second, tc.atBoundary},
			} {
				current = base.Add(point.elapsed)
				r := m.Status().Items[0]
				if r.TLS.State != point.wantTLS || r.TLS.ExpiresAt == nil || !r.TLS.ExpiresAt.Equal(tc.expires) || r.State != "ok" || r.Reason != "http_2xx" || r.HTTPStatus == nil || *r.HTTPStatus != 200 || r.ObservedAt == nil || !r.ObservedAt.Equal(base) {
					t.Fatalf("expiry aging at %s refreshed/lost HTTP evidence or misclassified expiry: %+v", point.elapsed, r)
				}
			}
			current = base.Add(time.Hour + 16*time.Second)
			r := m.Status().Items[0]
			if r.State != "unknown" || r.Reason != "stale" || r.HTTPStatus != nil || r.TLS.State != "unknown" || r.TLS.ExpiresAt != nil || !r.ObservedAt.Equal(base) {
				t.Fatalf("expiry aging overrode stale evidence clearing: %+v", r)
			}
			if m.items[0].TLS.State != tc.initial || !m.items[0].ObservedAt.Equal(base) {
				t.Fatal("Status rewrote the original certificate observation")
			}
		})
	}
}
