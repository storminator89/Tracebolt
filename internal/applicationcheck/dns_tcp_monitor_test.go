package applicationcheck

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/lanconfig"
)

func dnsTCPMonitorConfig() Config {
	http := transportTarget("https://private-fixture.example/status")
	http.ID, http.Kind = "http-fixture", "http"
	return Config{schema: ConfigSchemaVersionV2, enabled: true, managerID: "fixture-manager", origin: "https://manager.example", profile: lanconfig.TLS,
		interval: time.Minute, targets: []target{http, dnsTCPTarget("dns"), dnsTCPTarget("tcp")}}
}

func assertDNSHTTPJSON(t *testing.T, r Result, v2 bool) {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"httpStatus", "id", "observedAt", "reason", "state", "targetScheme", "tls"}
	if v2 {
		want = append(want, "kind")
		sort.Strings(want)
		if string(fields["kind"]) != `"http"` {
			t.Fatalf("HTTP v2 discriminator missing: %s", raw)
		}
	}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("incorrect HTTP compatibility shape: got %v, want %v; JSON=%s", keys, want, raw)
	}
}

func TestDNSAndTCPMonitorV2InitialViewIsInertAndKindSpecific(t *testing.T) {
	c := dnsTCPMonitorConfig()
	m := New(c)
	m.check = func(context.Context, target, string, time.Time) Result {
		t.Error("status initiated probe")
		return Result{}
	}
	m.wait = func(context.Context, time.Duration) bool { t.Error("status scheduled wait"); return false }
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	for range 2 {
		v := m.Status()
		if v.SchemaVersion != SchemaVersionV2 || !v.Enabled || v.Vantage != "management_server" || !v.ServerNow.Equal(now) || v.IntervalSeconds != 60 || v.MaxAgeSeconds != 80 || len(v.Items) != 3 {
			t.Fatalf("incorrect mixed initial view: %+v", v)
		}
		for i, r := range v.Items {
			if r.ID != c.targets[i].ID || r.Kind != c.targets[i].Kind || r.State != "unknown" || r.Reason != "not_checked" || r.ObservedAt != nil {
				t.Fatalf("initial view lost target kind or invented evidence: %+v", r)
			}
			if r.Kind == "http" {
				assertDNSHTTPJSON(t, r, true)
			} else {
				assertDNSCommonJSON(t, r)
			}
		}
	}
}

func TestDNSAndTCPDisabledV2PreservesSchemaWithoutWork(t *testing.T) {
	m := New(Config{schema: ConfigSchemaVersionV2})
	m.check = func(context.Context, target, string, time.Time) Result {
		t.Error("disabled v2 monitor probed")
		return Result{}
	}
	m.wait = func(context.Context, time.Duration) bool { t.Error("disabled v2 monitor waited"); return false }
	if err := m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	v := m.Status()
	if v.SchemaVersion != SchemaVersionV2 || v.Enabled || v.Items == nil || len(v.Items) != 0 || v.IntervalSeconds != 0 || v.MaxAgeSeconds != 0 {
		t.Fatalf("disabled v2 reverted schema or retained evidence: %+v", v)
	}
}

func TestDNSAndTCPMonitorMixedSequentialCadenceAndKindAuthority(t *testing.T) {
	c := dnsTCPMonitorConfig()
	m := New(c)
	start := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	now := start
	m.now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var order []string
	var starts []time.Time
	var active atomic.Int32
	m.check = func(_ context.Context, trg target, profile string, observed time.Time) Result {
		if active.Add(1) != 1 {
			t.Error("mixed probes overlapped")
		}
		defer active.Add(-1)
		if profile != lanconfig.TLS || !observed.Equal(now) {
			t.Error("mixed check received wrong start or profile")
		}
		order = append(order, trg.Kind)
		starts = append(starts, observed)
		now = now.Add(2 * time.Second)
		status := 204
		// The monitor owns both configured identity fields, even for a probe
		// seam returning an incorrect discriminator.
		r := Result{ID: "incorrect-id", Kind: "incorrect-kind", State: "ok", Reason: trg.Kind + "_fixture"}
		if trg.Kind == "http" {
			r.Scheme, r.HTTPStatus, r.TLS.State = "https", &status, "valid"
		}
		return r
	}
	waits := 0
	m.wait = func(_ context.Context, interval time.Duration) bool {
		waits++
		if interval != time.Minute || active.Load() != 0 || len(order) != waits*3 {
			t.Error("timer did not wait for a complete serial mixed sweep")
		}
		if waits == 2 {
			cancel()
			return false
		}
		now = now.Add(interval)
		return true
	}
	if err := m.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("mixed Run termination: %v", err)
	}
	if !reflect.DeepEqual(order, []string{"http", "dns", "tcp", "http", "dns", "tcp"}) || waits != 2 {
		t.Fatalf("incorrect mixed sweep order %v, waits=%d", order, waits)
	}
	if !reflect.DeepEqual(starts, []time.Time{start, start.Add(2 * time.Second), start.Add(4 * time.Second), start.Add(66 * time.Second), start.Add(68 * time.Second), start.Add(70 * time.Second)}) {
		t.Fatalf("mixed cadence caught up from a start rather than completion: %v", starts)
	}
	v := m.Status()
	if v.SchemaVersion != SchemaVersionV2 {
		t.Fatalf("mixed publication lost v2 schema: %q", v.SchemaVersion)
	}
	for i, r := range v.Items {
		if r.ID != c.targets[i].ID || r.Kind != c.targets[i].Kind || r.State != "ok" || r.ObservedAt == nil || !r.ObservedAt.Equal(starts[i+3]) {
			t.Fatalf("mixed publication lost configured identity or observation start: %+v", r)
		}
		if r.Kind == "http" {
			assertDNSHTTPJSON(t, r, true)
		} else {
			assertDNSCommonJSON(t, r)
		}
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-fixture.example", "8.8.8.8", "8443", "manager.example", "fixture-manager", "allowedAddresses"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("mixed status leaks private configuration %q", forbidden)
		}
	}
}

func TestDNSAndTCPMonitorFreshnessPreservesKindsAndSnapshotIsolation(t *testing.T) {
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		offset time.Duration
		stale  bool
	}{
		{"fresh", 0, false}, {"max-age boundary", 80 * time.Second, false}, {"stale", 80*time.Second + time.Nanosecond, true}, {"future", -time.Nanosecond, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := dnsTCPMonitorConfig()
			m := New(c)
			m.now = func() time.Time { return base.Add(tc.offset) }
			status, expiry := 200, base.Add(90*24*time.Hour)
			for i, trg := range c.targets {
				observed := base
				r := Result{Kind: trg.Kind, ID: trg.ID, State: "ok", Reason: trg.Kind + "_fixture", ObservedAt: &observed}
				if trg.Kind == "http" {
					r.Scheme, r.HTTPStatus, r.TLS = "https", &status, TLSResult{State: "valid", ExpiresAt: &expiry}
				}
				m.items[i] = r
			}
			for range 2 {
				v := m.Status()
				if v.SchemaVersion != SchemaVersionV2 || len(v.Items) != 3 {
					t.Fatalf("aged snapshot lost schema/items: %+v", v)
				}
				for i, r := range v.Items {
					if r.Kind != c.targets[i].Kind || r.ID != c.targets[i].ID || r.ObservedAt == nil || !r.ObservedAt.Equal(base) {
						t.Fatalf("aged/copied snapshot lost identity or refreshed time: %+v", r)
					}
					if tc.stale {
						if r.State != "unknown" || r.Reason != "stale" || r.HTTPStatus != nil || r.TLS.ExpiresAt != nil {
							t.Fatalf("stale mixed result retained success evidence: %+v", r)
						}
					} else if r.State != "ok" {
						t.Fatalf("fresh mixed result lost observation: %+v", r)
					}
					if r.Kind == "http" {
						assertDNSHTTPJSON(t, r, true)
					} else {
						assertDNSCommonJSON(t, r)
					}
					*r.ObservedAt = time.Time{}
					v.Items[i].Kind, v.Items[i].ID = "changed", "changed"
				}
			}
			for i, r := range m.items {
				if r.Kind != c.targets[i].Kind || r.ID != c.targets[i].ID || r.State != "ok" || !r.ObservedAt.Equal(base) {
					t.Fatalf("Status or caller rewrote retained observation: %+v", r)
				}
			}
		})
	}
}

func TestDNSAndTCPMonitorCancellationDoesNotPublishLateProbeSuccess(t *testing.T) {
	for _, cancelKind := range []string{"dns", "tcp"} {
		t.Run(cancelKind, func(t *testing.T) {
			c := dnsTCPMonitorConfig()
			m := New(c)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checks := 0
			m.check = func(_ context.Context, trg target, _ string, _ time.Time) Result {
				checks++
				if trg.Kind == cancelKind {
					cancel()
				}
				return Result{Kind: trg.Kind, State: "ok", Reason: trg.Kind + "_fixture"}
			}
			m.wait = func(context.Context, time.Duration) bool { t.Error("cancelled sweep waited"); return false }
			if err := m.Run(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled Run: %v", err)
			}
			wantChecks := 2
			if cancelKind == "tcp" {
				wantChecks = 3
			}
			if checks != wantChecks {
				t.Fatalf("cancellation continued sweep: %d checks", checks)
			}
			v := m.Status()
			for i, r := range v.Items {
				if r.Kind != c.targets[i].Kind || r.ID != c.targets[i].ID {
					t.Fatalf("cancelled snapshot lost kind/identity: %+v", r)
				}
				if i < wantChecks-1 {
					if r.State != "ok" || r.ObservedAt == nil {
						t.Fatalf("cancelled probe erased prior completed evidence: %+v", r)
					}
				} else if r.State != "unknown" || r.Reason != "not_checked" || r.ObservedAt != nil {
					t.Fatalf("cancelled or later work was published: %+v", r)
				}
			}
		})
	}
}

func TestDNSAndTCPMonitorV1HTTPJSONRemainsCompatible(t *testing.T) {
	m := New(monitorConfig())
	initial := m.Status()
	if initial.SchemaVersion != SchemaVersion {
		t.Fatalf("legacy config changed wire version: %s", initial.SchemaVersion)
	}
	for _, r := range initial.Items {
		assertDNSHTTPJSON(t, r, false)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.check = func(_ context.Context, trg target, _ string, _ time.Time) Result {
		status := 200
		return Result{Kind: "http", ID: trg.ID, Scheme: "http", State: "ok", Reason: "http_2xx", HTTPStatus: &status, TLS: TLSResult{State: "not_applicable"}}
	}
	m.wait = func(context.Context, time.Duration) bool { cancel(); return false }
	if err := m.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, r := range m.Status().Items {
		assertDNSHTTPJSON(t, r, false)
	}
}
