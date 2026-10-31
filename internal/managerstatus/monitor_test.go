package managerstatus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newMonitor(t *testing.T, checks []Check, now func() time.Time) *Monitor {
	t.Helper()
	m, e := New(checks, now)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func TestMonitorValidation(t *testing.T) {
	for _, checks := range [][]Check{{{Component: "private-sentinel", Probe: func(context.Context) ProbeResult { return ProbeResult{State: OK} }}}, {{Component: AppStorage}}, {{Component: AppStorage, Probe: func(context.Context) ProbeResult { return ProbeResult{State: OK} }}, {Component: AppStorage, Probe: func(context.Context) ProbeResult { return ProbeResult{State: OK} }}}} {
		if _, e := New(checks, nil); e == nil {
			t.Fatal("accepted invalid configuration")
		}
	}
}
func TestMonitorLifecycleAndCopies(t *testing.T) {
	now := time.Unix(100, 0)
	state := OK
	m := newMonitor(t, []Check{{AppStorage, func(context.Context) ProbeResult {
		return ProbeResult{State: state, Storage: &StorageMetrics{PoolOpen: 2, PoolInUse: 1}, Work: &WorkMetrics{Used: 2, Limit: 2}}
	}}}, func() time.Time { return now })
	if s := m.Snapshot(); s.Ready || s.State != Starting {
		t.Fatalf("initial %+v", s)
	}
	if e := m.Refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !m.Snapshot().Ready {
		t.Fatal("occupied work must remain ready")
	}
	s := m.Snapshot()
	s.Components[0].Storage.PoolOpen = 99
	s.Components[0].State = Invalid
	if m.Snapshot().Components[0].Storage.PoolOpen != 2 || !m.Snapshot().Ready {
		t.Fatal("snapshot alias")
	}
	metrics := m.Metrics()
	metrics.Probes[0].Outcomes[0].Count = 99
	if m.Metrics().Probes[0].Outcomes[0].Count != 1 {
		t.Fatal("metrics alias")
	}
	now = now.Add(16 * time.Second)
	if s := m.Snapshot(); s.Ready || s.State != Stale {
		t.Fatal("not stale")
	}
	state = Unavailable
	_ = m.Refresh(context.Background())
	if m.Snapshot().Ready {
		t.Fatal("failure ready")
	}
	state = OK
	_ = m.Refresh(context.Background())
	if !m.Snapshot().Ready {
		t.Fatal("did not recover")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.Run(ctx)
	if s := m.Snapshot(); s.Ready || s.State != Stopped {
		t.Fatal("not stopped")
	}
	if m.Refresh(context.Background()) == nil {
		t.Fatal("stopped refresh accepted")
	}
}
func TestMonitorSanitize(t *testing.T) {
	tests := []struct {
		in   ProbeResult
		want State
	}{
		{ProbeResult{State: State("private-sentinel")}, Invalid},
		{ProbeResult{State: OK, Storage: &StorageMetrics{PoolOpen: -1}}, Invalid},
		{ProbeResult{State: OK, Storage: &StorageMetrics{PoolOpen: 1, PoolInUse: 2}}, Invalid},
		{ProbeResult{State: OK, Storage: &StorageMetrics{PoolWaitCount: -1}}, Invalid},
		{ProbeResult{State: OK, Storage: &StorageMetrics{DatabaseBytes: 10, MaxDatabaseBytes: 10}}, OK},
		{ProbeResult{State: OK, Capacity: &CapacityMetrics{Used: 2, Limit: 1}}, Invalid},
		{ProbeResult{State: OK, Capacity: &CapacityMetrics{Used: 2, Limit: 3, Active: 2, Pending: 1}}, Invalid},
		{ProbeResult{State: OK, Capacity: &CapacityMetrics{Used: 2, Limit: 2}}, OK},
		{ProbeResult{State: OK, Work: &WorkMetrics{Used: 2, Limit: 1}}, Invalid},
		{ProbeResult{State: OK, Work: &WorkMetrics{Used: 2, Limit: 2}}, OK},
	}
	for _, tt := range tests {
		out := sanitize(tt.in)
		if out.State != tt.want {
			t.Fatalf("%+v got %+v want %s", tt.in, out, tt.want)
		}
		if out.State == Invalid && (out.Storage != nil || out.Capacity != nil || out.Work != nil) {
			t.Fatal("invalid metric leaked")
		}
	}
}
func TestMonitorTimeoutBoundsAndRecovery(t *testing.T) {
	block := make(chan struct{})
	var calls atomic.Int32
	m := newMonitor(t, []Check{{AppStorage, func(context.Context) ProbeResult { calls.Add(1); <-block; return ProbeResult{State: OK} }}, {TrustStorage, func(context.Context) ProbeResult { calls.Add(1); return ProbeResult{State: OK} }}}, nil)
	start := time.Now()
	_ = m.Refresh(context.Background())
	if time.Since(start) > 2*time.Second {
		t.Fatal("unbounded timeout")
	}
	s := m.Snapshot()
	if s.Ready || s.Components[0].State != Timeout || s.Components[1].State != Busy {
		t.Fatalf("%+v", s)
	}
	for range 20 {
		_ = m.Refresh(context.Background())
	}
	if calls.Load() != 1 {
		t.Fatal("overlapping probes")
	}
	close(block)
	deadline := time.Now().Add(time.Second)
	for len(m.probeSlot) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	_ = m.Refresh(context.Background())
	if !m.Snapshot().Ready {
		t.Fatal("did not recover")
	}
}
func TestMonitorPanicPrivacyAndConcurrentReaders(t *testing.T) {
	m := newMonitor(t, []Check{{AppStorage, func(context.Context) ProbeResult { panic("private-sentinel") }}}, nil)
	_ = m.Refresh(context.Background())
	if m.Snapshot().Components[0].State != Invalid {
		t.Fatal("panic not fail closed")
	}
	handler := m.Wrap(Operator, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 30 {
				handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/private-sentinel?secret=private-sentinel", nil))
				_ = m.Snapshot()
				_ = m.Metrics()
			}
		}()
	}
	wg.Wait()
	data, e := json.Marshal(m.Metrics())
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(data), "private-sentinel") {
		t.Fatal("private string disclosed")
	}
	h := m.Metrics().HTTP[0]
	if h.Requests != 360 || h.Inflight != 0 || h.StatusClasses[1] != 360 {
		t.Fatalf("%+v", h)
	}
}
func TestMonitorHTTPBehavior(t *testing.T) {
	m := newMonitor(t, healthyChecks(), nil)
	for _, h := range []http.Handler{http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e := http.NewResponseController(w).Flush(); e != nil {
			t.Error(e)
		}
	})} {
		m.Wrap(Agent, h).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}
	func() {
		defer func() {
			if recover() != "sentinel-panic" {
				t.Error("panic changed or suppressed")
			}
		}()
		m.Wrap(Agent, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("sentinel-panic") })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}()
	h := m.Metrics().HTTP[1]
	if h.Requests != 4 || h.Inflight != 0 || h.StatusClasses[1] != 3 || h.StatusClasses[5] != 1 {
		t.Fatalf("%+v", h)
	}
}
func TestMonitorRefreshConcurrency(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	m := newMonitor(t, []Check{{AppStorage, func(context.Context) ProbeResult { close(entered); <-release; return ProbeResult{State: OK} }}}, nil)
	done := make(chan error, 1)
	go func() { done <- m.Refresh(context.Background()) }()
	<-entered
	if m.Refresh(context.Background()) != errBusy {
		t.Fatal("concurrent refresh accepted")
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestMonitorStaleWithoutSample(t *testing.T) {
	now := time.Unix(100, 0)
	m := newMonitor(t, healthyChecks(), func() time.Time { return now })
	now = now.Add(15 * time.Second)
	if s := m.Snapshot(); s.Ready || s.State != Stale {
		t.Fatalf("%+v", s)
	}
}
func TestMonitorRunCancellationAndSingleLoop(t *testing.T) {
	entered := make(chan struct{})
	var once sync.Once
	m := newMonitor(t, []Check{{AppStorage, func(ctx context.Context) ProbeResult {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return ProbeResult{State: Unavailable}
	}}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	<-entered
	// Second Run must not start or stop the active owner.
	m.Run(context.Background())
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run cancellation blocked")
	}
	if m.Snapshot().State != Stopped {
		t.Fatal("Run did not stop")
	}
}

func healthyChecks() []Check {
	return []Check{{AppStorage, func(context.Context) ProbeResult { return ProbeResult{State: OK} }}}
}
func TestMonitorRejectEmptyAndAtCap(t *testing.T) {
	for _, checks := range [][]Check{nil, {}} {
		if m, err := New(checks, nil); err == nil || m != nil {
			t.Fatal("empty monitor accepted")
		}
	}
	m := newMonitor(t, []Check{{AppStorage, func(context.Context) ProbeResult {
		return ProbeResult{State: OK, Storage: &StorageMetrics{DatabaseBytes: 10, MaxDatabaseBytes: 10, WALBytes: 20, MaxWALBytes: 20}}
	}}}, nil)
	if err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := m.Metrics().Snapshot; !s.Ready || s.Components[0].State != OK {
		t.Fatal("at-cap bytes falsely imply known write failure")
	}
	for _, storage := range []*StorageMetrics{{DatabaseBytes: 11, MaxDatabaseBytes: 10}, {WALBytes: 21, MaxWALBytes: 20}} {
		if s := sanitize(ProbeResult{State: OK, Storage: storage}); s.State != Invalid || s.Storage != nil {
			t.Fatal("above-cap metrics accepted")
		}
	}
}
func TestMonitorNilContext(t *testing.T) {
	m := newMonitor(t, healthyChecks(), nil)
	if m.Refresh(nil) == nil {
		t.Fatal("nil refresh context accepted")
	}
	m.Run(nil)
	if s := m.Metrics().Snapshot; s.Ready || s.State != Stopped {
		t.Fatal("nil run context not fail closed")
	}
}

func TestMonitorExplicitCapacityStateAndWorkValidation(t *testing.T) {
	for _, state := range []State{OK, Full} {
		m := newMonitor(t, []Check{{Authentication, func(context.Context) ProbeResult {
			return ProbeResult{State: state, Capacity: &CapacityMetrics{Used: 2, Limit: 2, Terminal: 2}, Work: &WorkMetrics{Used: 1, Limit: 1, Retained: 2, RetainedLimit: 2, Completed: 5, Failed: 1, LastCompletedUnixMillis: 200, LastSucceededUnixMillis: 100}}
		}}}, nil)
		if err := m.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		s := m.Metrics().Snapshot
		if s.Ready != (state == OK) || s.Components[0].State != state {
			t.Fatal("metrics overrode explicit probe readiness")
		}
	}
	for _, w := range []*WorkMetrics{{Retained: -1}, {RetainedLimit: -1}, {Retained: 2, RetainedLimit: 1}, {Completed: 1, Failed: 2}, {LastCompletedUnixMillis: -1}, {LastSucceededUnixMillis: -1}, {LastCompletedUnixMillis: 1, LastSucceededUnixMillis: 2}, {LastSucceededUnixMillis: 1}} {
		if s := sanitize(ProbeResult{State: OK, Work: w}); s.State != Invalid || s.Work != nil {
			t.Fatalf("invalid work accepted: %+v", w)
		}
	}
}

func TestMonitorQueueFenceCopiesAndCachedRuntime(t *testing.T) {
	queue := &QueueMetrics{Records: 2, Queued: 1, Uncertain: 1, Dropped: 3, PendingLimit: 500, RecordLimit: 1000}
	fences := &FenceMetrics{JournalCancellationPending: true, JournalCaptureUnconfirmed: true}
	m, err := New([]Check{{Component: AppStorage, Probe: func(context.Context) ProbeResult {
		return ProbeResult{State: OK, AlarmQueue: queue, WindowsQueue: &QueueMetrics{PendingLimit: 500, RecordLimit: 1000}, Fences: fences}
	}}}, nil)
	if err != nil {
		t.Fatal("fixture rejected")
	}
	if err = m.Refresh(context.Background()); err != nil {
		t.Fatal("sample failed")
	}
	before := m.Metrics().Runtime
	queue.Records = 99
	fences.JournalCaptureUnconfirmed = false
	view := m.Snapshot()
	if !view.Ready || view.Components[0].AlarmQueue.Records != 2 || !view.Components[0].Fences.JournalCaptureUnconfirmed {
		t.Fatal("probe-owned values changed cached state")
	}
	view.Components[0].AlarmQueue.Queued = 99
	view.Components[0].WindowsQueue.Dropped = 99
	view.Components[0].Fences.JournalCancellationPending = false
	fresh := m.Snapshot()
	if fresh.Components[0].AlarmQueue.Queued != 1 || fresh.Components[0].WindowsQueue.Dropped != 0 || !fresh.Components[0].Fences.JournalCancellationPending {
		t.Fatal("display values changed cached state")
	}
	if after := m.Metrics().Runtime; before != after || after.Goroutines < 1 {
		t.Fatal("HTTP read collected runtime work or lost sample")
	}
	for _, invalid := range []*QueueMetrics{{Records: 1, RecordLimit: 1000, PendingLimit: 500}, {Records: 1, Queued: 1, PendingLimit: 0, RecordLimit: 1000}, {Dropped: -1, PendingLimit: 500, RecordLimit: 1000}} {
		if sanitize(ProbeResult{State: OK, WindowsQueue: invalid}).State != Invalid {
			t.Fatal("inconsistent queue metrics admitted")
		}
	}
}
