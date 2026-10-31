// Package managerstatus provides bounded, identifier-free manager diagnostics.
package managerstatus

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"sync"
	"time"
)

type Component string

const (
	AppStorage                Component = "application_storage"
	TrustStorage              Component = "trust_storage"
	LinuxEnrollment           Component = "linux_enrollment"
	WindowsEnrollment         Component = "windows_enrollment"
	MacOSBasicEnrollment      Component = "macos_basic_enrollment"
	MacOSInventoryEnrollment  Component = "macos_inventory_enrollment"
	Issuer                    Component = "issuer"
	ServerTLS                 Component = "server_tls"
	Filesystem                Component = "filesystem_write"
	InventoryMaintenance      Component = "inventory_maintenance"
	WindowsMaintenance        Component = "windows_maintenance"
	MacOSInventoryMaintenance Component = "macos_inventory_maintenance"
	Authentication            Component = "authentication"
)

var components = [...]Component{AppStorage, TrustStorage, LinuxEnrollment, WindowsEnrollment, MacOSBasicEnrollment, MacOSInventoryEnrollment, Issuer, ServerTLS, Filesystem, InventoryMaintenance, WindowsMaintenance, MacOSInventoryMaintenance, Authentication}

type State string

const (
	OK          State = "ok"
	Starting    State = "starting"
	Busy        State = "busy"
	Full        State = "full"
	Unavailable State = "unavailable"
	Expired     State = "expired"
	Stopped     State = "stopped"
	Stale       State = "stale"
	Timeout     State = "timeout"
	Invalid     State = "invalid"
	ReadOnly    State = "readonly"
	Denied      State = "denied"
	IOError     State = "io_error"
	Exhausted   State = "resource_exhausted"
)

var states = [...]State{OK, Starting, Busy, Full, Unavailable, Expired, Stopped, Stale, Timeout, Invalid, ReadOnly, Denied, IOError, Exhausted}

type StorageMetrics struct {
	// Optional filesystem aggregates. Omitted zero can mean unavailable or zero;
	// State, not presence of these fields, determines readiness.
	AvailableBytes       uint64 `json:"availableBytes,omitempty"`
	FreeInodes           uint64 `json:"freeInodes,omitempty"`
	ProbeBytes           uint64 `json:"probeBytes,omitempty"`
	DatabaseBytes        uint64 `json:"databaseBytes"`
	WALBytes             uint64 `json:"walBytes"`
	MaxDatabaseBytes     uint64 `json:"maxDatabaseBytes"`
	MaxWALBytes          uint64 `json:"maxWALBytes"`
	PoolOpen             int    `json:"poolOpen"`
	PoolInUse            int    `json:"poolInUse"`
	PoolWaitCount        int64  `json:"poolWaitCount"`
	PoolWaitMilliseconds int64  `json:"poolWaitMilliseconds"`
}
type CapacityMetrics struct {
	Used     int `json:"used"`
	Limit    int `json:"limit"`
	Active   int `json:"active"`
	Pending  int `json:"pending"`
	Terminal int `json:"terminal"`
}
type WorkMetrics struct {
	Retained                int    `json:"retained,omitempty"`
	RetainedLimit           int    `json:"retainedLimit,omitempty"`
	Completed               uint64 `json:"completed,omitempty"`
	Failed                  uint64 `json:"failed,omitempty"`
	LastCompletedUnixMillis int64  `json:"lastCompletedUnixMillis,omitempty"`
	LastSucceededUnixMillis int64  `json:"lastSucceededUnixMillis,omitempty"`
	Used                    int    `json:"used"`
	Limit                   int    `json:"limit"`
}

// QueueMetrics describes one existing bounded manager-owned notification outbox.
// It never contains destination, event, device, recipient or payload fields.
type QueueMetrics struct {
	Records          int   `json:"records"`
	Queued           int   `json:"queued"`
	InFlight         int   `json:"inFlight"`
	ProviderAccepted int   `json:"providerAccepted"`
	Failed           int   `json:"failed"`
	Uncertain        int   `json:"uncertain"`
	Suppressed       int   `json:"suppressed"`
	Dropped          int64 `json:"dropped"`
	PendingLimit     int   `json:"pendingLimit"`
	RecordLimit      int   `json:"recordLimit"`
}

// FenceMetrics is visibility only; a successful DB probe never clears a fence
// or claims availability of an independently scoped AI operation.
type FenceMetrics struct {
	JournalCancellationPending bool `json:"journalCancellationPending"`
	JournalCaptureUnconfirmed  bool `json:"journalCaptureUnconfirmed"`
}
type ProbeResult struct {
	WindowsQueue *QueueMetrics    `json:"windowsQueue,omitempty"`
	AlarmQueue   *QueueMetrics    `json:"alarmQueue,omitempty"`
	Fences       *FenceMetrics    `json:"fences,omitempty"`
	State        State            `json:"state"`
	Storage      *StorageMetrics  `json:"storage,omitempty"`
	Capacity     *CapacityMetrics `json:"capacity,omitempty"`
	Work         *WorkMetrics     `json:"work,omitempty"`
}
type Check struct {
	Component Component
	Probe     func(context.Context) ProbeResult
}
type ComponentStatus struct {
	Component Component `json:"component"`
	ProbeResult
}
type Snapshot struct {
	Ready      bool              `json:"ready"`
	State      State             `json:"state"`
	SampledAt  time.Time         `json:"sampledAt"`
	Components []ComponentStatus `json:"components"`
}
type OutcomeCount struct {
	State State  `json:"state"`
	Count uint64 `json:"count"`
}
type ProbeMetrics struct {
	Component Component      `json:"component"`
	Outcomes  []OutcomeCount `json:"outcomes"`
}
type Surface string

const (
	Operator Surface = "operator"
	Agent    Surface = "agent"
)

// Duration buckets are disjoint: <=10ms, <=100ms, <=1s, <=5s, >5s.
// Status classes are 1xx, 2xx, 3xx, 4xx, 5xx, other (including panic).
type HTTPMetrics struct {
	Surface         Surface   `json:"surface"`
	Inflight        uint64    `json:"inflight"`
	Requests        uint64    `json:"requests"`
	StatusClasses   [6]uint64 `json:"statusClasses"`
	DurationBuckets [5]uint64 `json:"durationBuckets"`
}
type RuntimeMetrics struct {
	Goroutines              int    `json:"goroutines"`
	HeapBytes               uint64 `json:"heapBytes"`
	HeapObjects             uint64 `json:"heapObjects"`
	SystemBytes             uint64 `json:"systemBytes"`
	NextGCBytes             uint64 `json:"nextGCBytes"`
	GCPauseTotalNanoseconds uint64 `json:"gcPauseTotalNanoseconds"`
	GCCount                 uint32 `json:"gcCount"`
}
type Metrics struct {
	Snapshot Snapshot       `json:"snapshot"`
	Probes   []ProbeMetrics `json:"probes"`
	HTTP     [2]HTTPMetrics `json:"http"`
	Runtime  RuntimeMetrics `json:"runtime"`
}
type Monitor struct {
	mu               sync.Mutex
	checks           []Check
	now              func() time.Time
	snapshot         Snapshot
	startedAt        time.Time
	counts           [len(components)][len(states)]uint64
	http             [2]HTTPMetrics
	runtime          RuntimeMetrics
	refreshSlot      chan struct{}
	probeSlot        chan struct{}
	running, stopped bool
}

var errBusy = errors.New("monitor refresh busy")
var errStopped = errors.New("monitor stopped")

func New(checks []Check, now func() time.Time) (*Monitor, error) {
	if len(checks) == 0 || len(checks) > len(components) {
		return nil, errors.New("invalid monitor check count")
	}
	seen := map[Component]bool{}
	for _, c := range checks {
		valid := false
		for _, v := range components {
			if v == c.Component {
				valid = true
			}
		}
		if !valid || seen[c.Component] || c.Probe == nil {
			return nil, errors.New("invalid monitor check")
		}
		seen[c.Component] = true
	}
	if now == nil {
		now = time.Now
	}
	m := &Monitor{checks: append([]Check(nil), checks...), now: now, refreshSlot: make(chan struct{}, 1), probeSlot: make(chan struct{}, 1)}
	m.startedAt = now()
	m.runtime = sampleRuntime()
	m.snapshot = Snapshot{State: Starting, Components: make([]ComponentStatus, len(checks))}
	for i, c := range checks {
		m.snapshot.Components[i] = ComponentStatus{c.Component, ProbeResult{State: Starting}}
	}
	m.http[0].Surface = Operator
	m.http[1].Surface = Agent
	return m, nil
}
func increment(v *uint64) {
	if *v < ^uint64(0) {
		*v++
	}
}
func cloneResult(r ProbeResult) ProbeResult {
	if r.WindowsQueue != nil {
		v := *r.WindowsQueue
		r.WindowsQueue = &v
	}
	if r.AlarmQueue != nil {
		v := *r.AlarmQueue
		r.AlarmQueue = &v
	}
	if r.Fences != nil {
		v := *r.Fences
		r.Fences = &v
	}
	if r.Storage != nil {
		v := *r.Storage
		r.Storage = &v
	}
	if r.Capacity != nil {
		v := *r.Capacity
		r.Capacity = &v
	}
	if r.Work != nil {
		v := *r.Work
		r.Work = &v
	}
	return r
}
func sanitize(r ProbeResult) ProbeResult {
	valid := false
	for _, s := range states {
		if r.State == s {
			valid = true
		}
	}
	if !valid {
		return ProbeResult{State: Invalid}
	}
	if s := r.Storage; s != nil {
		if s.PoolOpen < 0 || s.PoolInUse < 0 || s.PoolInUse > s.PoolOpen || s.PoolWaitCount < 0 || s.PoolWaitMilliseconds < 0 {
			return ProbeResult{State: Invalid}
		}
		// Equality is not proof of exhaustion: SQLite can reuse free pages.
		// The storage probe owns state; malformed above-cap aggregates fail closed.
		if (s.MaxDatabaseBytes > 0 && s.DatabaseBytes > s.MaxDatabaseBytes) || (s.MaxWALBytes > 0 && s.WALBytes > s.MaxWALBytes) {
			return ProbeResult{State: Invalid}
		}
	}
	if c := r.Capacity; c != nil {
		if c.Used < 0 || c.Limit < 0 || c.Active < 0 || c.Pending < 0 || c.Terminal < 0 || c.Used > c.Limit || c.Active > c.Used || c.Pending > c.Used-c.Active || c.Terminal > c.Used-c.Active-c.Pending {
			return ProbeResult{State: Invalid}
		}
	}
	if w := r.Work; w != nil {
		if w.Used < 0 || w.Limit < 0 || w.Used > w.Limit || w.Retained < 0 || w.RetainedLimit < 0 || w.Retained > w.RetainedLimit || w.Failed > w.Completed || w.LastCompletedUnixMillis < 0 || w.LastSucceededUnixMillis < 0 || w.LastSucceededUnixMillis > w.LastCompletedUnixMillis {
			return ProbeResult{State: Invalid}
		}
	}
	for _, q := range []*QueueMetrics{r.AlarmQueue, r.WindowsQueue} {
		if q == nil {
			continue
		}
		if q.Records < 0 || q.Queued < 0 || q.InFlight < 0 || q.ProviderAccepted < 0 || q.Failed < 0 || q.Uncertain < 0 || q.Suppressed < 0 || q.Dropped < 0 || q.PendingLimit < 0 || q.RecordLimit < 0 || q.Records > q.RecordLimit || q.Queued > q.PendingLimit || q.InFlight > q.PendingLimit-q.Queued || q.Queued > q.Records || q.InFlight > q.Records-q.Queued || q.ProviderAccepted > q.Records-q.Queued-q.InFlight || q.Failed > q.Records-q.Queued-q.InFlight-q.ProviderAccepted || q.Uncertain > q.Records-q.Queued-q.InFlight-q.ProviderAccepted-q.Failed || q.Suppressed != q.Records-q.Queued-q.InFlight-q.ProviderAccepted-q.Failed-q.Uncertain {
			return ProbeResult{State: Invalid}
		}
	}
	return cloneResult(r)
}

// probe retains its sole worker slot until the callback actually exits. Even a
// callback ignoring cancellation cannot create overlapping or unbounded workers.
func (m *Monitor) probe(ctx context.Context, f func(context.Context) ProbeResult) ProbeResult {
	select {
	case m.probeSlot <- struct{}{}:
	default:
		return ProbeResult{State: Busy}
	}
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	result := make(chan ProbeResult, 1)
	go func() {
		r := ProbeResult{State: Invalid}
		func() {
			defer func() {
				if recover() != nil {
					r = ProbeResult{State: Invalid}
				}
			}()
			r = sanitize(f(ctx))
		}()
		<-m.probeSlot
		result <- r
	}()
	select {
	case r := <-result:
		if ctx.Err() != nil {
			return ProbeResult{State: Timeout}
		}
		return r
	case <-ctx.Done():
		return ProbeResult{State: Timeout}
	}
}
func (m *Monitor) Refresh(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil monitor context")
	}
	select {
	case m.refreshSlot <- struct{}{}:
		defer func() { <-m.refreshSlot }()
	default:
		return errBusy
	}
	m.mu.Lock()
	stopped := m.stopped
	m.mu.Unlock()
	if stopped {
		return errStopped
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	s := Snapshot{Ready: true, State: OK, Components: make([]ComponentStatus, len(m.checks))}
	for i, c := range m.checks {
		r := ProbeResult{State: Timeout}
		if ctx.Err() == nil {
			r = m.probe(ctx, c.Probe)
		}
		s.Components[i] = ComponentStatus{c.Component, r}
		if r.State != OK {
			s.Ready = false
			s.State = Unavailable
		}
	}
	s.SampledAt = m.now()
	runtimeSample := sampleRuntime()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return errStopped
	}
	m.snapshot = s
	m.runtime = runtimeSample
	for i, c := range s.Components {
		for j, state := range states {
			if c.State == state {
				increment(&m.counts[i][j])
				break
			}
		}
	}
	return ctx.Err()
}

// Run owns the monitor lifecycle. Calling it again has no effect. Cancellation
// permanently stops this instance; create a new instance for a new lifecycle.
// A nil context fails closed by stopping the instance without running probes.
func (m *Monitor) Run(ctx context.Context) {
	m.mu.Lock()
	if m.running || m.stopped {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.stopped = true; m.running = false; m.mu.Unlock() }()
	if ctx == nil {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		_ = m.Refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (m *Monitor) snapshotLocked() Snapshot {
	s := m.snapshot
	s.Components = append([]ComponentStatus(nil), s.Components...)
	for i := range s.Components {
		s.Components[i].ProbeResult = cloneResult(s.Components[i].ProbeResult)
	}
	last := s.SampledAt
	if last.IsZero() {
		last = m.startedAt
	}
	now := m.now()
	if m.stopped {
		s.Ready = false
		s.State = Stopped
	} else if now.Sub(last) >= 15*time.Second || now.Before(last) {
		s.Ready = false
		s.State = Stale
	}
	return s
}
func (m *Monitor) Snapshot() Snapshot { m.mu.Lock(); defer m.mu.Unlock(); return m.snapshotLocked() }
func (m *Monitor) Metrics() Metrics {
	m.mu.Lock()
	v := Metrics{Snapshot: m.snapshotLocked(), HTTP: m.http, Runtime: m.runtime, Probes: make([]ProbeMetrics, len(m.checks))}
	for i, c := range m.checks {
		v.Probes[i] = ProbeMetrics{Component: c.Component, Outcomes: make([]OutcomeCount, len(states))}
		for j, s := range states {
			v.Probes[i].Outcomes[j] = OutcomeCount{s, m.counts[i][j]}
		}
	}
	m.mu.Unlock()
	return v
}

// Runtime collection runs at construction/background sampling, never on an API
// request. These are Go-process/GC aggregates, not host RAM or OOM assurances.
func sampleRuntime() RuntimeMetrics {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return RuntimeMetrics{Goroutines: runtime.NumGoroutine(), HeapBytes: mem.HeapAlloc, HeapObjects: mem.HeapObjects, SystemBytes: mem.Sys, NextGCBytes: mem.NextGC, GCPauseTotalNanoseconds: mem.PauseTotalNs, GCCount: mem.NumGC}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *responseWriter) WriteHeader(code int) {
	w.ResponseWriter.WriteHeader(code)
	if w.status == 0 && (code >= 200 || code == 101) {
		w.status = code
	}
}
func (w *responseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.ResponseWriter.Write(p)
}

type flushingWriter struct{ *responseWriter }

func (w *flushingWriter) Flush() {
	if w.status == 0 {
		w.status = 200
	}
	w.ResponseWriter.(http.Flusher).Flush()
}

// Wrap uses only the two fixed surface labels. Unknown surfaces are rejected at
// construction rather than becoming attacker-controlled metric cardinality.
func (m *Monitor) Wrap(surface Surface, next http.Handler) http.Handler {
	index := 0
	if surface == Agent {
		index = 1
	} else if surface != Operator {
		panic("invalid monitor surface")
	}
	if next == nil {
		panic("nil monitor handler")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.mu.Lock()
		increment(&m.http[index].Inflight)
		m.mu.Unlock()
		rw := &responseWriter{ResponseWriter: w}
		var writer http.ResponseWriter = rw
		if _, ok := w.(http.Flusher); ok {
			writer = &flushingWriter{rw}
		}
		completed := false
		defer func() {
			elapsed := time.Since(start)
			status := rw.status
			if status == 0 && completed {
				status = 200
			}
			class := 5
			if completed && status >= 100 && status < 600 {
				class = status/100 - 1
			}
			bucket := 4
			for i, b := range [...]time.Duration{10 * time.Millisecond, 100 * time.Millisecond, time.Second, 5 * time.Second} {
				if elapsed <= b {
					bucket = i
					break
				}
			}
			m.mu.Lock()
			m.http[index].Inflight--
			increment(&m.http[index].Requests)
			increment(&m.http[index].StatusClasses[class])
			increment(&m.http[index].DurationBuckets[bucket])
			m.mu.Unlock()
		}()
		next.ServeHTTP(writer, r)
		completed = true
	})
}
