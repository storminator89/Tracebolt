package applicationcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func historyResult(state string) Result {
	code, reason := 204, "http_2xx"
	if state == "http_error" {
		code, reason = 503, "http_status"
	}
	return Result{State: state, Reason: reason, HTTPStatus: &code, Scheme: "https", TLS: TLSResult{State: "valid"}}
}
func addHistory(m *Monitor, i int, result Result, start time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recordHistory(i, m.config.targets[i], result, start, start.Add(time.Second))
}
func TestHistoryReadsAreInertDetachedAndDoNotChangeStatus(t *testing.T) {
	m := New(monitorConfig())
	now := time.Date(2026, 11, 4, 1, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	m.check = func(context.Context, target, string, time.Time) Result {
		t.Fatal("history triggered probe")
		return Result{}
	}
	before, _ := json.Marshal(m.Status())
	addHistory(m, 0, historyResult("ok"), now.Add(-time.Minute))
	for range 3 {
		v := m.History()
		if !v.Enabled || !v.ClockReliable || len(v.Items) != 2 || len(v.Items[0].Samples) != 1 {
			t.Fatalf("bad history: %+v", v)
		}
		*v.Items[0].Samples[0].HTTPStatus = 500
		v.Items[0].Samples[0].State = "modified"
	}
	got := m.History().Items[0].Samples[0]
	if *got.HTTPStatus != 204 || got.State != "ok" {
		t.Fatal("history aliases caller memory")
	}
	after, _ := json.Marshal(m.Status())
	if string(before) != string(after) {
		t.Fatal("history changed live status")
	}
}
func TestHistoryBoundsRetentionAndOmittedCoverage(t *testing.T) {
	m := New(monitorConfig())
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	now := start
	m.now = func() time.Time { return now }
	for i := range 40 {
		now = start.Add(time.Duration(i) * time.Minute)
		addHistory(m, 0, historyResult("ok"), now.Add(-time.Second))
	}
	v := m.History()
	r := v.Items[0]
	if len(r.Samples) != HistoryLimit || !r.EarlierOmitted || !r.Samples[0].ObservedAt.Equal(start.Add(8*time.Minute-time.Second)) {
		t.Fatalf("bad ring: %+v", r)
	}
	now = now.Add(HistoryRetention)
	v = m.History()
	if len(v.Items[0].Samples) != 0 || !v.Items[0].EarlierOmitted {
		t.Fatal("expired history retained")
	}
	if len(m.history[0].samples) != 0 {
		t.Fatal("expired raw rows retained")
	}
}
func TestHistoryGapsClockRollbackAndNoResurrection(t *testing.T) {
	m := New(monitorConfig())
	start := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	now := start
	m.now = func() time.Time { return now }
	addHistory(m, 0, historyResult("http_error"), start)
	now = start.Add(5 * time.Minute)
	addHistory(m, 0, historyResult("ok"), now.Add(-time.Second))
	v := m.History()
	if !v.Items[0].Samples[1].GapBefore {
		t.Fatal("gap became continuous recovery")
	}
	now = start
	v = m.History()
	if v.ClockReliable || len(v.Items[0].Samples) != 0 {
		t.Fatal("clock rollback exposed future history")
	}
	now = start.Add(6 * time.Minute)
	if len(m.History().Items[0].Samples) != 0 {
		t.Fatal("rollback history resurrected")
	}
	addHistory(m, 0, historyResult("ok"), now.Add(-time.Second))
	if !m.History().Items[0].Samples[0].GapBefore {
		t.Fatal("lost clock coverage not marked")
	}
}
func TestHistoryCanceledAndUnknownProducerResultsAreNotRetained(t *testing.T) {
	m := New(monitorConfig())
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	for _, r := range []Result{{State: "unknown", Reason: "cancelled"}, {State: "unknown", Reason: "not_checked"}, {State: "ok", Reason: "raw private text"}, {State: "unknown", Reason: "stale"}} {
		addHistory(m, 0, r, now.Add(-time.Minute))
	}
	if len(m.History().Items[0].Samples) != 0 {
		t.Fatal("synthetic/unknown outcome retained")
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.check = func(context.Context, target, string, time.Time) Result { cancel(); return historyResult("ok") }
	_ = m.Run(ctx)
	if len(m.History().Items[0].Samples) != 0 {
		t.Fatal("cancelled attempt published")
	}
}
func TestHistoryMaxWireBoundAndPerKindRedaction(t *testing.T) {
	c := monitorConfig()
	c.targets = nil
	for i := range 8 {
		c.targets = append(c.targets, target{ID: fmt.Sprintf("fixture-%038d", i), Kind: kindHTTP, URL: "https://private.example/path"})
	}
	m := New(c)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	for j := range HistoryLimit {
		for i := range 8 {
			addHistory(m, i, historyResult("http_error"), now.Add(time.Duration(j-HistoryLimit)*time.Minute))
		}
	}
	raw, err := json.Marshal(m.History())
	if err != nil || len(raw) > HistoryMaxBytes {
		t.Fatalf("wire bound: %d %v", len(raw), err)
	}
	for _, forbidden := range []string{"private.example", "path", "tls", "expiresAt", "allowedAddresses", "certificate"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("history leaked %s", forbidden)
		}
	}
	for _, m := range []*Monitor{nil, New(Config{})} {
		v := m.History()
		if v.Enabled || len(v.Items) != 0 || v.SchemaVersion != HistorySchema {
			t.Fatal("disabled history not empty")
		}
	}
	for _, kind := range []string{kindDNS, kindTCP} {
		r := Result{State: "ok", Reason: "dns_resolved"}
		if kind == kindTCP {
			r.Reason = "tcp_connected"
		}
		if !historyOutcome(kind, r) {
			t.Fatal("valid network outcome rejected")
		}
		r.HTTPStatus = new(int)
		if historyOutcome(kind, r) {
			t.Fatal("network HTTP leak accepted")
		}
	}
}
func TestHistoryConfigurationLeaseAndReplacement(t *testing.T) {
	m := New(monitorConfig())
	s := &Settings{monitor: m}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() { s.WithHistory(func(HistoryView) { close(entered); <-release }); close(done) }()
	<-entered
	replaced := make(chan struct{})
	go func() {
		s.operation.Lock()
		s.mu.Lock()
		s.monitor = New(monitorConfig())
		s.mu.Unlock()
		s.operation.Unlock()
		close(replaced)
	}()
	select {
	case <-replaced:
		t.Fatal("configuration crossed response lease")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-done
	<-replaced
	s.WithHistory(func(v HistoryView) {
		if len(v.Items[0].Samples) != 0 {
			t.Fatal("replacement inherited history")
		}
	})
	s.mu.Lock()
	s.blocked = true
	s.mu.Unlock()
	s.WithHistory(func(v HistoryView) {
		if v.Enabled || len(v.Items) != 0 {
			t.Fatal("blocked source history exposed")
		}
	})
}

func TestHistoryQueuedReadSamplesClockAfterAdmission(t *testing.T) {
	m := New(monitorConfig())
	start := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	now := start
	sampled := make(chan struct{}, 1)
	m.now = func() time.Time {
		select {
		case sampled <- struct{}{}:
		default:
		}
		return now
	}
	m.mu.Lock()
	entered, done := make(chan struct{}), make(chan HistoryView, 1)
	go func() { close(entered); done <- m.History() }()
	<-entered
	select {
	case <-sampled:
		m.mu.Unlock()
		t.Fatal("reader sampled before admission")
	case <-time.After(20 * time.Millisecond):
	}
	now = start.Add(time.Minute)
	m.recordHistory(0, m.config.targets[0], historyResult("ok"), now.Add(-time.Second), now)
	m.mu.Unlock()
	v := <-done
	if !v.ClockReliable || len(v.Items[0].Samples) != 1 {
		t.Fatal("queued legitimate history was cleared")
	}
}
func TestHistoryBusyLeaseDoesNotQueue(t *testing.T) {
	s := &Settings{monitor: New(monitorConfig())}
	s.operation.Lock()
	defer s.operation.Unlock()
	if s.WithHistory(func(HistoryView) { t.Fatal("busy callback executed") }) {
		t.Fatal("busy read admitted")
	}
}

func TestHistoryFrozenClockNeverRearmsClearedChronology(t *testing.T) {
	m := New(monitorConfig())
	start := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	now := start.Add(time.Second)
	m.now = func() time.Time { return now }
	addHistory(m, 0, historyResult("ok"), start)
	for range 4 {
		addHistory(m, 0, historyResult("ok"), start)
		if len(m.History().Items[0].Samples) != 0 {
			t.Fatal("frozen timestamp rearmed discarded history")
		}
	}
	now = start.Add(2 * time.Minute)
	addHistory(m, 0, historyResult("ok"), now.Add(-time.Second))
	if len(m.History().Items[0].Samples) != 1 || !m.History().Items[0].Samples[0].GapBefore {
		t.Fatal("advancing clock failed to preserve coverage gap")
	}
}

func TestHistoryRunCompletionIsStampedAfterPublicationAdmission(t *testing.T) {
	c := monitorConfig()
	c.targets = c.targets[:1]
	m := New(c)
	start := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	now := start
	sampled := make(chan struct{}, 4)
	m.now = func() time.Time { sampled <- struct{}{}; return now }
	m.recordHistory(0, c.targets[0], historyResult("ok"), start.Add(-time.Minute), start.Add(-time.Minute+time.Second))
	entered, release := make(chan struct{}), make(chan struct{})
	m.check = func(context.Context, target, string, time.Time) Result {
		close(entered)
		<-release
		return historyResult("ok")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.wait = func(context.Context, time.Duration) bool { cancel(); return false }
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	<-entered
	<-sampled
	m.mu.Lock()
	close(release)
	select {
	case <-sampled:
		m.mu.Unlock()
		t.Fatal("completion stamped before admission")
	case <-time.After(20 * time.Millisecond):
	}
	now = start.Add(time.Second)
	m.historyClock = now
	m.mu.Unlock()
	<-done
	v := m.History()
	if !v.ClockReliable || len(v.Items[0].Samples) != 2 {
		t.Fatal("legitimate concurrent publication discarded")
	}
}

func TestHistoryCancellationWhilePublicationQueuedDoesNotAppend(t *testing.T) {
	c := monitorConfig()
	c.targets = c.targets[:1]
	m := New(c)
	entered, release := make(chan struct{}), make(chan struct{})
	m.check = func(context.Context, target, string, time.Time) Result {
		close(entered)
		<-release
		return historyResult("ok")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	<-entered
	m.mu.Lock()
	close(release)
	cancel()
	m.mu.Unlock()
	<-done
	v := m.History()
	if len(v.Items[0].Samples) != 0 || m.Status().Items[0].ObservedAt != nil {
		t.Fatal("cancelled queued publication became an observation")
	}
}

func TestHistoryPublicationLeaseDoesNotBlockProbeCooldown(t *testing.T) {
	s := &Settings{monitor: New(monitorConfig())}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() { s.WithHistory(func(HistoryView) { close(entered); <-release }); close(done) }()
	<-entered
	if !s.mu.TryLock() {
		close(release)
		<-done
		t.Fatal("history response holds settings lock needed by probe completion")
	}
	s.nextAllowed = time.Now()
	s.mu.Unlock()
	close(release)
	<-done
}
