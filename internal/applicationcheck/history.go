package applicationcheck

import (
	"time"
)

const HistorySchema = "tracebolt.application-check-history.v1"
const HistoryMediaType = "application/vnd.tracebolt.application-check-history.v1+json"
const HistoryLimit = 32
const HistoryRetention = 24 * time.Hour
const HistoryMaxBytes = 128 << 10

// History contains only redacted outcomes of checks that already finished.
// It is not an availability percentage, an incident ledger or a request to probe.
type HistorySample struct {
	ObservedAt  time.Time `json:"observedAt"`
	CompletedAt time.Time `json:"completedAt"`
	State       string    `json:"state"`
	Reason      string    `json:"reason"`
	HTTPStatus  *int      `json:"httpStatus"`
	GapBefore   bool      `json:"gapBefore"`
}
type HistoryTarget struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	Scheme         string          `json:"targetScheme"`
	EarlierOmitted bool            `json:"earlierOmitted"`
	Samples        []HistorySample `json:"samples"`
}
type HistoryView struct {
	SchemaVersion    string          `json:"schemaVersion"`
	Enabled          bool            `json:"enabled"`
	Vantage          string          `json:"vantage"`
	ServerNow        time.Time       `json:"serverNow"`
	RetentionSeconds int             `json:"retentionSeconds"`
	PerTargetLimit   int             `json:"perTargetLimit"`
	ClockReliable    bool            `json:"clockReliable"`
	Items            []HistoryTarget `json:"items"`
}
type targetHistory struct {
	samples       []HistorySample
	omitted       bool
	lastCompleted time.Time
}

func historyKind(t target) string {
	if t.Kind == "" {
		return kindHTTP
	}
	return t.Kind
}

// recordHistory is called under m.mu only after a completed, uncancelled check.
func (m *Monitor) recordHistory(i int, t target, r Result, start, completed time.Time) {
	h := &m.history[i]
	if completed.After(m.historyClock) {
		m.historyClock = completed
	}
	if completed.Before(start) || completed.Before(m.historyClock) || !h.lastCompleted.IsZero() && !start.After(h.lastCompleted) {
		// A regressed/frozen clock cannot construct a chronological history.
		*h = targetHistory{omitted: true, lastCompleted: h.lastCompleted}
		return
	}
	if !historyOutcome(historyKind(t), r) {
		return
	}
	sample := HistorySample{ObservedAt: start, CompletedAt: completed, State: r.State, Reason: r.Reason}
	if historyKind(t) == kindHTTP && r.HTTPStatus != nil {
		status := *r.HTTPStatus
		sample.HTTPStatus = &status
	}
	if len(h.samples) > 0 {
		maxAge := m.config.interval + time.Duration(len(m.config.targets)+1)*CheckTimeout
		sample.GapBefore = start.Sub(h.samples[len(h.samples)-1].CompletedAt) > maxAge
	} else {
		sample.GapBefore = h.omitted
	}
	kept := h.samples[:0]
	for _, old := range h.samples {
		if completed.Sub(old.ObservedAt) <= HistoryRetention {
			kept = append(kept, old)
		} else {
			h.omitted = true
		}
	}
	clear(h.samples[len(kept):])
	h.samples = append(kept, sample)
	h.lastCompleted = completed
	if len(h.samples) > HistoryLimit {
		h.omitted = true
		copy(h.samples, h.samples[len(h.samples)-HistoryLimit:])
		clear(h.samples[HistoryLimit:])
		h.samples = h.samples[:HistoryLimit]
	}
}

// Never turn future producer fields into retained text. The history allows only
// the existing fixed per-kind result vocabulary, and no certificates or content.
func historyOutcome(kind string, r Result) bool {
	if r.State == "unknown" {
		return r.HTTPStatus == nil && (r.Reason == "invalid_configuration" || r.Reason == "destination_blocked")
	}
	if kind == kindHTTP {
		if r.State == "tls_error" {
			return r.HTTPStatus == nil && (r.Reason == "tls_verification_failed" || r.Reason == "tls_handshake_failed")
		}
		if r.State == "network_error" {
			return r.HTTPStatus == nil && (r.Reason == "dns_failed" || r.Reason == "timeout" || r.Reason == "request_failed")
		}
		if r.HTTPStatus == nil || *r.HTTPStatus < 100 || *r.HTTPStatus > 999 {
			return false
		}
		s := *r.HTTPStatus
		return s >= 200 && s < 300 && r.State == "ok" && r.Reason == "http_2xx" ||
			r.State == "http_error" && ((s >= 300 && s < 400 && r.Reason == "redirect_blocked") || ((s < 200 || s >= 400) && r.Reason == "http_status"))
	}
	if r.HTTPStatus != nil {
		return false
	}
	if r.State == "ok" {
		return kind == kindDNS && r.Reason == "dns_resolved" || kind == kindTCP && r.Reason == "tcp_connected"
	}
	return r.State == "network_error" && (r.Reason == "dns_failed" || r.Reason == "timeout" || kind == kindTCP && r.Reason == "tcp_failed")
}

// History is inert, bounded and detached from mutable monitor slices. Stale
// outcomes remain explicitly historical; they never replace the live Status.
func (m *Monitor) History() HistoryView {
	now := time.Now().UTC()
	if m != nil {
		// Sample the clock only after admission. A queued reader must not
		// mistake a concurrently published observation for clock rollback.
		m.mu.Lock()
		defer m.mu.Unlock()
		now = m.now().UTC()
	}
	v := HistoryView{SchemaVersion: HistorySchema, Vantage: "management_server", ServerNow: now,
		RetentionSeconds: int(HistoryRetention / time.Second), PerTargetLimit: HistoryLimit,
		ClockReliable: true, Items: []HistoryTarget{}}
	if m == nil || !m.config.enabled {
		return v
	}
	v.Enabled = true
	if now.Before(m.historyClock) {
		v.ClockReliable = false
	} else {
		m.historyClock = now
	}
	for i, t := range m.config.targets {
		h := &m.history[i]
		row := HistoryTarget{ID: t.ID, Kind: historyKind(t), Samples: []HistorySample{}, EarlierOmitted: h.omitted}
		if row.Kind == kindHTTP {
			row.Scheme = "https"
			if len(t.URL) >= 7 && t.URL[:7] == "http://" {
				row.Scheme = "http"
			}
		}
		kept := h.samples[:0]
		for _, sample := range h.samples {
			if sample.CompletedAt.After(now) {
				v.ClockReliable = false
				continue
			}
			if now.Sub(sample.ObservedAt) > HistoryRetention {
				h.omitted, row.EarlierOmitted = true, true
				continue
			}
			kept = append(kept, sample)
			if sample.HTTPStatus != nil {
				status := *sample.HTTPStatus
				sample.HTTPStatus = &status
			}
			row.Samples = append(row.Samples, sample)
		}
		clear(h.samples[len(kept):])
		h.samples = kept
		v.Items = append(v.Items, row)
	}
	if !v.ClockReliable {
		for i := range m.history {
			m.history[i] = targetHistory{omitted: true, lastCompleted: m.history[i].lastCompleted}
			v.Items[i].Samples = []HistorySample{}
			v.Items[i].EarlierOmitted = true
		}
	}
	return v
}

// WithHistory leases the current configuration through a bounded operator response.
// Replacement/disable cannot cross the publication of the old monitor's history.
// The callback must not probe targets or perform provider I/O.
func (s *Settings) WithHistory(consume func(HistoryView)) bool {
	if s == nil {
		consume((*Monitor)(nil).History())
		return true
	}
	if !s.operation.TryLock() {
		return false
	}
	defer s.operation.Unlock()
	s.mu.RLock()
	monitor := s.monitor
	if s.blocked {
		monitor = nil
	}
	s.mu.RUnlock()
	consume(monitor.History())
	return true
}
