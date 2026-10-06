package applicationcheck

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

const SchemaVersion = "tracebolt.application-checks.v1"

var ErrRunning = errors.New("application_checks_already_running")

type TLSResult struct {
	State     string     `json:"state"`
	ExpiresAt *time.Time `json:"expiresAt"`
}
type Result struct {
	Scheme     string     `json:"targetScheme"`
	ID         string     `json:"id"`
	State      string     `json:"state"`
	Reason     string     `json:"reason"`
	ObservedAt *time.Time `json:"observedAt"`
	HTTPStatus *int       `json:"httpStatus"`
	TLS        TLSResult  `json:"tls"`
}
type View struct {
	SchemaVersion   string    `json:"schemaVersion"`
	Enabled         bool      `json:"enabled"`
	Vantage         string    `json:"vantage"`
	ServerNow       time.Time `json:"serverNow"`
	IntervalSeconds int       `json:"intervalSeconds"`
	MaxAgeSeconds   int       `json:"maxAgeSeconds"`
	Items           []Result  `json:"items"`
}
type Monitor struct {
	config  Config
	mu      sync.RWMutex
	items   []Result
	running atomic.Bool
	check   func(context.Context, target, string, time.Time) Result
	now     func() time.Time
	// A completion-based timer prevents catch-up bursts and overlap.
	wait func(context.Context, time.Duration) bool
}

func (m *Monitor) Matches(managerID, origin, profile string) bool {
	return m == nil || m.config.Matches(managerID, origin, profile)
}
func (*Monitor) String() string               { return "applicationcheck.Monitor{redacted}" }
func (*Monitor) GoString() string             { return "applicationcheck.Monitor{redacted}" }
func (*Monitor) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

// New and Status are inert. Only the manager lifecycle calls Run.
func New(c Config) *Monitor {
	m := &Monitor{config: c, items: []Result{}, check: newProbe().check, now: time.Now, wait: wait}
	for _, t := range c.targets {
		scheme, tlsState := "https", "unknown"
		if len(t.URL) >= 7 && t.URL[:7] == "http://" {
			scheme, tlsState = "http", "not_applicable"
		}
		m.items = append(m.items, Result{ID: t.ID, Scheme: scheme, State: "unknown", Reason: "not_checked", TLS: TLSResult{State: tlsState}})
	}
	return m
}
func wait(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func (m *Monitor) Run(ctx context.Context) error {
	if m == nil || !m.config.enabled {
		return nil
	}
	if !m.running.CompareAndSwap(false, true) {
		return ErrRunning
	}
	defer m.running.Store(false)
	for {
		for i, t := range m.config.targets {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			start := m.now().UTC()
			r := m.check(ctx, t, m.config.profile, start)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Record the start of the bounded observation, never refresh on API reads.
			r.ID = t.ID
			r.ObservedAt = &start
			m.mu.Lock()
			m.items[i] = clone(r)
			m.mu.Unlock()
		}
		if !m.wait(ctx, m.config.interval) {
			return ctx.Err()
		}
	}
}
func clone(r Result) Result {
	if r.ObservedAt != nil {
		v := *r.ObservedAt
		r.ObservedAt = &v
	}
	if r.HTTPStatus != nil {
		v := *r.HTTPStatus
		r.HTTPStatus = &v
	}
	if r.TLS.ExpiresAt != nil {
		v := *r.TLS.ExpiresAt
		r.TLS.ExpiresAt = &v
	}
	return r
}
func (m *Monitor) Status() View {
	now := time.Now().UTC()
	if m != nil {
		now = m.now().UTC()
	}
	v := View{SchemaVersion: SchemaVersion, Vantage: "management_server", ServerNow: now, Items: []Result{}}
	if m == nil || !m.config.enabled {
		return v
	}
	v.Enabled = true
	v.IntervalSeconds = int(m.config.interval / time.Second)
	maxAge := m.config.interval + time.Duration(len(m.config.targets)+1)*CheckTimeout
	v.MaxAgeSeconds = int(maxAge / time.Second)
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, item := range m.items {
		r := clone(item)
		if r.ObservedAt != nil && (r.ObservedAt.After(now) || now.Sub(*r.ObservedAt) > maxAge) {
			r.State = "unknown"
			r.Reason = "stale"
			r.HTTPStatus = nil
			r.TLS = TLSResult{State: "unknown"}
			if r.Scheme == "http" {
				r.TLS.State = "not_applicable"
			}
		}
		// Reclassify only the known expiry of the last verified leaf. This
		// neither refreshes HTTP evidence nor proves a new TLS handshake.
		if r.Scheme == "https" && r.TLS.ExpiresAt != nil {
			switch {
			case !r.TLS.ExpiresAt.After(now):
				r.TLS.State = "expired"
			case !r.TLS.ExpiresAt.After(now.Add(30 * 24 * time.Hour)):
				r.TLS.State = "expiring"
			default:
				r.TLS.State = "valid"
			}
		}
		v.Items = append(v.Items, r)
	}
	return v
}
