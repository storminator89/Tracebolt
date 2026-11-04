package applicationcheck

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

const IncidentWriteTimeout = 2 * time.Second

func newIncidentSource(c Config, now func() time.Time) (IncidentSource, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return IncidentSource{}, err
	}
	token := "appsource_" + hex.EncodeToString(nonce)
	mode := "managed"
	if c.external {
		mode = "external"
	}
	raw, err := json.Marshal(struct {
		Schema, Generation, Manager, Origin, Profile string
		External, Enabled                            bool
		Interval                                     int64
		Targets                                      []target
	}{c.schema, c.incidentGeneration, c.managerID, c.origin, c.profile, c.external, c.enabled, int64(c.interval), c.targets})
	if err != nil {
		return IncidentSource{}, err
	}
	sum := sha256.Sum256(raw)
	clear(raw)
	src := IncidentSource{Key: hex.EncodeToString(sum[:]), Token: token, Mode: mode, Enabled: c.enabled, Targets: []IncidentTarget{}, Now: now}
	if c.enabled {
		src.IntervalSeconds = int(c.interval / time.Second)
		src.MaxAgeSeconds = int((c.interval + time.Duration(len(c.targets)+1)*CheckTimeout) / time.Second)
		for _, t := range c.targets {
			it := IncidentTarget{ID: t.ID, Kind: historyKind(t)}
			if it.Kind == kindHTTP {
				s := "https"
				if len(t.URL) >= 7 && t.URL[:7] == "http://" {
					s = "http"
				}
				it.Scheme = &s
			}
			src.Targets = append(src.Targets, it)
		}
	}
	return src, nil
}

// WithIncidentSource holds only the settings generation lease. The caller may
// perform bounded local persistence, but never a probe/provider request.
func (s *Settings) WithIncidentSource(consume func(IncidentSource)) bool {
	if s == nil || s.incidentSink == nil || !s.operation.TryLock() {
		return false
	}
	defer s.operation.Unlock()
	s.mu.RLock()
	m, blocked := s.monitor, s.blocked
	s.mu.RUnlock()
	if blocked || m == nil {
		return false
	}
	source := m.incidentSource
	source.Targets = cloneIncidentTargets(source.Targets)
	consume(source)
	return true
}
func (m *Monitor) WithIncidentSource(consume func(IncidentSource)) bool {
	if m == nil {
		return false
	}
	source := m.incidentSource
	source.Targets = cloneIncidentTargets(source.Targets)
	consume(source)
	return true
}
func (m *Monitor) observeIncidentSource() {
	if m.incidentSink == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), IncidentWriteTimeout)
	defer cancel()
	_ = m.incidentSink.ObserveApplicationSource(ctx, m.incidentSource)
}
func (m *Monitor) observeIncidentResult(ctx context.Context, r Result, start, completed time.Time) {
	if m.incidentSink == nil || ctx.Err() != nil {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, IncidentWriteTimeout)
	defer cancel()
	_ = m.incidentSink.ObserveApplicationResult(bounded, m.incidentSource, IncidentObservation{TargetID: r.ID, Kind: historyKind(target{Kind: r.Kind}), Scheme: r.Scheme, State: r.State, Reason: r.Reason, ObservedAt: start, CompletedAt: completed, HTTPStatus: r.HTTPStatus})
}

func cloneIncidentTargets(rows []IncidentTarget) []IncidentTarget {
	out := make([]IncidentTarget, 0, len(rows))
	for _, r := range rows {
		if r.Scheme != nil {
			s := *r.Scheme
			r.Scheme = &s
		}
		out = append(out, r)
	}
	return out
}
