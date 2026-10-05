// Package health evaluates a small set of manager-side checks from existing
// authenticated observations. It neither collects nor repairs endpoint state.
package health

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"localrmm/internal/model"
)

const (
	Interval      = 30 * time.Second
	MaxAge        = 2 * time.Minute
	MaxServices   = 8
	MaxIncidents  = 100
	MaxStateBytes = 128 << 10
	Retention     = 30 * 24 * time.Hour
)

var ErrInvalid = errors.New("health_invalid")
var servicePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@:-]{0,118}\.service$`)

type ServiceSample struct {
	State      string
	ObservedAt time.Time
}
type Input struct {
	DeviceID   string
	Authorized bool
	ReceivedAt time.Time
	Disk       model.Metric
	Services   map[string]ServiceSample
}
type Check struct {
	Key        string     `json:"key"`
	Kind       string     `json:"kind"`
	Target     string     `json:"target"`
	State      string     `json:"state"`
	ObservedAt *time.Time `json:"observedAt"`
	Value      *float64   `json:"value"`
	BadSince   *time.Time `json:"badSince,omitempty"`
	GoodSince  *time.Time `json:"goodSince,omitempty"`
}
type Incident struct {
	ID             string     `json:"id"`
	Key            string     `json:"key"`
	Kind           string     `json:"kind"`
	Target         string     `json:"target"`
	OpenedAt       time.Time  `json:"openedAt"`
	LastObservedAt time.Time  `json:"lastObservedAt"`
	ResolvedAt     *time.Time `json:"resolvedAt"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt"`
	ClosedReason   string     `json:"closedReason,omitempty"`
}
type State struct {
	Version           int        `json:"version"`
	MonitoredServices []string   `json:"monitoredServices"`
	MaintenanceUntil  *time.Time `json:"maintenanceUntil"`
	EvaluatedAt       *time.Time `json:"evaluatedAt"`
	Checks            []Check    `json:"checks"`
	Incidents         []Incident `json:"incidents"`
	NextID            uint64     `json:"nextId"`
}
type View struct {
	SchemaVersion     string     `json:"schemaVersion"`
	DeviceID          string     `json:"deviceId"`
	ServerNow         time.Time  `json:"serverNow"`
	Status            string     `json:"status"`
	EvaluatedAt       *time.Time `json:"evaluatedAt"`
	MaintenanceUntil  *time.Time `json:"maintenanceUntil"`
	MonitoredServices []string   `json:"monitoredServices"`
	Checks            []Check    `json:"checks"`
	Incidents         []Incident `json:"incidents"`
}

func New() State {
	return State{Version: 1, MonitoredServices: []string{}, Checks: baseChecks(nil), Incidents: []Incident{}}
}
func baseChecks(services []string) []Check {
	out := []Check{{Key: "offline:contact", Kind: "offline", Target: "agent", State: "unknown"}, {Key: "filesystem:root", Kind: "filesystem", Target: "/", State: "unknown"}}
	for _, s := range services {
		out = append(out, Check{Key: "service:" + s, Kind: "service", Target: s, State: "unknown"})
	}
	return out
}
func Services(in []string) ([]string, error) {
	if in == nil || len(in) > MaxServices {
		return nil, ErrInvalid
	}
	out := append([]string{}, in...)
	sort.Strings(out)
	for i, s := range out {
		if !servicePattern.MatchString(s) || len(s) > 127 || i > 0 && out[i-1] == s {
			return nil, ErrInvalid
		}
	}
	return out, nil
}
func (s *State) SetServices(in []string, now time.Time) error {
	if s.EvaluatedAt != nil && now.Before(*s.EvaluatedAt) {
		return ErrInvalid
	}
	services, e := Services(in)
	if e != nil {
		return e
	}
	desired := baseChecks(services)
	previous := map[string]Check{}
	for _, c := range s.Checks {
		previous[c.Key] = c
	}
	keep := map[string]bool{}
	for i, c := range desired {
		keep[c.Key] = true
		if old, ok := previous[c.Key]; ok {
			desired[i] = old
		}
	}
	for i := range s.Incidents {
		x := &s.Incidents[i]
		if x.ResolvedAt == nil && !keep[x.Key] {
			x.ResolvedAt = stamp(now)
			x.ClosedReason = "monitoring_stopped"
		}
	}
	s.MonitoredServices = services
	s.Checks = desired
	return nil
}
func (s *State) Maintain(minutes int, now time.Time) error {
	if s.EvaluatedAt != nil && now.Before(*s.EvaluatedAt) {
		return ErrInvalid
	}
	if minutes != 0 && minutes != 15 && minutes != 60 && minutes != 240 {
		return ErrInvalid
	}
	s.MaintenanceUntil = nil
	if minutes > 0 {
		s.MaintenanceUntil = stamp(now.Add(time.Duration(minutes) * time.Minute))
	}
	for i := range s.Checks {
		s.Checks[i].BadSince = nil
		s.Checks[i].GoodSince = nil
	}
	return nil
}
func (s *State) Acknowledge(id string, now time.Time) error {
	for i := range s.Incidents {
		x := &s.Incidents[i]
		if x.ID == id {
			if now.Before(x.OpenedAt) {
				return ErrInvalid
			}
			if x.AcknowledgedAt == nil {
				x.AcknowledgedAt = stamp(now)
			}
			return nil
		}
	}
	return ErrInvalid
}
func stamp(t time.Time) *time.Time { t = t.UTC(); return &t }
func Fresh(at, now time.Time) bool { return !at.IsZero() && !at.After(now) && now.Sub(at) <= MaxAge }

// Evaluate requires consecutive, advancing samples for metric/service thresholds.
// Re-reading one snapshot never earns minimum duration. Missing/old samples reset
// pending transitions but never resolve an existing incident. Manager gaps reset
// timers too; history does not invent events while the manager was stopped.
func (s *State) Evaluate(in Input, now time.Time) {
	_ = s.EvaluateTransitions(in, now)
}

// EvaluateTransitions returns only transitions created by this evaluation, before
// bounded UI history pruning. Persistence may atomically retain their delivery
// intent without reconstructing transitions from potentially pruned history.
func (s *State) EvaluateTransitions(in Input, now time.Time) []Incident {
	transitions := []Incident{}
	now = now.UTC()
	if s.EvaluatedAt != nil && now.Before(*s.EvaluatedAt) {
		for i := range s.Checks {
			s.Checks[i].State = "unknown"
			s.Checks[i].BadSince = nil
			s.Checks[i].GoodSince = nil
		}
		return nil
	}
	gap := s.EvaluatedAt == nil || now.Before(*s.EvaluatedAt) || now.Sub(*s.EvaluatedAt) > 3*Interval
	maintenance := s.MaintenanceUntil != nil && now.Before(*s.MaintenanceUntil)
	for i := range s.Checks {
		c := &s.Checks[i]
		prior := c.ObservedAt
		if gap {
			c.BadSince = nil
			c.GoodSince = nil
		}
		if maintenance {
			c.BadSince = nil
		}
		c.Value = nil
		c.ObservedAt = nil
		condition := "unknown"
		at := time.Time{}
		duration := 2 * time.Minute
		if in.Authorized {
			switch c.Kind {
			case "offline":
				duration = time.Minute
				if !in.ReceivedAt.IsZero() && !in.ReceivedAt.After(now) {
					at = now
					c.ObservedAt = stamp(in.ReceivedAt)
					condition = "good"
					if now.Sub(in.ReceivedAt) > MaxAge {
						condition = "bad"
					}
				}
			case "filesystem":
				m := in.Disk
				if Fresh(in.ReceivedAt, now) && Fresh(m.CollectedAt, now) && m.Quality == "healthy" && m.Unit == "%" && m.Value != nil && !math.IsNaN(*m.Value) && !math.IsInf(*m.Value, 0) && *m.Value >= 0 && *m.Value <= 100 {
					v := *m.Value
					c.Value = &v
					at = m.CollectedAt
					c.ObservedAt = stamp(at)
					condition = "hold"
					if v >= 90 {
						condition = "bad"
					} else if v <= 85 {
						condition = "good"
					} else if s.open(c.Key) == nil {
						condition = "good"
					}
				}
			case "service":
				v, ok := in.Services[c.Target]
				if ok && Fresh(in.ReceivedAt, now) && Fresh(v.ObservedAt, now) {
					at = v.ObservedAt
					c.ObservedAt = stamp(at)
					switch v.State {
					case "active":
						condition = "good"
					case "inactive", "failed":
						condition = "bad"
					}
				}
			}
		}
		open := s.open(c.Key)
		if condition == "unknown" {
			c.State = "unknown"
			c.BadSince = nil
			c.GoodSince = nil
			continue
		}
		c.State = "ok"
		if open != nil {
			c.State = "open"
		} else if condition == "bad" {
			c.State = "pending"
			if maintenance {
				c.State = "unknown"
			}
		}
		if c.Kind != "offline" && prior != nil && !at.After(*prior) {
			continue
		}
		if condition == "hold" {
			c.BadSince = nil
			c.GoodSince = nil
			continue
		}
		if condition == "bad" {
			c.GoodSince = nil
			if open != nil {
				open.LastObservedAt = at
				continue
			}
			if maintenance {
				c.State = "unknown"
				continue
			}
			if c.BadSince == nil {
				c.BadSince = stamp(now)
			}
			c.State = "pending"
			if at.Sub(*c.BadSince) >= duration {
				s.NextID++
				s.Incidents = append([]Incident{{ID: fmt.Sprintf("health_%016x", s.NextID), Key: c.Key, Kind: c.Kind, Target: c.Target, OpenedAt: now, LastObservedAt: at}}, s.Incidents...)
				transitions = append(transitions, s.Incidents[0])
				c.BadSince = nil
				c.State = "open"
			}
		} else {
			c.BadSince = nil
			if open == nil {
				c.State = "ok"
				c.GoodSince = nil
				continue
			}
			if c.GoodSince == nil {
				c.GoodSince = stamp(now)
			}
			if at.Sub(*c.GoodSince) >= time.Minute {
				open.ResolvedAt = stamp(now)
				open.ClosedReason = "recovered"
				open.LastObservedAt = at
				transitions = append(transitions, *open)
				c.GoodSince = nil
				c.State = "ok"
			}
		}
	}
	s.EvaluatedAt = stamp(now)
	s.prune(now)
	return transitions
}
func (s *State) open(key string) *Incident {
	for i := range s.Incidents {
		if s.Incidents[i].Key == key && s.Incidents[i].ResolvedAt == nil {
			return &s.Incidents[i]
		}
	}
	return nil
}
func (s *State) prune(now time.Time) {
	out := make([]Incident, 0, len(s.Incidents))
	for _, v := range s.Incidents {
		if v.ResolvedAt == nil || now.Sub(*v.ResolvedAt) <= Retention {
			out = append(out, v)
		}
	}
	for len(out) > MaxIncidents {
		removed := false
		for i := len(out) - 1; i >= 0; i-- {
			if out[i].ResolvedAt != nil {
				out = append(out[:i], out[i+1:]...)
				removed = true
				break
			}
		}
		if !removed {
			break
		} // Validation rejects excess open records; never spin on corruption.
	}
	s.Incidents = out
}
func (s State) View(id string, now time.Time) View {
	checks := append([]Check{}, s.Checks...)
	status := "clear"
	for i := range checks {
		checks[i].BadSince = nil
		checks[i].GoodSince = nil
		sourceStale := checks[i].ObservedAt != nil && (checks[i].Kind != "offline" || checks[i].State == "ok") && !Fresh(*checks[i].ObservedAt, now)
		if s.EvaluatedAt == nil || !Fresh(*s.EvaluatedAt, now) || sourceStale {
			checks[i].State = "unknown"
			checks[i].Value = nil
		}
		if checks[i].State == "unknown" {
			status = "unknown"
		}
	}
	for _, c := range checks {
		if c.State == "open" || c.State == "pending" {
			status = "attention"
		}
	}
	if s.MaintenanceUntil != nil && now.Before(*s.MaintenanceUntil) {
		status = "maintenance"
	}
	maintenanceUntil := s.MaintenanceUntil
	if maintenanceUntil != nil && !now.Before(*maintenanceUntil) {
		maintenanceUntil = nil
	}
	return View{"tracebolt.health-view.v1", id, now.UTC(), status, s.EvaluatedAt, maintenanceUntil, s.MonitoredServices, checks, s.Incidents}
}
func (s State) Validate() error {
	if s.Version != 1 || s.NextID > 1<<53-1 || len(s.Incidents) > MaxIncidents {
		return ErrInvalid
	}
	services, e := Services(s.MonitoredServices)
	if e != nil {
		return e
	}
	desired := baseChecks(services)
	if len(desired) != len(s.Checks) {
		return ErrInvalid
	}
	known := map[string]bool{}
	for i, c := range s.Checks {
		known[c.Key] = true
		d := desired[i]
		if c.Key != d.Key || c.Kind != d.Kind || c.Target != d.Target {
			return ErrInvalid
		}
		switch c.State {
		case "ok", "pending", "open", "unknown":
		default:
			return ErrInvalid
		}
	}
	ids, open := map[string]bool{}, map[string]bool{}
	for _, x := range s.Incidents {
		n, err := strconv.ParseUint(strings.TrimPrefix(x.ID, "health_"), 16, 64)
		if err != nil || x.ID != fmt.Sprintf("health_%016x", n) || n == 0 || n > s.NextID || ids[x.ID] || x.OpenedAt.IsZero() || x.LastObservedAt.IsZero() || !validTarget(x.Key, x.Kind, x.Target) {
			return ErrInvalid
		}
		ids[x.ID] = true
		if x.ResolvedAt == nil {
			if open[x.Key] || !known[x.Key] || x.ClosedReason != "" {
				return ErrInvalid
			}
			open[x.Key] = true
		} else if x.ClosedReason != "recovered" && x.ClosedReason != "monitoring_stopped" {
			return ErrInvalid
		}
	}
	return nil
}

func validTarget(key, kind, target string) bool {
	switch kind {
	case "offline":
		return key == "offline:contact" && target == "agent"
	case "filesystem":
		return key == "filesystem:root" && target == "/"
	case "service":
		return servicePattern.MatchString(target) && len(target) <= 127 && key == "service:"+target
	}
	return false
}
