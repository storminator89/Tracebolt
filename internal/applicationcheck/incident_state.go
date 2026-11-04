package applicationcheck

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type incidentRecord struct {
	ApplicationIncident
	SourceKey string
}
type incidentProgress struct {
	Check IncidentCheck
	First time.Time
	Last  time.Time
}
type IncidentState struct {
	Version                int
	Revision               uint64
	NextID                 uint64
	SourceKey, SourceToken string
	PolicyKey              string
	Floor                  time.Time
	Policy                 IncidentPolicyView
	Records                []incidentRecord
	Progress               map[string]incidentProgress
	EarlierOmitted         bool
	LastCommand            *IncidentCommand
}

func NewIncidentState() IncidentState {
	return IncidentState{Version: 1, NextID: 1, Policy: IncidentPolicyView{TargetIDs: []string{}, ConsecutiveFailures: 2}, Records: []incidentRecord{}, Progress: map[string]incidentProgress{}}
}

var incidentRequestPattern = regexp.MustCompile(`^apprequest_[0-9a-f]{32}$`)

var incidentKeyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var incidentTokenPattern = regexp.MustCompile(`^appsource_[0-9a-f]{32}$`)
var incidentIDPattern = regexp.MustCompile(`^appincident_[0-9a-f]{16}$`)

func incidentTime(t time.Time) bool {
	_, z := t.Zone()
	return !t.IsZero() && z == 0 && t.Year() >= 1 && t.Year() <= 9999
}
func incidentToken(t string) bool {
	return incidentTokenPattern.MatchString(t) && t != "appsource_"+strings.Repeat("0", 32)
}
func incidentKind(k string, scheme *string) bool {
	return k == kindHTTP && scheme != nil && (*scheme == "http" || *scheme == "https") || (k == kindDNS || k == kindTCP) && scheme == nil
}
func validateIncidentSource(s IncidentSource, now time.Time) error {
	if !incidentTime(now) || !incidentKeyPattern.MatchString(s.Key) || !incidentToken(s.Token) || (s.Mode != "managed" && s.Mode != "external") {
		return ErrIncidentInvalid
	}
	if !s.Enabled {
		if len(s.Targets) != 0 || s.IntervalSeconds != 0 || s.MaxAgeSeconds != 0 {
			return ErrIncidentInvalid
		}
		return nil
	}
	if len(s.Targets) < 1 || len(s.Targets) > 8 || s.IntervalSeconds < 60 || s.IntervalSeconds > 3600 || s.MaxAgeSeconds != s.IntervalSeconds+(len(s.Targets)+1)*5 {
		return ErrIncidentInvalid
	}
	seen := map[string]bool{}
	for _, t := range s.Targets {
		if !validID(t.ID) || seen[t.ID] || !incidentKind(t.Kind, t.Scheme) {
			return ErrIncidentInvalid
		}
		seen[t.ID] = true
	}
	return nil
}
func incidentFailure(kind string, scheme *string, reason string, status *int) bool {
	if kind == kindHTTP && scheme != nil && *scheme == "http" && strings.HasPrefix(reason, "tls_") {
		return false
	}
	for _, state := range []string{"network_error", "tls_error", "http_error"} {
		if historyOutcome(kind, Result{State: state, Reason: reason, HTTPStatus: status}) {
			return true
		}
	}
	return false
}
func (s IncidentState) Validate() error {
	bad := func() error { return ErrIncidentInvalid }
	b, e := json.Marshal(s)
	if e != nil || len(b) >= IncidentMaxBytes || s.Version != 1 || s.NextID == 0 || len(s.Records) > 128 || len(s.Progress) > 8 || s.Progress == nil || s.Records == nil || s.Policy.TargetIDs == nil {
		return bad()
	}
	if s.SourceKey == "" {
		if s.SourceToken != "" || !s.Floor.IsZero() || s.Revision != 0 || len(s.Records) != 0 || s.Policy.Enabled {
			return bad()
		}
	} else if !incidentKeyPattern.MatchString(s.SourceKey) || !incidentToken(s.SourceToken) || !incidentTime(s.Floor) {
		return bad()
	}
	if s.Policy.SourceMatches != s.Policy.Enabled {
		return bad()
	}
	if s.Policy.ConsecutiveFailures != 2 && s.Policy.ConsecutiveFailures != 3 {
		return bad()
	}
	selected := map[string]bool{}
	for _, id := range s.Policy.TargetIDs {
		if !validID(id) || selected[id] {
			return bad()
		}
		selected[id] = true
	}
	if s.Policy.Enabled {
		if len(selected) < 1 || len(selected) > 8 || s.PolicyKey != s.SourceKey || !incidentKeyPattern.MatchString(s.PolicyKey) || s.Policy.EnabledAt == nil || !incidentTime(*s.Policy.EnabledAt) || s.Policy.EnabledAt.After(s.Floor) {
			return bad()
		}
	} else if len(selected) != 0 || s.Policy.EnabledAt != nil || s.PolicyKey != "" || s.Policy.ConsecutiveFailures != 2 {
		return bad()
	}
	if s.LastCommand == nil {
		if s.Revision != 0 {
			return bad()
		}
	} else {
		c := s.LastCommand
		if !incidentRequestPattern.MatchString(c.RequestID) || c.RequestID == "apprequest_"+strings.Repeat("0", 32) || !incidentToken(c.SourceToken) || c.ExpectedRevision == ^uint64(0) || c.ExpectedRevision+1 != s.Revision {
			return bad()
		}
		switch c.Operation {
		case "enable":
			if c.IncidentID != nil || !c.RetentionAcknowledged || len(c.TargetIDs) < 1 || len(c.TargetIDs) > 8 || (c.ConsecutiveFailures != 2 && c.ConsecutiveFailures != 3) {
				return bad()
			}
			m := map[string]bool{}
			for _, id := range c.TargetIDs {
				if !validID(id) || m[id] {
					return bad()
				}
				m[id] = true
			}
		case "disable", "acknowledge":
			if len(c.TargetIDs) != 0 || c.ConsecutiveFailures != 0 || c.RetentionAcknowledged || (c.Operation == "disable" && c.IncidentID != nil) || (c.Operation == "acknowledge" && (c.IncidentID == nil || !incidentIDPattern.MatchString(*c.IncidentID))) {
				return bad()
			}
		default:
			return bad()
		}
	}
	ids, opens := map[string]bool{}, map[string]bool{}
	lastID := uint64(0)
	for _, r := range s.Records {
		if !incidentIDPattern.MatchString(r.ID) || ids[r.ID] || !incidentKeyPattern.MatchString(r.SourceKey) || !validID(r.TargetID) || !incidentKind(r.Kind, r.Scheme) || r.SourceCurrent {
			return bad()
		}
		ids[r.ID] = true
		n, _ := strconv.ParseUint(strings.TrimPrefix(r.ID, "appincident_"), 16, 64)
		if n == 0 || n >= s.NextID || n <= lastID {
			return bad()
		}
		lastID = n
		o := r.Opening
		if !incidentTime(o.FirstObservedAt) || !incidentTime(o.ObservedAt) || !incidentTime(o.CompletedAt) || o.FirstObservedAt.After(o.ObservedAt) || !o.FirstObservedAt.Before(o.ObservedAt) || o.ObservedAt.After(o.CompletedAt) || (o.Samples != 2 && o.Samples != 3) || !incidentFailure(r.Kind, r.Scheme, o.Reason, o.HTTPStatus) || !incidentTime(r.LastObservedAt) || !incidentTime(r.LastCompletedAt) || r.LastObservedAt.Before(o.ObservedAt) || r.LastCompletedAt.Before(o.CompletedAt) || r.LastObservedAt.After(r.LastCompletedAt) || r.LastCompletedAt.After(s.Floor) {
			return bad()
		}
		if r.ClosedAt != nil && (!incidentTime(*r.ClosedAt) || r.ClosedAt.Before(r.LastCompletedAt) || r.ClosedAt.After(s.Floor)) {
			return bad()
		}
		if r.AcknowledgedAt != nil && (!incidentTime(*r.AcknowledgedAt) || r.AcknowledgedAt.Before(o.CompletedAt) || r.AcknowledgedAt.After(s.Floor)) {
			return bad()
		}
		switch r.State {
		case "open":
			key := r.SourceKey + "/" + r.TargetID
			if opens[key] || r.ClosedAt != nil || r.Recovery != nil || !s.Policy.Enabled || r.SourceKey != s.PolicyKey || !selected[r.TargetID] {
				return bad()
			}
			opens[key] = true
		case "monitoring_stopped":
			if r.Recovery != nil {
				return bad()
			}
		case "recovered":
			q := r.Recovery
			if q == nil || r.ClosedAt == nil || q.Samples != 2 || !incidentTime(q.FirstObservedAt) || !incidentTime(q.ObservedAt) || !incidentTime(q.CompletedAt) || !q.FirstObservedAt.After(o.CompletedAt) || !q.ObservedAt.After(q.FirstObservedAt) || q.ObservedAt.After(q.CompletedAt) || !q.CompletedAt.Equal(*r.ClosedAt) || !q.ObservedAt.Equal(r.LastObservedAt) || !q.CompletedAt.Equal(r.LastCompletedAt) {
				return bad()
			}
		default:
			return bad()
		}
	}
	for id, p := range s.Progress {
		c := p.Check
		if !selected[id] || (!p.Last.IsZero() && (!incidentTime(p.Last) || p.Last.After(s.Floor))) {
			return bad()
		}
		if c.ID == "" {
			if !reflect.DeepEqual(c, IncidentCheck{}) || !p.First.IsZero() {
				return bad()
			}
			continue
		}
		if c.ID != id || !incidentKind(c.Kind, c.Scheme) || c.ObservedAt == nil || c.CompletedAt == nil || c.Reason == nil || !incidentTime(*c.ObservedAt) || !incidentTime(*c.CompletedAt) || c.ObservedAt.After(*c.CompletedAt) || !c.CompletedAt.Equal(p.Last) || c.ObservedAt.Before(*s.Policy.EnabledAt) || c.FailureCount < 0 || c.FailureCount > 3 || c.SuccessCount < 0 || c.SuccessCount > 2 || c.FailureCount*c.SuccessCount != 0 {
			return bad()
		}
		if c.FailureCount+c.SuccessCount > 0 {
			if !incidentTime(p.First) || p.First.After(*c.ObservedAt) || p.First.Before(*s.Policy.EnabledAt) {
				return bad()
			}
		} else if !p.First.IsZero() {
			return bad()
		}
		open := opens[s.PolicyKey+"/"+id]
		switch c.Condition {
		case "pending":
			if c.FailureCount <= 0 || c.FailureCount >= s.Policy.ConsecutiveFailures || c.SuccessCount != 0 || open {
				return bad()
			}
		case "incident":
			if !open || c.FailureCount+c.SuccessCount == 0 || c.SuccessCount >= 2 {
				return bad()
			}
		case "ok":
			if c.SuccessCount <= 0 || open {
				return bad()
			}
		case "unknown":
			if c.FailureCount+c.SuccessCount != 0 {
				return bad()
			}
		default:
			return bad()
		}
		if c.FailureCount > 0 {
			if !incidentFailure(c.Kind, c.Scheme, *c.Reason, c.HTTPStatus) {
				return bad()
			}
		} else {
			state := "unknown"
			if c.SuccessCount > 0 {
				state = "ok"
			}
			if !historyOutcome(c.Kind, Result{State: state, Reason: *c.Reason, HTTPStatus: c.HTTPStatus}) {
				return bad()
			}
		}
	}
	return nil
}
func (s IncidentState) copy() IncidentState {
	b, _ := json.Marshal(s)
	var n IncidentState
	_ = json.Unmarshal(b, &n)
	return n
}
func (s *IncidentState) retire(now time.Time) {
	for i := range s.Records {
		r := &s.Records[i]
		if r.State == "open" {
			r.State = "monitoring_stopped"
			if !now.Before(s.Floor) && !now.Before(r.LastCompletedAt) {
				t := now.UTC()
				r.ClosedAt = &t
			}
		}
	}
	s.Policy = NewIncidentState().Policy
	s.PolicyKey = ""
	s.Progress = map[string]incidentProgress{}
}
func (s *IncidentState) sync(source IncidentSource, now time.Time) {
	now = now.UTC()
	if s.SourceKey != "" && (s.SourceKey != source.Key || !source.Enabled) {
		s.retire(now)
	}
	if s.SourceToken != source.Token || now.Before(s.Floor) {
		s.Progress = map[string]incidentProgress{}
	}
	s.SourceKey = source.Key
	s.SourceToken = source.Token
	if !now.Before(s.Floor) {
		s.Floor = now
	}
	kept := s.Records[:0]
	for _, r := range s.Records {
		end := r.LastCompletedAt
		if r.ClosedAt != nil {
			end = *r.ClosedAt
		}
		if r.State != "open" && now.Sub(end) > IncidentRetention {
			s.EarlierOmitted = true
			continue
		}
		kept = append(kept, r)
	}
	s.Records = kept
}
func (s *IncidentState) commit(n IncidentState) error {
	if reflect.DeepEqual(*s, n) {
		return nil
	}

	if e := n.Validate(); e != nil {
		return e
	}
	*s = n.copy()
	return nil
}
func (s *IncidentState) Synchronize(source IncidentSource, now time.Time) error {
	if s.Validate() != nil || validateIncidentSource(source, now) != nil || s.validateCurrentIncidentSource(source) != nil {
		return ErrIncidentInvalid
	}
	n := s.copy()
	n.sync(source, now)
	return s.commit(n)
}
func (s *IncidentState) Apply(c IncidentCommand, source IncidentSource, now time.Time) error {
	if s.Validate() != nil || validateIncidentSource(source, now) != nil || s.validateCurrentIncidentSource(source) != nil {
		return ErrIncidentInvalid
	}
	n := s.copy()
	if c.SourceToken != source.Token {
		return ErrIncidentInvalid
	}
	if n.LastCommand != nil && reflect.DeepEqual(*n.LastCommand, c) {
		n.sync(source, now)
		return s.commit(n)
	}
	if !incidentRequestPattern.MatchString(c.RequestID) || c.RequestID == "apprequest_00000000000000000000000000000000" || c.SourceToken != source.Token || c.ExpectedRevision != s.Revision || (s.LastCommand != nil && s.LastCommand.RequestID == c.RequestID) {
		return ErrIncidentInvalid
	}
	rollback := now.Before(s.Floor)
	n.sync(source, now)
	switch c.Operation {
	case "enable":
		if rollback || !source.Enabled || c.IncidentID != nil || !c.RetentionAcknowledged || len(c.TargetIDs) < 1 || len(c.TargetIDs) > 8 || (c.ConsecutiveFailures != 2 && c.ConsecutiveFailures != 3) {
			return ErrIncidentInvalid
		}
		seen := map[string]bool{}
		for _, id := range c.TargetIDs {
			found := false
			for _, t := range source.Targets {
				if t.ID == id {
					found = true
				}
			}
			if !found || seen[id] {
				return ErrIncidentInvalid
			}
			seen[id] = true
		}
		n.retire(now)
		n.PolicyKey = source.Key
		t := now.UTC()
		n.Policy = IncidentPolicyView{Enabled: true, SourceMatches: true, TargetIDs: append([]string{}, c.TargetIDs...), ConsecutiveFailures: c.ConsecutiveFailures, EnabledAt: &t}
	case "disable", "acknowledge":
		if len(c.TargetIDs) != 0 || c.ConsecutiveFailures != 0 || c.RetentionAcknowledged {
			return ErrIncidentInvalid
		}
		if c.Operation == "disable" {
			if c.IncidentID != nil {
				return ErrIncidentInvalid
			}
			n.retire(now)
		} else {
			if rollback || c.IncidentID == nil {
				return ErrIncidentInvalid
			}
			found := false
			for i := range n.Records {
				if n.Records[i].ID == *c.IncidentID {
					found = true
					if n.Records[i].AcknowledgedAt == nil {
						t := now.UTC()
						n.Records[i].AcknowledgedAt = &t
					}
				}
			}
			if !found {
				return ErrIncidentInvalid
			}
		}
	default:
		return ErrIncidentInvalid
	}
	if s.Revision == ^uint64(0) {
		return ErrIncidentInvalid
	}
	n.Revision = s.Revision + 1
	n.LastCommand = &c
	return s.commit(n)
}
func (s *IncidentState) Observe(source IncidentSource, r IncidentObservation, now time.Time) error {
	if s.Validate() != nil || validateIncidentSource(source, now) != nil || s.validateCurrentIncidentSource(source) != nil {
		return ErrIncidentInvalid
	}
	n := s.copy()
	rollback := now.Before(s.Floor)
	n.sync(source, now)
	if rollback || !n.Policy.Enabled {
		return s.commit(n)
	}
	selected := false
	for _, id := range n.Policy.TargetIDs {
		if id == r.TargetID {
			selected = true
		}
	}
	if !selected {
		return s.commit(n)
	}
	var target IncidentTarget
	for _, t := range source.Targets {
		if t.ID == r.TargetID {
			target = t
		}
	}
	p := n.Progress[r.TargetID]
	valid := !(r.Kind == kindHTTP && r.Scheme == "http" && r.State == "tls_error") && r.Kind == target.Kind && (target.Scheme == nil && r.Scheme == "" || target.Scheme != nil && r.Scheme == *target.Scheme) && historyOutcome(r.Kind, Result{State: r.State, Reason: r.Reason, HTTPStatus: r.HTTPStatus})
	if !valid || r.ObservedAt.IsZero() || r.CompletedAt.Before(r.ObservedAt) || r.CompletedAt.After(now) || r.ObservedAt.Before(*n.Policy.EnabledAt) || now.Sub(r.ObservedAt) > time.Duration(source.MaxAgeSeconds)*time.Second || !p.Last.IsZero() && !r.ObservedAt.After(p.Last) {
		p.Check = IncidentCheck{}
		p.First = time.Time{}
		n.Progress[r.TargetID] = p
		return s.commit(n)
	}
	if !p.Last.IsZero() && r.ObservedAt.Sub(p.Last) > time.Duration(source.MaxAgeSeconds)*time.Second {
		p.Check = IncidentCheck{}
		p.First = time.Time{}
	}
	observed, completed := r.ObservedAt.UTC(), r.CompletedAt.UTC()
	reason := r.Reason
	p.Last = completed
	fail := r.State == "network_error" || r.State == "tls_error" || r.State == "http_error"
	success := r.State == "ok"
	if fail {
		if p.Check.FailureCount == 0 {
			p.First = observed
		}
		p.Check.FailureCount++
		p.Check.SuccessCount = 0
	} else if success {
		if p.Check.SuccessCount == 0 {
			p.First = observed
		}
		p.Check.SuccessCount++
		p.Check.FailureCount = 0
	} else {
		p.Check.FailureCount = 0
		p.Check.SuccessCount = 0
		p.First = time.Time{}
	}
	if p.Check.FailureCount > 3 {
		p.Check.FailureCount = 3
	}
	if p.Check.SuccessCount > 2 {
		p.Check.SuccessCount = 2
	}
	p.Check.ID = target.ID
	p.Check.Kind = target.Kind
	p.Check.Scheme = target.Scheme
	p.Check.Condition = "unknown"
	if fail {
		p.Check.Condition = "pending"
	}
	if success {
		p.Check.Condition = "ok"
	}
	p.Check.ObservedAt = &observed
	p.Check.CompletedAt = &completed
	p.Check.Reason = &reason
	p.Check.HTTPStatus = r.HTTPStatus
	open := -1
	for i := range n.Records {
		if n.Records[i].State == "open" && n.Records[i].TargetID == r.TargetID && n.Records[i].SourceKey == source.Key {
			open = i
		}
	}
	if open >= 0 {
		if fail || success {
			p.Check.Condition = "incident"
		}
		x := &n.Records[open]
		x.LastObservedAt = observed
		x.LastCompletedAt = completed
		if success && p.Check.SuccessCount >= 2 {
			x.State = "recovered"
			p.Check.Condition = "ok"
			x.ClosedAt = &completed
			x.Recovery = &IncidentRecovery{FirstObservedAt: p.First, ObservedAt: observed, CompletedAt: completed, Samples: 2}
		}
	} else if fail && p.Check.FailureCount >= n.Policy.ConsecutiveFailures {
		if n.NextID == ^uint64(0) {
			return ErrIncidentInvalid
		}
		p.Check.Condition = "incident"
		if len(n.Records) >= IncidentLimit {
			for i, x := range n.Records {
				if x.State != "open" {
					n.Records = append(n.Records[:i], n.Records[i+1:]...)
					n.EarlierOmitted = true
					break
				}
			}
		}
		n.Records = append(n.Records, incidentRecord{SourceKey: source.Key, ApplicationIncident: ApplicationIncident{ID: fmt.Sprintf("appincident_%016x", n.NextID), TargetID: target.ID, Kind: target.Kind, Scheme: target.Scheme, State: "open", Opening: IncidentOpening{FirstObservedAt: p.First, ObservedAt: observed, CompletedAt: completed, Reason: r.Reason, HTTPStatus: r.HTTPStatus, Samples: n.Policy.ConsecutiveFailures}, LastObservedAt: observed, LastCompletedAt: completed}})
		n.NextID++
	}
	n.Progress[r.TargetID] = p
	return s.commit(n)
}
func (s IncidentState) View(source IncidentSource, now time.Time, canManage bool) IncidentView {
	reliable := !now.Before(s.Floor)
	s = s.copy()
	s.sync(source, now)
	v := IncidentView{SchemaVersion: IncidentSchema, ServerNow: now.UTC(), Revision: s.Revision, CanManage: canManage, ClockReliable: reliable, RetentionDays: 30, MaxIncidents: IncidentLimit, EarlierOmitted: s.EarlierOmitted, Policy: s.Policy, Checks: []IncidentCheck{}, Incidents: []ApplicationIncident{}, CurrentSource: IncidentSourceView{Token: source.Token, Mode: source.Mode, ChecksEnabled: source.Enabled, Targets: []IncidentTarget{}}}
	v.Policy.SourceMatches = s.PolicyKey != "" && s.PolicyKey == source.Key
	if source.Enabled {
		v.CurrentSource.Targets = cloneIncidentTargets(source.Targets)
		v.CurrentSource.IntervalSeconds = source.IntervalSeconds
		v.CurrentSource.MaxAgeSeconds = source.MaxAgeSeconds
	}
	for _, id := range s.Policy.TargetIDs {
		p := s.Progress[id]
		c := p.Check
		if !reliable || c.CompletedAt == nil || now.Sub(*c.ObservedAt) > time.Duration(source.MaxAgeSeconds)*time.Second {
			c = IncidentCheck{ID: id, Condition: "unknown"}
			for _, t := range source.Targets {
				if t.ID == id {
					c.Kind = t.Kind
					c.Scheme = t.Scheme
				}
			}
		}
		v.Checks = append(v.Checks, c)
	}
	for i := len(s.Records) - 1; i >= 0; i-- {
		r := s.Records[i]
		r.SourceCurrent = r.SourceKey == source.Key
		v.Incidents = append(v.Incidents, r.ApplicationIncident)
	}
	if s.LastCommand != nil {
		c := s.LastCommand
		v.LastRequest = &IncidentRequestView{RequestID: c.RequestID, Operation: c.Operation, SourceToken: c.SourceToken, IncidentID: c.IncidentID}
	}
	return v
}

// A matching private binding must agree with its immutable runtime definition.
// A legitimate different generation is retired, not mistaken for corruption.
func (s IncidentState) validateCurrentIncidentSource(source IncidentSource) error {
	if !s.Policy.Enabled || s.PolicyKey != source.Key || !source.Enabled {
		return nil
	}
	targets := map[string]IncidentTarget{}
	for _, t := range source.Targets {
		targets[t.ID] = t
	}
	for _, id := range s.Policy.TargetIDs {
		if _, ok := targets[id]; !ok {
			return ErrIncidentInvalid
		}
	}
	for id, p := range s.Progress {
		t, ok := targets[id]
		if !ok || p.Check.ID != "" && (p.Check.Kind != t.Kind || !reflect.DeepEqual(p.Check.Scheme, t.Scheme)) {
			return ErrIncidentInvalid
		}
	}
	for _, r := range s.Records {
		if r.State == "open" && r.SourceKey == source.Key {
			t, ok := targets[r.TargetID]
			if !ok || r.Kind != t.Kind || !reflect.DeepEqual(r.Scheme, t.Scheme) {
				return ErrIncidentInvalid
			}
		}
	}
	return nil
}
