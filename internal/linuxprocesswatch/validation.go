package linuxprocesswatch

import (
	"math"
	"reflect"
	"time"
)

func validPolicy(p Policy) bool {
	if p.Names == nil || len(p.Names) > MaxRules {
		return false
	}
	if !p.Enabled {
		return len(p.Names) == 0 && p.ConsecutiveFailures == 0 && p.EnabledAt == nil
	}
	if len(p.Names) == 0 || (p.ConsecutiveFailures != 2 && p.ConsecutiveFailures != 3) {
		return false
	}
	for i, n := range p.Names {
		if !ValidName(n) || i > 0 && p.Names[i-1] >= n {
			return false
		}
	}
	return p.EnabledAt == nil || utc(*p.EnabledAt)
}
func validObservation(o Observation) bool {
	return validGeneration(o.Generation) && uint64(o.ActiveCount)+uint64(o.NonRunningCount) <= uint64(o.Generation.TotalRows-o.Generation.UnidentifiedRows)
}
func validProof(p Proof, success bool) bool {
	if (p.Samples != 2 && p.Samples != 3) || success && p.Samples != 2 || !validObservation(p.First) || !validObservation(p.Last) || !advancing(p.First.Generation, p.Last.Generation) {
		return false
	}
	first, _ := sequence(p.First.Generation.Sequence)
	last, _ := sequence(p.Last.Generation.Sequence)
	if last-first != uint64(p.Samples-1) {
		return false
	}
	if success {
		return p.First.ActiveCount > 0 && p.Last.ActiveCount > 0
	}
	return p.First.ActiveCount == 0 && p.Last.ActiveCount == 0 && p.First.Generation.UnidentifiedRows == 0 && p.Last.Generation.UnidentifiedRows == 0
}
func optionalUTC(t *time.Time) bool { return t == nil || utc(*t) }
func validate(s *State) error {
	if s == nil || !hex(s.DeviceID, "agent_", 32) || s.Revision > math.MaxInt64 || s.NextID == 0 || s.SeenSequence > math.MaxInt64 || s.Progress == nil || s.Incidents == nil || !validPolicy(s.Policy) || len(s.Incidents) > MaxIncidents || len(s.Progress) != len(s.Policy.Names) {
		return ErrInvalid
	}
	if s.Identity == "" {
		if s.Epoch != "" || s.Policy.Enabled || s.Revision != 0 || len(s.Incidents) != 0 || s.LastGeneration != nil || s.LastRequest != nil {
			return ErrInvalid
		}
	} else if !hex(s.Identity, "", 64) || !hex(s.Epoch, "", 32) {
		return ErrInvalid
	}
	if !s.ClockFloor.IsZero() && !utc(s.ClockFloor) {
		return ErrInvalid
	}
	if s.Policy.Enabled && (s.Policy.EnabledAt == nil || s.Policy.EnabledAt.After(s.ClockFloor)) {
		return ErrInvalid
	}
	if s.LastGeneration != nil {
		q, _ := sequence(s.LastGeneration.Sequence)
		if !validGeneration(*s.LastGeneration) || q > s.SeenSequence {
			return ErrInvalid
		}
	} else if s.SeenSequence != 0 {
		return ErrInvalid
	}
	opens := map[string]bool{}
	ids := map[string]bool{}
	var previous uint64
	for _, c := range s.Incidents {
		if !hex(c.ID, "processincident_", 16) || !ValidName(c.Name) || !hex(c.Identity, "", 64) || !utc(c.OpenedAt) || !utc(c.LastObservedAt) || !optionalUTC(c.ClosedAt) || !optionalUTC(c.AcknowledgedAt) || !validProof(c.Opening, false) || c.OpenedAt.Before(c.Opening.Last.Generation.ReceivedAt) || c.LastObservedAt.Before(c.Opening.Last.Generation.CaptureFinishedAt) || c.OpenedAt.After(s.ClockFloor) || c.LastObservedAt.After(s.ClockFloor) || c.ClosedAt != nil && c.ClosedAt.After(s.ClockFloor) || c.AcknowledgedAt != nil && c.AcknowledgedAt.After(s.ClockFloor) || ids[c.ID] {
			return ErrInvalid
		}
		ids[c.ID] = true
		var id uint64
		for _, ch := range c.ID[len("processincident_"):] {
			id *= 16
			if ch <= '9' {
				id += uint64(ch - '0')
			} else {
				id += uint64(ch - 'a' + 10)
			}
		}
		if id == 0 || id >= s.NextID || id <= previous {
			return ErrInvalid
		}
		previous = id
		if c.ClosedAt != nil && c.ClosedAt.Before(c.OpenedAt) || c.AcknowledgedAt != nil && c.AcknowledgedAt.Before(c.OpenedAt) {
			return ErrInvalid
		}
		switch c.State {
		case "open":
			if c.ClosedAt != nil || c.Recovery != nil || c.Identity != s.Identity || !s.Policy.Enabled || opens[c.Name] || s.Policy.EnabledAt == nil || !c.Opening.First.Generation.CaptureStartedAt.After(*s.Policy.EnabledAt) {
				return ErrInvalid
			}
			found := false
			for _, n := range s.Policy.Names {
				if n == c.Name {
					found = true
				}
			}
			if !found {
				return ErrInvalid
			}
			opens[c.Name] = true
		case "recovered":
			if c.ClosedAt == nil || c.Recovery == nil || !validProof(*c.Recovery, true) || c.ClosedAt.Before(c.Recovery.Last.Generation.ReceivedAt) || !c.LastObservedAt.Equal(c.Recovery.Last.Generation.CaptureFinishedAt) || !advancing(c.Opening.Last.Generation, c.Recovery.First.Generation) {
				return ErrInvalid
			}
		case "monitoring_stopped":
			if c.Recovery != nil {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	if len(opens) > MaxRules {
		return ErrInvalid
	}
	for i, p := range s.Progress {
		if p.Name != s.Policy.Names[i] || p.FailureCount < 0 || p.FailureCount > 3 || p.SuccessCount < 0 || p.SuccessCount > 2 {
			return ErrInvalid
		}
		for _, o := range []*Observation{p.Last, p.FailureFirst, p.SuccessFirst} {
			if o != nil && (!validObservation(*o) || s.Policy.EnabledAt == nil || !o.Generation.CaptureStartedAt.After(*s.Policy.EnabledAt) || o.Generation.ReceivedAt.After(s.ClockFloor)) {
				return ErrInvalid
			}
		}
		if (p.FailureCount == 0) != (p.FailureFirst == nil) || (p.SuccessCount == 0) != (p.SuccessFirst == nil) || p.FailureCount > 0 && p.SuccessCount > 0 {
			return ErrInvalid
		}

		if p.Last != nil && (s.LastGeneration == nil || !reflect.DeepEqual(p.Last.Generation, *s.LastGeneration)) {
			return ErrInvalid
		}
		for _, streak := range []struct {
			first   *Observation
			count   int
			success bool
		}{{p.FailureFirst, p.FailureCount, false}, {p.SuccessFirst, p.SuccessCount, true}} {
			if streak.first == nil {
				continue
			}
			if p.Last == nil || streak.success != (streak.first.ActiveCount > 0) || !streak.success && streak.first.Generation.UnidentifiedRows != 0 {
				return ErrInvalid
			}
			first, _ := sequence(streak.first.Generation.Sequence)
			last, _ := sequence(p.Last.Generation.Sequence)
			if last < first || last-first != uint64(streak.count-1) {
				return ErrInvalid
			}
			if streak.count == 1 && !reflect.DeepEqual(*streak.first, *p.Last) || streak.count > 1 && !advancing(streak.first.Generation, p.Last.Generation) {
				return ErrInvalid
			}
		}
		switch p.Condition {
		case "unknown":
			if p.Last != nil || p.FailureCount != 0 || p.SuccessCount != 0 {
				return ErrInvalid
			}
		case "present":
			if p.Last == nil || p.Last.ActiveCount == 0 || opens[p.Name] || p.FailureCount != 0 || p.SuccessCount != 0 {
				return ErrInvalid
			}
		case "pending":
			if p.Last == nil || p.Last.ActiveCount != 0 || p.Last.Generation.UnidentifiedRows != 0 || p.FailureCount < 1 || p.FailureCount >= s.Policy.ConsecutiveFailures || opens[p.Name] {
				return ErrInvalid
			}
		case "incident":
			if !opens[p.Name] || p.Last == nil || p.FailureCount != 0 {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	if r := s.LastRequest; r != nil {
		if !hex(r.Public.RequestID, "processrequest_", 32) || !hex(r.Public.SourceToken, "processsource_", 32) || r.Identity != s.Identity || r.Epoch != s.Epoch || r.ExpectedRevision >= math.MaxInt64 || r.ExpectedRevision+1 != s.Revision {
			return ErrInvalid
		}
		switch r.Public.Operation {
		case "policy":
			if r.Public.IncidentID != nil || r.Policy == nil || !validPolicy(*r.Policy) || r.Policy.EnabledAt != nil || r.RetentionAcknowledged != r.Policy.Enabled {
				return ErrInvalid
			}
		case "acknowledge":
			if r.Policy != nil || r.RetentionAcknowledged || r.Public.IncidentID == nil || !hex(*r.Public.IncidentID, "processincident_", 16) {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	return nil
}
