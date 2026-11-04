package linuxprocesswatch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

func New(deviceID string) *State {
	return &State{DeviceID: deviceID, NextID: 1, Policy: Policy{Names: []string{}}, Progress: []Progress{}, Incidents: []Incident{}}
}
func hex(s, p string, n int) bool {
	if !strings.HasPrefix(s, p) || len(s) != len(p)+n {
		return false
	}
	for _, c := range s[len(p):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func ValidName(s string) bool {
	if len(s) < 1 || len(s) > 64 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == utf8.RuneError || r == 0x2028 || r == 0x2029 || unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}
func utc(t time.Time) bool { return !t.IsZero() && t.Location() == time.UTC }
func sequence(s string) (uint64, bool) {
	v, e := strconv.ParseUint(s, 10, 63)
	return v, e == nil && v > 0 && strconv.FormatUint(v, 10) == s
}
func validGeneration(g Generation) bool {
	_, ok := sequence(g.Sequence)
	return ok && hex(g.GenerationID, "sample_", 32) && hex(g.ManifestHash, "", 64) && utc(g.CaptureStartedAt) && utc(g.CaptureFinishedAt) && utc(g.ReceivedAt) && !g.CaptureFinishedAt.Before(g.CaptureStartedAt) && !g.ReceivedAt.Before(g.CaptureFinishedAt) && g.TotalRows <= 32768 && g.UnidentifiedRows <= g.TotalRows
}
func validInput(s *State, in Input) bool {
	return hex(s.DeviceID, "agent_", 32) && in.DeviceID == s.DeviceID && hex(in.Identity, "", 64) && hex(in.Epoch, "", 32) && hex(in.SourceToken, "processsource_", 32) && utc(in.AuthorityUntil)
}
func usable(s *State, in Input, now time.Time) bool {
	return validInput(s, in) && in.Authorized && in.Available && in.Reason == "none" && now.Before(in.AuthorityUntil) && in.Sample != nil && validGeneration(*in.Sample) && !in.Sample.ReceivedAt.After(now) && now.Sub(in.Sample.CaptureStartedAt) < MaxAge && now.Sub(in.Sample.ReceivedAt) < MaxAge
}
func copyState(s *State) *State {
	b, _ := json.Marshal(s)
	var n State
	_ = json.Unmarshal(b, &n)
	return &n
}
func reset(s *State) {
	s.Progress = []Progress{}
	for _, n := range s.Policy.Names {
		s.Progress = append(s.Progress, Progress{Name: n, Condition: "unknown"})
	}
}
func retire(s *State, now time.Time, reliable bool) {
	for i := range s.Incidents {
		c := &s.Incidents[i]
		if c.State == "open" {
			c.State = "monitoring_stopped"
			if reliable {
				t := now
				c.ClosedAt = &t
			}
		}
	}
}
func prune(s *State, now time.Time, reserve int) {
	kept := s.Incidents[:0]
	for _, c := range s.Incidents {
		t := c.LastObservedAt
		if c.ClosedAt != nil {
			t = *c.ClosedAt
		}
		if c.State != "open" && now.Sub(t) > Retention {
			s.EarlierOmitted++
			continue
		}
		kept = append(kept, c)
	}
	s.Incidents = kept
	for len(s.Incidents)+reserve > MaxIncidents || stateBytes(s) > MaxBytes {
		found := -1
		for i, c := range s.Incidents {
			if c.State != "open" && (found < 0 || terminalTime(c).Before(terminalTime(s.Incidents[found]))) {
				found = i
			}
		}
		if found < 0 {
			return
		}
		s.Incidents = append(s.Incidents[:found], s.Incidents[found+1:]...)
		s.EarlierOmitted++
	}
}
func stateBytes(s *State) int {
	b, err := json.Marshal(s)
	if err != nil {
		return MaxBytes + 1
	}
	return len(b)
}
func advanceFloor(s *State, now time.Time) {
	if now.After(s.ClockFloor) {
		s.ClockFloor = now
	}
}
func replay(s *State, in Input, c Command) bool {
	return s.LastRequest != nil && s.Identity == in.Identity && s.Epoch == in.Epoch && reflect.DeepEqual(*s.LastRequest, c)
}
func Configure(s *State, in Input, r ConfigureRequest, now time.Time) error {
	if s == nil || !utc(now) || !validInput(s, in) || !hex(r.RequestID, "processrequest_", 32) || r.SourceToken != in.SourceToken {
		return ErrSource
	}
	names := append([]string{}, r.Names...)
	sort.Strings(names)
	for i, n := range names {
		if !ValidName(n) || i > 0 && names[i-1] == n {
			return ErrInvalid
		}
	}
	if r.Enabled {
		if len(names) < 1 || len(names) > MaxRules || (r.ConsecutiveFailures != 2 && r.ConsecutiveFailures != 3) || !r.RetentionAcknowledged {
			return ErrInvalid
		}
	} else if len(names) != 0 || r.ConsecutiveFailures != 0 || r.RetentionAcknowledged {
		return ErrInvalid
	}
	p := Policy{Enabled: r.Enabled, Names: names, ConsecutiveFailures: r.ConsecutiveFailures}
	c := Command{Public: LastRequest{RequestID: r.RequestID, Operation: "policy", SourceToken: r.SourceToken}, ExpectedRevision: r.ExpectedRevision, Identity: in.Identity, Epoch: in.Epoch, Policy: &p, RetentionAcknowledged: r.RetentionAcknowledged}
	if replay(s, in, c) {
		return nil
	}
	if s.LastRequest != nil && s.LastRequest.Public.RequestID == r.RequestID {
		return ErrConflict
	}
	if r.ExpectedRevision != s.Revision || s.Revision >= math.MaxInt64 {
		return ErrConflict
	}
	reliable := !now.Before(s.ClockFloor)
	if r.Enabled && (!reliable) {
		return ErrClock
	}
	if r.Enabled && (!usable(s, in, now)) {
		return ErrSource
	}
	if !in.Authorized || !now.Before(in.AuthorityUntil) {
		return ErrSource
	}
	n := copyState(s)
	retire(n, now, reliable)
	if n.Identity != in.Identity {
		n.LastGeneration = nil
		n.SeenSequence = 0
	}
	n.Identity = in.Identity
	n.Epoch = in.Epoch
	n.Policy = p
	if p.Enabled {
		t := now
		n.Policy.EnabledAt = &t
	}
	reset(n)
	consume(n, in.Sample)
	n.LastRequest = &c
	n.Revision++
	advanceFloor(n, now)
	if reliable {
		prune(n, now, 0)
	} else {
		prune(n, n.ClockFloor, 0)
	}
	*s = *n
	return nil
}
func Acknowledge(s *State, in Input, r AcknowledgeRequest, now time.Time) error {
	if s == nil || !utc(now) || !validInput(s, in) || r.SourceToken != in.SourceToken || !hex(r.RequestID, "processrequest_", 32) || !hex(r.IncidentID, "processincident_", 16) || !in.Authorized || !now.Before(in.AuthorityUntil) {
		return ErrSource
	}
	if now.Before(s.ClockFloor) {
		return ErrClock
	}
	id := r.IncidentID
	c := Command{Public: LastRequest{RequestID: r.RequestID, Operation: "acknowledge", SourceToken: r.SourceToken, IncidentID: &id}, ExpectedRevision: r.ExpectedRevision, Identity: in.Identity, Epoch: in.Epoch}
	if replay(s, in, c) {
		return nil
	}
	if s.LastRequest != nil && s.LastRequest.Public.RequestID == r.RequestID {
		return ErrConflict
	}
	if s.Revision != r.ExpectedRevision || s.Revision >= math.MaxInt64 {
		return ErrConflict
	}
	if s.Identity != in.Identity || s.Epoch != in.Epoch {
		return ErrSource
	}
	n := copyState(s)
	found := false
	for i := range n.Incidents {
		if n.Incidents[i].ID == id {
			found = true
			if n.Incidents[i].AcknowledgedAt == nil {
				t := now
				n.Incidents[i].AcknowledgedAt = &t
			}
			break
		}
	}
	if !found {
		return ErrInvalid
	}
	n.Revision++
	n.LastRequest = &c
	advanceFloor(n, now)
	prune(n, now, 0)
	*s = *n
	return nil
}
func advancing(a, b Generation) bool {
	x, _ := sequence(a.Sequence)
	y, _ := sequence(b.Sequence)
	return y > x && b.CaptureStartedAt.After(a.CaptureStartedAt) && b.CaptureFinishedAt.After(a.CaptureFinishedAt) && b.ReceivedAt.After(a.ReceivedAt)
}
func openIndex(s *State, name string) int {
	for i, c := range s.Incidents {
		if c.State == "open" && c.Name == name && c.Identity == s.Identity {
			return i
		}
	}
	return -1
}

// Maintain only expires terminal history against a trustworthy local clock.
// It neither reads source data nor changes policy, progress or open incidents.
func Maintain(s *State, now time.Time) error {
	if s == nil || !utc(now) {
		return ErrInvalid
	}
	if now.Before(s.ClockFloor) {
		return nil
	}
	n := copyState(s)
	advanceFloor(n, now)
	prune(n, now, 0)
	*s = *n
	return nil
}

func Evaluate(s *State, in Input, now time.Time) error {
	if s == nil || !utc(now) {
		return ErrInvalid
	}
	if now.Before(s.ClockFloor) {
		reset(s)
		return nil
	}
	n := copyState(s)
	advanceFloor(n, now)
	prune(n, now, 0)
	if !validInput(n, in) || !in.Authorized || !now.Before(in.AuthorityUntil) {
		reset(n)
		prune(n, now, 0)
		*s = *n
		return nil
	}
	if n.Identity != "" && n.Identity != in.Identity {
		retire(n, now, true)
		n.Policy = Policy{Names: []string{}}
		reset(n)
		n.Identity = in.Identity
		n.Epoch = in.Epoch
		n.LastGeneration = nil
		n.SeenSequence = 0
		n.LastRequest = nil
		prune(n, now, 0)
		*s = *n
		return nil
	}
	if n.Identity == "" {
		n.Identity = in.Identity
		n.Epoch = in.Epoch
	}
	if n.Epoch != in.Epoch {
		n.Epoch = in.Epoch
		reset(n)
		consume(n, in.Sample)
		n.LastRequest = nil
		prune(n, now, 0)
		*s = *n
		return nil
	}
	if !n.Policy.Enabled {
		prune(n, now, 0)
		*s = *n
		return nil
	}
	good := usable(n, in, now) && n.Policy.EnabledAt != nil && in.Sample.CaptureStartedAt.After(*n.Policy.EnabledAt) && len(in.Counts) == len(n.Policy.Names)
	if good {
		var sum uint64
		for i, c := range in.Counts {
			if c.Name != n.Policy.Names[i] {
				good = false
			}
			sum += uint64(c.ActiveCount) + uint64(c.NonRunningCount)
		}
		if sum > uint64(in.Sample.TotalRows-in.Sample.UnidentifiedRows) {
			good = false
		}
	}
	if !good {
		reset(n)
		consume(n, in.Sample)
		prune(n, now, 0)
		*s = *n
		return nil
	}
	g := *in.Sample
	seq, _ := sequence(g.Sequence)
	if n.LastGeneration != nil {
		if reflect.DeepEqual(*n.LastGeneration, g) && seq == n.SeenSequence {
			prune(n, now, 0)
			*s = *n
			return nil
		}
		if seq <= n.SeenSequence || !advancing(*n.LastGeneration, g) {
			reset(n)
			consume(n, &g)
			prune(n, now, 0)
			*s = *n
			return nil
		}
		if seq != n.SeenSequence+1 || g.CaptureStartedAt.Sub(n.LastGeneration.CaptureStartedAt) > MaxAge || g.ReceivedAt.Sub(n.LastGeneration.ReceivedAt) > MaxAge {
			reset(n)
		}
	}
	n.LastGeneration = &g
	n.SeenSequence = seq
	for i, c := range in.Counts {
		p := &n.Progress[i]
		o := Observation{Generation: g, ActiveCount: c.ActiveCount, NonRunningCount: c.NonRunningCount}
		p.Last = &o
		oi := openIndex(n, c.Name)
		if c.ActiveCount == 0 && g.UnidentifiedRows > 0 {
			*p = Progress{Name: c.Name, Condition: "unknown"}
			continue
		}
		if c.ActiveCount > 0 {
			p.FailureCount = 0
			p.FailureFirst = nil
			p.Condition = "present"
			if oi >= 0 {
				p.Condition = "incident"
				if p.SuccessCount == 0 {
					p.SuccessFirst = &o
				}
				p.SuccessCount++
				n.Incidents[oi].LastObservedAt = g.CaptureFinishedAt
				if p.SuccessCount >= 2 {
					t := now
					n.Incidents[oi].State = "recovered"
					n.Incidents[oi].ClosedAt = &t
					n.Incidents[oi].Recovery = &Proof{First: *p.SuccessFirst, Last: o, Samples: 2}
					p.Condition = "present"
					p.SuccessCount = 0
					p.SuccessFirst = nil
				}
			} else {
				p.SuccessCount = 0
				p.SuccessFirst = nil
			}
			continue
		}
		p.SuccessCount = 0
		p.SuccessFirst = nil
		if oi >= 0 {
			p.Condition = "incident"
			p.FailureCount = 0
			p.FailureFirst = nil
			n.Incidents[oi].LastObservedAt = g.CaptureFinishedAt
			continue
		}
		if p.FailureCount == 0 {
			p.FailureFirst = &o
		}
		p.FailureCount++
		p.Condition = "pending"
		if p.FailureCount >= n.Policy.ConsecutiveFailures {
			if n.NextID == 0 || n.NextID == math.MaxUint64 {
				return ErrCapacity
			}
			prune(n, now, 1)
			if len(n.Incidents) >= MaxIncidents {
				return ErrCapacity
			}
			n.Incidents = append(n.Incidents, Incident{ID: fmt.Sprintf("processincident_%016x", n.NextID), Name: c.Name, Identity: n.Identity, State: "open", OpenedAt: now, LastObservedAt: g.CaptureFinishedAt, Opening: Proof{First: *p.FailureFirst, Last: o, Samples: p.FailureCount}})
			n.NextID++
			p.Condition = "incident"
			p.FailureCount = 0
			p.FailureFirst = nil
		}
	}
	prune(n, now, 0)
	*s = *n
	return nil
}
func View(s *State, in Input, now time.Time, canManage bool) PublicView {
	s = copyState(s)
	now = now.UTC()
	v := PublicView{SchemaVersion: SchemaVersion, DeviceID: s.DeviceID, ServerNow: now, ValidUntil: now.Add(30 * time.Second), Revision: strconv.FormatUint(s.Revision, 10), ClockReliable: !now.Before(s.ClockFloor), MaxRules: MaxRules, MaxIncidents: MaxIncidents, RetentionDays: RetentionDays, EarlierOmitted: s.EarlierOmitted, Checks: []Check{}, Incidents: []PublicIncident{}}
	if in.AuthorityUntil.Before(v.ValidUntil) {
		v.ValidUntil = in.AuthorityUntil
	}
	v.CanManage = canManage && in.Authorized && validInput(s, in) && now.Before(in.AuthorityUntil) && s.Revision < math.MaxInt64
	v.Source = PublicSource{Token: in.SourceToken, Scope: "agent-visible-linux-namespaces", Status: "unknown", Reason: in.Reason}
	switch v.Source.Reason {
	case "none", "not_configured", "no_generation", "newer_attempt", "stale", "unavailable":
	default:
		v.Source.Reason = "unavailable"
	}
	good := usable(s, in, now) && v.ClockReliable
	if good {
		v.Source.Status = "available"
		g := *in.Sample
		v.Source.Generation = &g
		v.Source.Reason = "none"
		for _, deadline := range []time.Time{g.CaptureStartedAt.Add(MaxAge), g.ReceivedAt.Add(MaxAge)} {
			if deadline.Before(v.ValidUntil) {
				v.ValidUntil = deadline
			}
		}
	} else if v.Source.Reason == "none" {
		v.Source.Reason = "stale"
	}
	match := s.Identity == in.Identity && s.Identity != ""
	v.Policy = PublicPolicy{Policy: s.Policy, SourceMatches: match}
	v.Policy.Names = append([]string{}, s.Policy.Names...)
	if !v.Policy.Enabled {
		v.Policy.ConsecutiveFailures = 2
		v.Policy.EnabledAt = nil
	}
	current := good && match && s.Epoch == in.Epoch && in.Sample != nil && s.LastGeneration != nil && reflect.DeepEqual(*in.Sample, *s.LastGeneration) && func() bool { q, _ := sequence(in.Sample.Sequence); return q == s.SeenSequence }()
	for _, p := range s.Progress {
		c := Check{Name: p.Name, Condition: "unknown"}
		if current && p.Last != nil && reflect.DeepEqual(p.Last.Generation, *in.Sample) {
			c.Condition = p.Condition
			a, b := p.Last.ActiveCount, p.Last.NonRunningCount
			c.ActiveCount = &a
			c.NonRunningCount = &b
			c.FailureCount = p.FailureCount
			c.SuccessCount = p.SuccessCount
		}
		v.Checks = append(v.Checks, c)
	}
	for _, c := range s.Incidents {
		if v.ClockReliable && c.State != "open" && now.Sub(terminalTime(c)) > Retention {
			v.EarlierOmitted++
			continue
		}
		v.Incidents = append(v.Incidents, PublicIncident{ID: c.ID, Name: c.Name, State: c.State, SourceCurrent: c.Identity == in.Identity, OpenedAt: c.OpenedAt, LastObservedAt: c.LastObservedAt, ClosedAt: c.ClosedAt, AcknowledgedAt: c.AcknowledgedAt, Opening: c.Opening, Recovery: c.Recovery})
	}
	if s.LastRequest != nil {
		r := s.LastRequest.Public
		v.LastRequest = &r
	}
	return v
}
func Encode(s *State) ([]byte, error) {
	if err := validate(s); err != nil {
		return nil, err
	}
	b, e := json.Marshal(s)
	if e != nil || len(b) > MaxBytes {
		return nil, ErrInvalid
	}
	return b, nil
}
func Decode(b []byte) (*State, error) {
	if len(b) == 0 || len(b) > MaxBytes {
		return nil, ErrInvalid
	}
	var s State
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil {
		return nil, ErrInvalid
	}
	canonical, e := Encode(&s)
	if e != nil || !bytes.Equal(b, canonical) {
		return nil, ErrInvalid
	}
	return &s, nil
}

func consume(s *State, g *Generation) {
	if g == nil || !validGeneration(*g) {
		return
	}
	q, _ := sequence(g.Sequence)
	if q > s.SeenSequence {
		s.SeenSequence = q
	}
	if s.LastGeneration == nil || advancing(*s.LastGeneration, *g) {
		c := *g
		s.LastGeneration = &c
	}
}

func terminalTime(c Incident) time.Time {
	if c.ClosedAt != nil {
		return *c.ClosedAt
	}
	return c.LastObservedAt
}
