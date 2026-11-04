// Package windowseventwatch evaluates positive matches from already-consented
// periodic headers. It never collects events or infers recovery from absence.
package windowseventwatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowseventhealth"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MaxSelectors  = 4
	MaxIncidents  = 100
	MaxStateBytes = 128 << 10
	MaxAge        = 120 * time.Second
	Retention     = 7 * 24 * time.Hour
	MaxCounter    = windowscontact.MaxCounter
)

var ErrInvalid = errors.New("windows_event_watch_invalid")

type Selector struct {
	Channel  string `json:"channel"`
	Provider string `json:"provider"`
	EventID  uint16 `json:"eventId"`
	Level    uint8  `json:"level"`
}
type Policy struct {
	Enabled               bool       `json:"enabled"`
	Revision              uint64     `json:"revision"`
	Selectors             []Selector `json:"selectors"`
	EnabledAt             time.Time  `json:"enabledAt"`
	RetentionAcknowledged bool       `json:"retentionAcknowledged"`
}
type Input struct {
	Source windowscontact.Input
	Events *windowseventhealth.Snapshot
}

// Incident contains only consented selectors and derived observations, never
// raw event timestamps, record IDs, event messages, or raw header rows.
type Incident struct {
	ID              string     `json:"id"`
	Selector        Selector   `json:"selector"`
	FirstObservedAt time.Time  `json:"firstObservedAt"`
	LastObservedAt  time.Time  `json:"lastObservedAt"`
	FirstReceivedAt time.Time  `json:"firstReceivedAt"`
	LastReceivedAt  time.Time  `json:"lastReceivedAt"`
	CountLowerBound uint64     `json:"countLowerBound"`
	ReviewedAt      *time.Time `json:"reviewedAt"`
}
type Floor struct {
	Ready    bool   `json:"ready"`
	RecordID string `json:"recordId"`
}
type State struct {
	Version         int        `json:"version"`
	DeviceID        string     `json:"deviceId"`
	InvitationID    string     `json:"invitationId"`
	CertificateHash string     `json:"certificateHash"`
	GrantID         string     `json:"grantId"`
	Policy          Policy     `json:"policy"`
	Status          string     `json:"status"`
	Floors          [2]Floor   `json:"floors"`
	Sequence        uint64     `json:"sequence"`
	CapturedAt      *time.Time `json:"capturedAt"`
	ReceivedAt      *time.Time `json:"receivedAt"`
	EvaluatedAt     *time.Time `json:"evaluatedAt"`
	RearmRequired   bool       `json:"rearmRequired"`
	NextID          uint64     `json:"nextId"`
	Incidents       []Incident `json:"incidents"`
}
type View struct {
	SchemaVersion string     `json:"schemaVersion"`
	ServerNow     time.Time  `json:"serverNow"`
	Policy        Policy     `json:"policy"`
	Status        string     `json:"status"`
	Incidents     []Incident `json:"incidents"`
}

func New() State {
	return State{Version: 1, Policy: Policy{Selectors: []Selector{}}, Status: "disabled", Incidents: []Incident{}}
}
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1970 && t.Year() <= 9999
}
func ptr(t time.Time) *time.Time { t = t.UTC().Round(0); return &t }
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func binding(inv, hash string) bool {
	return strings.HasPrefix(inv, "invite_") && isHex(strings.TrimPrefix(inv, "invite_"), 32) && strings.TrimPrefix(inv, "invite_") != strings.Repeat("0", 32) && isHex(hash, 64) && hash != strings.Repeat("0", 64)
}
func (s Selector) Validate() error {
	if s.Channel != "Application" && s.Channel != "System" {
		return ErrInvalid
	}
	units := 0
	for _, r := range s.Provider {
		units++
		if r > 0xffff {
			units++
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError || r == '\u2028' || r == '\u2029' {
			return ErrInvalid
		}
	}
	if units == 0 || units > 256 || len(s.Provider) > 1024 || !utf8.ValidString(s.Provider) || strings.TrimSpace(s.Provider) != s.Provider {
		return ErrInvalid
	}
	return nil
}
func (p Policy) Validate() error {
	if p.Selectors == nil || len(p.Selectors) > MaxSelectors || p.Revision > MaxCounter {
		return ErrInvalid
	}
	seen := map[Selector]bool{}
	for _, x := range p.Selectors {
		if x.Validate() != nil || seen[x] {
			return ErrInvalid
		}
		seen[x] = true
	}
	if p.Enabled {
		if !p.RetentionAcknowledged || p.Revision == 0 || len(p.Selectors) == 0 || !validTime(p.EnabledAt) {
			return ErrInvalid
		}
	}
	if !p.EnabledAt.IsZero() && !validTime(p.EnabledAt) {
		return ErrInvalid
	}
	if !p.Enabled && (len(p.Selectors) != 0 || !p.EnabledAt.IsZero() || p.RetentionAcknowledged) {
		return ErrInvalid
	}
	return nil
}

// SetPolicy is an explicit manager operation, not inferred source consent.
// Every change requires a new revision. Re-enabling/re-arming establishes a new
// no-backfill baseline; it cannot erase incidents or original identity binding.
func (s *State) SetPolicy(p Policy, now time.Time) error {
	now = now.UTC().Round(0)
	if s.Validate() != nil || p.Validate() != nil || !validTime(now) || p.Revision <= s.Policy.Revision || p.Enabled && !p.EnabledAt.Equal(now) || s.EvaluatedAt != nil && now.Before(*s.EvaluatedAt) {
		return ErrInvalid
	}
	c := s.clone()
	c.prune(now)
	c.Policy = p
	c.Policy.Selectors = append([]Selector{}, p.Selectors...)
	c.Floors = [2]Floor{}
	c.Sequence = 0
	c.CapturedAt = nil
	c.ReceivedAt = nil
	c.RearmRequired = false
	c.EvaluatedAt = ptr(now)
	c.Status = "disabled"
	if p.Enabled {
		c.Status = "baselining"
	} else {
		c.Policy.Selectors = []Selector{}
		c.Policy.EnabledAt = time.Time{}
		c.Policy.RetentionAcknowledged = false
	}
	return s.commit(c)
}
func (s State) clone() State {
	s.Policy.Selectors = append([]Selector{}, s.Policy.Selectors...)
	s.Incidents = append([]Incident{}, s.Incidents...)
	for i := range s.Incidents {
		if s.Incidents[i].ReviewedAt != nil {
			s.Incidents[i].ReviewedAt = ptr(*s.Incidents[i].ReviewedAt)
		}
	}
	if s.CapturedAt != nil {
		s.CapturedAt = ptr(*s.CapturedAt)
	}
	if s.ReceivedAt != nil {
		s.ReceivedAt = ptr(*s.ReceivedAt)
	}
	if s.EvaluatedAt != nil {
		s.EvaluatedAt = ptr(*s.EvaluatedAt)
	}
	return s
}
func (s *State) commit(c State) error {
	if _, e := Encode(c); e != nil {
		return e
	}
	*s = c
	return nil
}
func (s *State) Cleanup(now time.Time) error {
	if s.Validate() != nil || !validTime(now.UTC()) {
		return ErrInvalid
	}
	c := s.clone()
	c.prune(now)
	return s.commit(c)
}
func (s *State) prune(now time.Time) {
	out := []Incident{}
	for _, x := range s.Incidents {
		if now.Sub(x.LastReceivedAt) < Retention {
			out = append(out, x)
		}
	}
	s.Incidents = out
	if s.Status == "matched" {
		hasOpen := false
		for _, x := range out {
			hasOpen = hasOpen || x.ReviewedAt == nil
		}
		if !hasOpen {
			s.Status = "unknown"
		}
	}
}
func (s *State) Review(id string, now time.Time) error {
	now = now.UTC().Round(0)
	if s.Validate() != nil || !validTime(now) || s.EvaluatedAt != nil && now.Before(*s.EvaluatedAt) {
		return ErrInvalid
	}
	c := s.clone()
	c.prune(now)
	for i := range c.Incidents {
		x := &c.Incidents[i]
		if x.ID == id {
			if x.ReviewedAt != nil {
				return nil
			}
			if now.Before(x.LastReceivedAt) {
				return ErrInvalid
			}
			x.ReviewedAt = ptr(now)
			c.EvaluatedAt = ptr(now)
			if c.Status == "matched" {
				c.Status = "unknown"
			}
			return s.commit(c)
		}
	}
	return ErrInvalid
}
func (s State) authorized(in Input, now time.Time) bool {
	x := in.Source
	return x.Authorized && windowscontact.ValidDeviceID(x.DeviceID) && binding(x.InvitationID, x.CertificateHash) && validTime(x.AuthorityUntil.UTC()) && now.Before(x.AuthorityUntil) && (s.DeviceID == "" || s.DeviceID == x.DeviceID && s.InvitationID == x.InvitationID && s.CertificateHash == x.CertificateHash)
}

// Public never exposes durable dedup metadata and hides retained information
// when original identity/current authority do not match. Call Evaluate first
// when a fresh source is available; Public does not mutate evidence.
func (s State) Public(in Input, now time.Time) View {
	v := View{SchemaVersion: "tracebolt.windows-event-watch.v1", ServerNow: now.UTC(), Policy: Policy{Selectors: []Selector{}}, Status: "unknown", Incidents: []Incident{}}
	if s.Validate() != nil || !validTime(now.UTC()) || !s.authorized(in, now) {
		return v
	}
	c := s.clone()
	c.prune(now)
	v.Policy = c.Policy
	v.Status = c.Status
	v.Incidents = c.Incidents
	// Retained derived history does not extend the original periodic-header
	// private-view authority. Enforce its original capture boundary even when
	// an upstream caller has not stripped an expired or future snapshot.
	if in.Events == nil || windowseventhealth.Validate(*in.Events) != nil || in.Events.CollectedAt.After(now) || !now.Before(in.Events.CollectedAt.Add(24*time.Hour)) || s.GrantID != "" && in.Events.GrantID != s.GrantID {
		v.Status = "unknown"
		v.Policy = Policy{Selectors: []Selector{}}
		v.Incidents = []Incident{}
		return v
	}
	if !s.Policy.Enabled {
		v.Status = "disabled"
		return v
	}
	if !fresh(in.Source.ReceivedAt, now) || !fresh(in.Events.CollectedAt, now) || s.EvaluatedAt == nil || !fresh(*s.EvaluatedAt, now) || s.CapturedAt == nil || s.ReceivedAt == nil || in.Source.Sequence != s.Sequence || !in.Events.CollectedAt.Equal(*s.CapturedAt) || !in.Source.ReceivedAt.Equal(*s.ReceivedAt) {
		v.Status = "unknown"
	}
	return v
}
func fresh(t, now time.Time) bool { return validTime(t) && !t.After(now) && now.Sub(t) <= MaxAge }
func (s *State) Evaluate(in Input, now time.Time) error {
	if s.Validate() != nil || !validTime(now.UTC()) {
		return ErrInvalid
	}
	c := s.clone()
	if e := c.evaluate(in, now.UTC().Round(0)); e != nil {
		return e
	}
	return s.commit(c)
}
func (s *State) evaluate(in Input, now time.Time) error {
	s.prune(now)
	if !s.Policy.Enabled {
		s.Status = "disabled"
		return nil
	}
	s.Status = "unknown"
	if s.EvaluatedAt != nil && now.Before(*s.EvaluatedAt) {
		return nil
	}
	s.EvaluatedAt = ptr(now)
	if !s.authorized(in, now) {
		return nil
	}
	if in.Events == nil {
		return nil
	}
	e := in.Events
	x := in.Source
	if windowseventhealth.Validate(*e) != nil {
		return ErrInvalid
	}
	if s.RearmRequired {
		s.Status = "continuity-unknown"
		return nil
	}
	if s.GrantID != "" && s.GrantID != e.GrantID {
		s.RearmRequired = true
		s.Status = "continuity-unknown"
		return nil
	}
	if !fresh(x.ReceivedAt, now) || !fresh(e.CollectedAt, now) || e.CollectedAt.After(x.ReceivedAt) || s.Sequence > 0 && !e.CollectedAt.After(s.Policy.EnabledAt) || x.Sequence == 0 || x.Sequence > MaxCounter {
		return nil
	}
	if s.Sequence != 0 {
		if x.Sequence < s.Sequence || x.Sequence == s.Sequence && (!e.CollectedAt.Equal(*s.CapturedAt) || !x.ReceivedAt.Equal(*s.ReceivedAt)) {
			return nil
		}
		if x.Sequence == s.Sequence {
			s.statusFor(e)
			return nil
		}
		if !e.CollectedAt.After(*s.CapturedAt) || x.ReceivedAt.Before(*s.ReceivedAt) {
			return nil
		}
	}
	if s.DeviceID == "" {
		s.DeviceID = x.DeviceID
		s.InvitationID = x.InvitationID
		s.CertificateHash = x.CertificateHash
	}
	s.GrantID = e.GrantID
	// Detect log continuity loss before admitting any match in either channel.
	for i, c := range e.Channels {
		max := maxRecord(c)
		if s.Floors[i].Ready && len(c.Rows) > 0 && max < floorValue(s.Floors[i]) {
			s.RearmRequired = true
			s.Status = "continuity-unknown"
			return nil
		}
	}
	s.Sequence = x.Sequence
	s.CapturedAt = ptr(e.CollectedAt)
	s.ReceivedAt = ptr(x.ReceivedAt)
	for i, c := range e.Channels {
		if c.Quality == "denied" || c.Quality == "unavailable" {
			continue
		}
		f := &s.Floors[i]
		max := maxRecord(c)
		if !f.Ready {
			f.Ready = true
			f.RecordID = strconv.FormatUint(max, 10)
			continue
		}
		floor := floorValue(*f)
		for _, selector := range s.Policy.Selectors {
			if selector.Channel != c.Channel {
				continue
			}
			count := uint64(0)
			for _, r := range c.Rows {
				id, _ := strconv.ParseUint(r.RecordID, 10, 64)
				// Raw event time is used transiently only: delayed historical headers
				// and endpoint-clock uncertainty must not become post-consent incidents.
				if id > floor && r.Timestamp.After(s.Policy.EnabledAt) && !r.Timestamp.After(e.CollectedAt) && r.Provider == selector.Provider && r.EventID == selector.EventID && r.Level == selector.Level {
					count++
				}
			}
			if count == 0 {
				continue
			}
			found := false
			for n := range s.Incidents {
				incident := &s.Incidents[n]
				if incident.ReviewedAt == nil && incident.Selector == selector {
					incident.LastObservedAt = e.CollectedAt
					incident.LastReceivedAt = x.ReceivedAt
					if MaxCounter-incident.CountLowerBound < count {
						incident.CountLowerBound = MaxCounter
					} else {
						incident.CountLowerBound += count
					}
					found = true
					break
				}
			}
			if !found {
				if len(s.Incidents) >= MaxIncidents || s.NextID == MaxCounter {
					s.Status = "history-full"
					s.RearmRequired = true
					return nil
				}
				s.NextID++
				s.Incidents = append(s.Incidents, Incident{ID: fmt.Sprintf("wevent_%016x", s.NextID), Selector: selector, FirstObservedAt: e.CollectedAt, LastObservedAt: e.CollectedAt, FirstReceivedAt: x.ReceivedAt, LastReceivedAt: x.ReceivedAt, CountLowerBound: count})
			}
		}
		if max > floor {
			f.RecordID = strconv.FormatUint(max, 10)
		}
	}
	s.statusFor(e)
	return nil
}

// SourceToken is a non-authorizing identity/grant comparison token. It is not
// a capability, freshness proof, or substitute for the caller's authority lease.
func SourceToken(in Input) string {
	grant := ""
	if in.Events != nil {
		grant = in.Events.GrantID
	}
	b, _ := json.Marshal([]string{"tracebolt.windows-event-watch-source.v1", in.Source.DeviceID, in.Source.InvitationID, in.Source.CertificateHash, grant})
	h := sha256.Sum256(b)
	return "eventsource_" + hex.EncodeToString(h[:16])
}
func (s State) SourceMatches(in Input) bool {
	return s.DeviceID != "" && s.DeviceID == in.Source.DeviceID && s.InvitationID == in.Source.InvitationID && s.CertificateHash == in.Source.CertificateHash && in.Events != nil && s.GrantID != "" && s.GrantID == in.Events.GrantID
}

// Fresh checks the original source times, validated periodic scope, and current
// authority. It does not imply a match or continuity with any saved state.
func Fresh(in Input, now time.Time) bool {
	return validTime(now.UTC()) && New().authorized(in, now) && in.Events != nil && windowseventhealth.Validate(*in.Events) == nil && in.Source.Sequence > 0 && in.Source.Sequence <= MaxCounter && fresh(in.Source.ReceivedAt, now) && fresh(in.Events.CollectedAt, now) && !in.Events.CollectedAt.After(in.Source.ReceivedAt)
}
func (s *State) statusFor(e *windowseventhealth.Snapshot) {
	s.status()
	for _, selector := range s.Policy.Selectors {
		i := 0
		if selector.Channel == "System" {
			i = 1
		}
		if e.Channels[i].Quality == "denied" || e.Channels[i].Quality == "unavailable" || e.Channels[i].Quality == "partial" {
			s.Status = "unknown"
			return
		}
	}
}
func (s *State) status() {
	s.Status = "watching"
	for _, selector := range s.Policy.Selectors {
		i := 0
		if selector.Channel == "System" {
			i = 1
		}
		if !s.Floors[i].Ready {
			s.Status = "baselining"
			return
		}
	}
	for _, x := range s.Incidents {
		if x.ReviewedAt == nil {
			s.Status = "matched"
			return
		}
	}
}
func floorValue(f Floor) uint64 { v, _ := strconv.ParseUint(f.RecordID, 10, 64); return v }
func maxRecord(c windowseventhealth.Channel) uint64 {
	var max uint64
	for _, r := range c.Rows {
		n, _ := strconv.ParseUint(r.RecordID, 10, 64)
		if n > max {
			max = n
		}
	}
	return max
}

func (s State) Validate() error {
	if s.Version != 1 || s.Policy.Validate() != nil || s.Incidents == nil || len(s.Incidents) > MaxIncidents || s.Sequence > MaxCounter || s.NextID > MaxCounter {
		return ErrInvalid
	}
	switch s.Status {
	case "disabled", "unknown", "baselining", "watching", "matched", "continuity-unknown", "history-full":
	default:
		return ErrInvalid
	}
	if s.DeviceID == "" {
		if s.InvitationID != "" || s.CertificateHash != "" || s.GrantID != "" || s.Sequence != 0 || len(s.Incidents) != 0 {
			return ErrInvalid
		}
	} else if !windowscontact.ValidDeviceID(s.DeviceID) || !binding(s.InvitationID, s.CertificateHash) {
		return ErrInvalid
	}
	if len(s.Incidents) > 0 && s.GrantID == "" || s.GrantID != "" && !isHex(s.GrantID, 32) {
		return ErrInvalid
	}
	if (s.Sequence == 0) != (s.CapturedAt == nil) || (s.Sequence == 0) != (s.ReceivedAt == nil) || s.Sequence > 0 && s.GrantID == "" {
		return ErrInvalid
	}
	for _, t := range []*time.Time{s.CapturedAt, s.ReceivedAt, s.EvaluatedAt} {
		if t != nil && !validTime(*t) {
			return ErrInvalid
		}
	}
	if s.CapturedAt != nil && (s.CapturedAt.After(*s.ReceivedAt) || s.EvaluatedAt == nil || s.ReceivedAt.After(*s.EvaluatedAt)) {
		return ErrInvalid
	}
	for _, f := range s.Floors {
		if !f.Ready {
			if f.RecordID != "" {
				return ErrInvalid
			}
		} else {
			n, e := strconv.ParseUint(f.RecordID, 10, 64)
			if e != nil || strconv.FormatUint(n, 10) != f.RecordID || s.Sequence == 0 {
				return ErrInvalid
			}
		}
	}
	if !s.Policy.Enabled && (s.Status != "disabled" || s.Sequence != 0 || s.RearmRequired) {
		return ErrInvalid
	}
	if s.RearmRequired && s.Status != "continuity-unknown" && s.Status != "unknown" && s.Status != "history-full" {
		return ErrInvalid
	}
	seen := map[string]bool{}
	open := map[Selector]bool{}
	for _, x := range s.Incidents {
		n, e := strconv.ParseUint(strings.TrimPrefix(x.ID, "wevent_"), 16, 64)
		if e != nil || n == 0 || n > s.NextID || x.ID != fmt.Sprintf("wevent_%016x", n) || seen[x.ID] || x.Selector.Validate() != nil || x.CountLowerBound == 0 || x.CountLowerBound > MaxCounter {
			return ErrInvalid
		}
		seen[x.ID] = true
		for _, t := range []time.Time{x.FirstObservedAt, x.LastObservedAt, x.FirstReceivedAt, x.LastReceivedAt} {
			if !validTime(t) {
				return ErrInvalid
			}
		}
		if s.EvaluatedAt == nil || x.LastReceivedAt.After(*s.EvaluatedAt) {
			return ErrInvalid
		}
		if x.FirstObservedAt.After(x.LastObservedAt) || x.FirstReceivedAt.After(x.LastReceivedAt) || x.FirstObservedAt.After(x.FirstReceivedAt) || x.LastObservedAt.After(x.LastReceivedAt) {
			return ErrInvalid
		}
		if x.ReviewedAt != nil {
			if !validTime(*x.ReviewedAt) || x.ReviewedAt.Before(x.LastReceivedAt) || x.ReviewedAt.After(*s.EvaluatedAt) {
				return ErrInvalid
			}
		} else {
			if open[x.Selector] {
				return ErrInvalid
			}
			open[x.Selector] = true
		}
	}
	return nil
}
func Encode(s State) ([]byte, error) {
	if s.Validate() != nil {
		return nil, ErrInvalid
	}
	b, e := json.Marshal(s)
	if e != nil || len(b) > MaxStateBytes {
		return nil, ErrInvalid
	}
	return b, nil
}
func Decode(b []byte) (State, error) {
	var s State
	if len(b) == 0 || len(b) > MaxStateBytes || !utf8.Valid(b) {
		return State{}, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF {
		return State{}, ErrInvalid
	}
	out, e := Encode(s)
	if e != nil || !bytes.Equal(out, b) {
		return State{}, ErrInvalid
	}
	return s, nil
}
