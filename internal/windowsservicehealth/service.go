// Package windowsservicehealth checks explicit should-be-running selections using only
// positive rows in accepted, caller-visible Windows metadata. It has no native,
// action, notification or AI capability. Names are exact report keys, not service
// instance identities. Missing rows never establish absence or a stopped state.
package windowsservicehealth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsmanaged"
)

const (
	SchemaVersion = "tracebolt.windows-service-view.v1"
	StateSchema   = "tracebolt.windows-service-state.v1"
	MaxAge        = 120 * time.Second
	Confirmation  = 120 * time.Second
	Recovery      = 60 * time.Second
	MaxGap        = 90 * time.Second
	Retention     = 30 * 24 * time.Hour
	MaxServices   = 8
	MaxDevices    = 25
	MaxIncidents  = 100
	MaxStateBytes = 256 << 10
	MaxCounter    = uint64(1<<53 - 1)
)

var ErrInvalid = errors.New("windows_service_invalid")

type Sample struct {
	CollectedAt time.Time
	Services    windowsmanaged.Section[windowsmanaged.Service]
	Complete    *CompleteSample
}
type Input struct {
	windowscontact.Input
	Sample      Sample
	Complete    bool
	CurrentLeaf string
	Selection   *Provenance
}
type Policy struct {
	Enabled  bool           `json:"enabled"`
	Services []string       `json:"services"`
	Revision uint64         `json:"revision"`
	Source   *SourceBinding `json:"source,omitempty"`
}
type Observation struct {
	State       string      `json:"state"`
	CollectedAt time.Time   `json:"collectedAt"`
	ReceivedAt  time.Time   `json:"receivedAt"`
	Sequence    uint64      `json:"sequence"`
	Source      *Provenance `json:"source,omitempty"`
}
type Check struct {
	Name        string       `json:"name"`
	Status      string       `json:"status"`
	Observation *Observation `json:"observation"`
}
type Progress struct {
	Check
	Since *time.Time   `json:"since"`
	Start *Observation `json:"start"`
}
type Incident struct {
	ID                  string       `json:"id"`
	Name                string       `json:"name"`
	PolicyRevision      uint64       `json:"policyRevision"`
	OpenedAt            time.Time    `json:"openedAt"`
	LastConfirmedAt     time.Time    `json:"lastConfirmedAt"`
	OpeningObservation  Observation  `json:"openingObservation"`
	LastBadObservation  Observation  `json:"lastBadObservation"`
	ResolvedAt          *time.Time   `json:"resolvedAt"`
	RecoveryObservation *Observation `json:"recoveryObservation"`
	ClosedReason        string       `json:"closedReason"`
}
type State struct {
	SchemaVersion   string      `json:"schemaVersion"`
	DeviceID        string      `json:"deviceId"`
	InvitationID    string      `json:"invitationId"`
	CertificateHash string      `json:"certificateHash"`
	Policy          Policy      `json:"policy"`
	PolicyChangedAt *time.Time  `json:"policyChangedAt"`
	Epoch           string      `json:"epoch"`
	EvaluatedAt     *time.Time  `json:"evaluatedAt"`
	Checks          []Progress  `json:"checks"`
	SequenceFloor   uint64      `json:"sequenceFloor"`
	ReceiptFloor    *time.Time  `json:"receiptFloor"`
	CaptureFloor    *time.Time  `json:"captureFloor"`
	Incidents       []Incident  `json:"incidents"`
	NextID          uint64      `json:"nextId"`
	SourceFloor     *Provenance `json:"sourceFloor,omitempty"`
}
type Choice struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
}
type Inventory struct {
	CollectedAt   time.Time   `json:"collectedAt"`
	ReceivedAt    time.Time   `json:"receivedAt"`
	Sequence      uint64      `json:"sequence"`
	Quality       string      `json:"quality"`
	Complete      bool        `json:"complete"`
	Truncated     bool        `json:"truncated"`
	CountExact    bool        `json:"countExact"`
	ObservedCount uint32      `json:"observedCount"`
	Services      []Choice    `json:"services"`
	Source        *Provenance `json:"source,omitempty"`
}
type View struct {
	SchemaVersion        string     `json:"schemaVersion"`
	DeviceID             string     `json:"deviceId"`
	ServerNow            time.Time  `json:"serverNow"`
	CertificateExpiresAt time.Time  `json:"certificateExpiresAt"`
	Policy               Policy     `json:"policy"`
	Status               string     `json:"status"`
	EvaluatedAt          *time.Time `json:"evaluatedAt"`
	Checks               []Check    `json:"checks"`
	Incidents            []Incident `json:"incidents"`
	Inventory            *Inventory `json:"inventory"`
}

func New() State {
	return State{SchemaVersion: StateSchema, Policy: Policy{Services: []string{}}, Checks: []Progress{}, Incidents: []Incident{}}
}
func stamp(t time.Time) *time.Time { t = t.UTC().Round(0); return &t }
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Location() == time.UTC
}
func optional(t *time.Time) bool  { return t == nil || validTime(*t) }
func Fresh(t, now time.Time) bool { return validTime(t) && !t.After(now) && now.Sub(t) <= MaxAge }
func validText(s string, required bool) bool {
	return (!required || strings.TrimSpace(s) != "") && len(s) <= windowsmanaged.MaxTextBytes && utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError || r == '\u2028' || r == '\u2029'
	}) < 0
}
func Services(names []string) ([]string, error) {
	if names == nil || len(names) > MaxServices {
		return nil, ErrInvalid
	}
	out := append([]string{}, names...)
	sort.Strings(out)
	for i, n := range out {
		if !validText(n, true) || i > 0 && out[i-1] == n {
			return nil, ErrInvalid
		}
	}
	return out, nil
}
func nativeState(s string) bool {
	switch s {
	case "running", "stopped", "paused", "start_pending", "stop_pending", "continue_pending", "pause_pending":
		return true
	}
	return false
}
func bad(s string) bool { return s == "stopped" || s == "paused" }
func (in Input) authorized(now time.Time) bool {
	return in.Authorized && validTime(in.AuthorityUntil) && now.Before(in.AuthorityUntil)
}

// The accepted wire permits partial positive rows and duplicate exact names.
// Validate quality/truncation invariants but never convert scoped counts to host
// coverage. Omit every ambiguous name, even if duplicate rows happen to agree.
func (in Input) Inventory(now time.Time) *Inventory {
	if in.Complete {
		return in.completeInventory(now)
	}
	s := in.Sample.Services
	if !in.authorized(now) || !Fresh(in.Sample.CollectedAt, now) || !Fresh(in.ReceivedAt, now) || in.Sequence == 0 || in.Sequence > MaxCounter || s.Rows == nil || len(s.Rows) > windowsmanaged.MaxServiceRows || s.ObservedCount > 2048 || int(s.ObservedCount) < len(s.Rows) || int(s.ObservedCount) > len(s.Rows) && !s.Truncated {
		return nil
	}
	switch s.Quality {
	case "healthy":
		if !s.Complete || !s.CountExact || s.Truncated || int(s.ObservedCount) != len(s.Rows) {
			return nil
		}
	case "partial":
		if s.Complete || s.CountExact && (!s.Truncated || int(s.ObservedCount) == len(s.Rows)) {
			return nil
		}
	default:
		return nil
	}
	counts := map[string]int{}
	for _, r := range s.Rows {
		if !validText(r.Name, true) || !validText(r.DisplayName, false) || !nativeState(r.State) {
			return nil
		}
		counts[r.Name]++
	}
	rows := []Choice{}
	for _, r := range s.Rows {
		if counts[r.Name] == 1 {
			rows = append(rows, Choice{r.Name, r.DisplayName, r.State})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return &Inventory{CollectedAt: in.Sample.CollectedAt, ReceivedAt: in.ReceivedAt, Sequence: in.Sequence, Quality: s.Quality, Complete: s.Complete, Truncated: s.Truncated, CountExact: s.CountExact, ObservedCount: s.ObservedCount, Services: rows}
}
func observation(inv *Inventory, name string) *Observation {
	if inv == nil {
		return nil
	}
	for _, r := range inv.Services {
		if r.Name == name && (r.State == "running" || bad(r.State)) {
			return &Observation{State: r.State, CollectedAt: inv.CollectedAt, ReceivedAt: inv.ReceivedAt, Sequence: inv.Sequence, Source: inv.Source}
		}
	}
	return nil
}
func (s State) binding(in Input) bool {
	return s.DeviceID == in.DeviceID && s.InvitationID == in.InvitationID && s.CertificateHash == in.CertificateHash
}
func (s *State) bind(in Input) error {
	if !windowscontact.ValidDeviceID(in.DeviceID) || !enrollmentcrypto.ValidID(in.InvitationID, "invite_") || !enrollmentcrypto.ValidHash(in.CertificateHash) || s.DeviceID != "" && !s.binding(in) {
		return ErrInvalid
	}
	s.DeviceID = in.DeviceID
	s.InvitationID = in.InvitationID
	s.CertificateHash = in.CertificateHash
	return nil
}
func (s *State) reset() {
	for i := range s.Checks {
		s.Checks[i] = Progress{Check: Check{Name: s.Checks[i].Name, Status: "unknown"}}
	}
}
func (s *State) open(name string) *Incident {
	for i := range s.Incidents {
		if s.Incidents[i].Name == name && s.Incidents[i].ResolvedAt == nil {
			return &s.Incidents[i]
		}
	}
	return nil
}
func (s *State) transition(change func(*State) error) error {
	raw, e := Encode(*s)
	if e != nil {
		return e
	}
	copy, e := Decode(raw)
	if e != nil {
		return e
	}
	if e = change(&copy); e != nil {
		return e
	}
	if _, e := Encode(copy); e != nil {
		return ErrInvalid
	}
	*s = copy
	return nil
}
func (s *State) Configure(in Input, enabled bool, names []string, expected uint64, now time.Time) error {
	return s.transition(func(c *State) error {
		if in.Complete && !c.complete() {
			if c.DeviceID != "" || c.Policy.Revision != 0 {
				return ErrInvalid
			}
			c.SchemaVersion = CompleteStateSchema
		}
		if c.complete() != in.Complete {
			return ErrInvalid
		}
		names, e := c.names(names)
		if e != nil || enabled && len(names) == 0 || !validTime(now) || !in.authorized(now) || expected != c.Policy.Revision || expected >= MaxCounter || c.EvaluatedAt != nil && now.Before(*c.EvaluatedAt) || c.PolicyChangedAt != nil && now.Before(*c.PolicyChangedAt) {
			return ErrInvalid
		}
		if e = c.bind(in); e != nil {
			return e
		}
		unchanged := strings.Join(names, "\x00") == strings.Join(c.Policy.Services, "\x00")
		sourceChanged := false
		var selectedSource *SourceBinding
		if c.complete() {
			selectedSource = c.Policy.Source
			if in.Selection != nil {
				inv := in.Inventory(now)
				if inv == nil || inv.Source == nil || *inv.Source != *in.Selection {
					return ErrInvalid
				}
				binding := in.Selection.Binding()
				selectedSource = &binding
				sourceChanged = c.Policy.Source == nil || *c.Policy.Source != binding
			}
			if selectedSource == nil && (enabled || len(names) > 0) {
				return ErrInvalid
			}
		}
		if unchanged && enabled == c.Policy.Enabled && !sourceChanged {
			return nil
		}
		// Existing names may always be removed/disabled under live authority. New names
		// and re-enablement require current unambiguous positive metadata.
		inv := in.Inventory(now)
		known := map[string]bool{}
		if inv != nil {
			for _, r := range inv.Services {
				known[r.Name] = true
			}
		}
		old := map[string]bool{}
		for _, n := range c.Policy.Services {
			old[n] = true
		}
		for _, n := range names {
			if !old[n] || enabled && !c.Policy.Enabled || sourceChanged {
				if !known[n] || c.complete() && (in.Selection == nil || selectedSource == nil || in.Selection.Binding() != *selectedSource) {
					return ErrInvalid
				}
			}
		}
		for i := range c.Incidents {
			if c.Incidents[i].ResolvedAt == nil {
				c.Incidents[i].ResolvedAt = stamp(now)
				c.Incidents[i].ClosedReason = "policy-changed"
			}
		}
		c.Policy = Policy{Enabled: enabled, Services: names, Revision: expected + 1, Source: selectedSource}
		c.PolicyChangedAt = stamp(now)
		c.Epoch = ""
		c.EvaluatedAt = nil
		c.Checks = []Progress{}
		for _, n := range names {
			c.Checks = append(c.Checks, Progress{Check: Check{Name: n, Status: "unknown"}})
		}
		c.prune(now)
		return nil
	})
}
func (s *State) Evaluate(in Input, now time.Time, epoch string) error {
	in.Complete = s.complete()
	in = in.normalized()
	return s.transition(func(c *State) error {
		if !validTime(now) || !windowscontact.ValidEpoch(epoch) || !windowscontact.ValidDeviceID(in.DeviceID) {
			return ErrInvalid
		}
		if !c.Policy.Enabled {
			return nil
		}
		if !c.binding(in) || c.EvaluatedAt != nil && now.Before(*c.EvaluatedAt) {
			return ErrInvalid
		}
		if c.Epoch != epoch || c.EvaluatedAt == nil || now.Sub(*c.EvaluatedAt) > MaxGap {
			c.reset()
		}
		c.Epoch = epoch
		c.EvaluatedAt = stamp(now)
		inv := in.Inventory(now)
		if c.complete() && (inv == nil || inv.Source == nil || c.Policy.Source == nil || inv.Source.Binding() != *c.Policy.Source) {
			inv = nil
		}
		sourceOK := !c.complete() || in.Sample.Complete != nil && in.Sample.Complete.Source.Valid()
		if c.complete() && sourceOK && c.SourceFloor != nil && in.Sequence == c.SequenceFloor && in.Sample.Complete.Source != *c.SourceFloor {
			sourceOK = false
		}
		monotonic := sourceOK && in.authorized(now) && in.Sequence > 0 && in.Sequence <= MaxCounter && validTime(in.ReceivedAt) && !in.ReceivedAt.After(now)
		if monotonic && c.ReceiptFloor != nil {
			monotonic = in.Sequence >= c.SequenceFloor && !in.ReceivedAt.Before(*c.ReceiptFloor) && (in.Sequence != c.SequenceFloor || in.ReceivedAt.Equal(*c.ReceiptFloor))
		}
		if monotonic {
			c.SequenceFloor = in.Sequence
			c.ReceiptFloor = stamp(in.ReceivedAt)
			if c.complete() {
				p := in.Sample.Complete.Source
				c.SourceFloor = &p
			}
		} else {
			inv = nil
		}
		if validTime(in.Sample.CollectedAt) && !in.Sample.CollectedAt.After(now) {
			if c.CaptureFloor != nil && in.Sample.CollectedAt.Before(*c.CaptureFloor) {
				inv = nil
			} else if monotonic {
				c.CaptureFloor = stamp(in.Sample.CollectedAt)
			}
		}
		if c.PolicyChangedAt != nil && now.Before(*c.PolicyChangedAt) {
			inv = nil
		}
		for i := range c.Checks {
			p := &c.Checks[i]
			o := observation(inv, p.Name)
			if o == nil {
				*p = Progress{Check: Check{Name: p.Name, Status: "unknown"}}
				continue
			}
			p.Observation = o
			incident := c.open(p.Name)
			if incident == nil && !bad(o.State) {
				p.Status = "running"
				p.Since = nil
				p.Start = nil
				continue
			}
			p.Status = "pending"
			duration := Confirmation
			if incident != nil {
				p.Status = "attention"
				duration = Recovery
				if bad(o.State) {
					if o.Sequence > incident.LastBadObservation.Sequence && o.CollectedAt.After(incident.LastBadObservation.CollectedAt) {
						incident.LastBadObservation = *o
						incident.LastConfirmedAt = now
					}
					p.Since = nil
					p.Start = nil
					continue
				}
				if o.Sequence <= incident.LastBadObservation.Sequence || !o.CollectedAt.After(incident.LastBadObservation.CollectedAt) {
					p.Since = nil
					p.Start = nil
					continue
				}
			}
			if p.Since == nil {
				p.Since = stamp(now)
				p.Start = o
			}
			if now.Sub(*p.Since) < duration || o.Sequence <= p.Start.Sequence || o.CollectedAt.Sub(p.Start.CollectedAt) < duration {
				continue
			}
			if incident == nil {
				if c.NextID >= MaxCounter {
					return ErrInvalid
				}
				c.NextID++
				c.Incidents = append([]Incident{{ID: fmt.Sprintf("wservice_%016x", c.NextID), Name: p.Name, PolicyRevision: c.Policy.Revision, OpenedAt: now, LastConfirmedAt: now, OpeningObservation: *o, LastBadObservation: *o}}, c.Incidents...)
				p.Status = "attention"
			} else {
				incident.ResolvedAt = stamp(now)
				incident.RecoveryObservation = o
				incident.ClosedReason = "running"
				p.Status = "running"
			}
			p.Since = nil
			p.Start = nil
		}
		c.prune(now)
		return nil
	})
}
func (s *State) prune(now time.Time) {
	out := []Incident{}
	for _, r := range s.Incidents {
		if r.ResolvedAt == nil || now.Sub(*r.ResolvedAt) <= Retention {
			out = append(out, r)
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
		}
	}
	s.Incidents = out
	// Full provenance is intentionally retained per historical observation.
	// Under the same durable byte cap, remove only oldest closed episodes;
	// open episodes, floors and exact policy identity can never be truncated.
	if s.complete() {
		for {
			raw, e := json.Marshal(s)
			if e != nil || len(raw) <= MaxStateBytes {
				break
			}
			removed := false
			for i := len(s.Incidents) - 1; i >= 0; i-- {
				if s.Incidents[i].ResolvedAt != nil {
					s.Incidents = append(s.Incidents[:i], s.Incidents[i+1:]...)
					removed = true
					break
				}
			}
			if !removed {
				break
			}
		}
	}
}
func (s State) View(in Input, now time.Time, epoch string) View {
	in.Complete = s.complete()
	in = in.normalized()
	inv := in.Inventory(now)
	if s.complete() && inv != nil {
		selected := []Choice{}
		for _, row := range inv.Services {
			if contains(s.Policy.Services, row.Name) {
				selected = append(selected, row)
			}
		}
		inv.Services = selected
	}
	checks := []Check{}
	status := "running"
	if !s.Policy.Enabled {
		status = "disabled"
	}
	for _, p := range s.Checks {
		c := p.Check
		current := observation(inv, c.Name)
		if s.complete() && (inv == nil || inv.Source == nil || s.Policy.Source == nil || inv.Source.Binding() != *s.Policy.Source) {
			current = nil
		}
		if !s.Policy.Enabled || s.Epoch != epoch || epoch == "" || s.EvaluatedAt == nil || !Fresh(*s.EvaluatedAt, now) || !s.binding(in) || c.Observation == nil || current == nil || !sameObservation(*current, *c.Observation) {
			c.Status = "unknown"
			c.Observation = nil
		}
		checks = append(checks, c)
	}
	if s.Policy.Enabled {
		for _, v := range []string{"unknown", "pending", "attention"} {
			for _, c := range checks {
				if c.Status == v {
					status = v
					break
				}
			}
		}
	}
	schema := SchemaVersion
	if s.complete() {
		schema = CompleteSchemaVersion
	}
	return View{schema, in.DeviceID, now, in.AuthorityUntil, s.Policy, status, s.EvaluatedAt, checks, append([]Incident{}, s.Incidents...), inv}
}
func validObservation(o Observation, at time.Time) bool {
	return (o.State == "running" || bad(o.State)) && o.Sequence > 0 && o.Sequence <= MaxCounter && Fresh(o.CollectedAt, at) && Fresh(o.ReceivedAt, at)
}
func (s State) Validate() error {
	names, e := s.names(s.Policy.Services)
	if !s.complete() && (s.Policy.Source != nil || s.SourceFloor != nil) {
		return ErrInvalid
	}
	if s.complete() {
		if s.Policy.Source != nil && (s.Policy.Source.Kind != CompleteSourceKind || !validBinding(*s.Policy.Source)) {
			return ErrInvalid
		}
		if s.Policy.Revision > 0 && (s.Policy.Enabled || len(s.Policy.Services) > 0) && s.Policy.Source == nil {
			return ErrInvalid
		}
		if (s.SourceFloor == nil) != (s.SequenceFloor == 0) {
			return ErrInvalid
		}
		if s.SourceFloor != nil && (!s.SourceFloor.Valid() || s.SourceFloor.Sequence != s.SequenceFloor || s.ReceiptFloor == nil || !s.SourceFloor.ReceivedAt.Equal(*s.ReceiptFloor)) {
			return ErrInvalid
		}
	}
	if e != nil || !equalNames(names, s.Policy.Services) || (s.SchemaVersion != StateSchema && s.SchemaVersion != CompleteStateSchema) || s.Policy.Revision > MaxCounter || s.Policy.Enabled && (s.Policy.Revision == 0 || len(names) == 0) || s.Checks == nil || len(s.Checks) != len(names) || s.Incidents == nil || len(s.Incidents) > MaxIncidents || s.NextID > MaxCounter || !optional(s.PolicyChangedAt) || !optional(s.EvaluatedAt) || !optional(s.ReceiptFloor) || !optional(s.CaptureFloor) {
		return ErrInvalid
	}
	if s.DeviceID == "" {
		if s.Policy.Source != nil || s.SourceFloor != nil {
			return ErrInvalid
		}
		if s.InvitationID != "" || s.CertificateHash != "" || s.Policy.Revision != 0 || s.Policy.Enabled || s.PolicyChangedAt != nil || s.EvaluatedAt != nil || s.Epoch != "" || len(names) != 0 || len(s.Incidents) != 0 || s.NextID != 0 || s.SequenceFloor != 0 || s.ReceiptFloor != nil || s.CaptureFloor != nil {
			return ErrInvalid
		}
		return nil
	}
	if !windowscontact.ValidDeviceID(s.DeviceID) || !enrollmentcrypto.ValidID(s.InvitationID, "invite_") || !enrollmentcrypto.ValidHash(s.CertificateHash) || s.Policy.Revision > 0 && s.PolicyChangedAt == nil || (s.EvaluatedAt == nil) != (s.Epoch == "") || s.Epoch != "" && !windowscontact.ValidEpoch(s.Epoch) || s.SequenceFloor > MaxCounter || (s.SequenceFloor == 0) != (s.ReceiptFloor == nil) || s.CaptureFloor != nil && s.ReceiptFloor == nil {
		return ErrInvalid
	}
	if s.complete() && s.SourceFloor != nil {
		g, e := generationFor(s.DeviceID, *s.SourceFloor)
		if e != nil || g != s.SourceFloor.GenerationID {
			return ErrInvalid
		}
	}
	at := s.PolicyChangedAt
	if s.EvaluatedAt != nil && (at == nil || s.EvaluatedAt.After(*at)) {
		at = s.EvaluatedAt
	}
	if s.ReceiptFloor != nil && (at == nil || s.ReceiptFloor.After(*at)) || s.CaptureFloor != nil && (at == nil || s.CaptureFloor.After(*at)) {
		return ErrInvalid
	}
	open := map[string]bool{}
	previous := s.NextID + 1
	for _, r := range s.Incidents {
		var n uint64
		if (r.OpeningObservation.Source != nil) != s.complete() || (r.LastBadObservation.Source != nil) != s.complete() || r.RecoveryObservation != nil && (r.RecoveryObservation.Source != nil) != s.complete() {
			return ErrInvalid
		}
		if _, e := fmt.Sscanf(r.ID, "wservice_%x", &n); e != nil || r.ID != fmt.Sprintf("wservice_%016x", n) || n == 0 || n >= previous || n > s.NextID || !s.validName(r.Name) || r.PolicyRevision == 0 || r.PolicyRevision > s.Policy.Revision || !validTime(r.OpenedAt) || !validTime(r.LastConfirmedAt) || at == nil || r.LastConfirmedAt.Before(r.OpenedAt) || r.LastConfirmedAt.After(*at) || !s.validEvidence(r.OpeningObservation, r.OpenedAt) || !bad(r.OpeningObservation.State) || !s.validEvidence(r.LastBadObservation, r.LastConfirmedAt) || !bad(r.LastBadObservation.State) || r.LastBadObservation.Sequence < r.OpeningObservation.Sequence || r.LastBadObservation.CollectedAt.Before(r.OpeningObservation.CollectedAt) {
			return ErrInvalid
		}
		if s.complete() && (r.OpeningObservation.Source.Binding() != r.LastBadObservation.Source.Binding() || r.RecoveryObservation != nil && r.RecoveryObservation.Source.Binding() != r.LastBadObservation.Source.Binding() || r.ResolvedAt == nil && (s.Policy.Source == nil || r.LastBadObservation.Source.Binding() != *s.Policy.Source)) {
			return ErrInvalid
		}
		previous = n
		if r.ResolvedAt == nil {
			if open[r.Name] || !s.Policy.Enabled || r.PolicyRevision != s.Policy.Revision || !contains(names, r.Name) || r.ClosedReason != "" || r.RecoveryObservation != nil {
				return ErrInvalid
			}
			open[r.Name] = true
		} else {
			if !validTime(*r.ResolvedAt) || r.ResolvedAt.Before(r.LastConfirmedAt) || r.ResolvedAt.After(*at) {
				return ErrInvalid
			}
			switch r.ClosedReason {
			case "policy-changed":
				if r.RecoveryObservation != nil || r.PolicyRevision >= s.Policy.Revision {
					return ErrInvalid
				}
			case "running":
				o := r.RecoveryObservation
				if o == nil || !s.validEvidence(*o, *r.ResolvedAt) || o.State != "running" || o.Sequence <= r.LastBadObservation.Sequence || !o.CollectedAt.After(r.LastBadObservation.CollectedAt) {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
		}
	}
	for i, p := range s.Checks {
		if p.Name != names[i] || !optional(p.Since) || (p.Since == nil) != (p.Start == nil) {
			return ErrInvalid
		}
		if p.Observation != nil && ((p.Observation.Source != nil) != s.complete()) {
			return ErrInvalid
		}
		if p.Observation != nil && (s.EvaluatedAt == nil || !s.validEvidence(*p.Observation, *s.EvaluatedAt) || s.ReceiptFloor == nil || s.CaptureFloor == nil || p.Observation.Sequence != s.SequenceFloor || !p.Observation.ReceivedAt.Equal(*s.ReceiptFloor) || !p.Observation.CollectedAt.Equal(*s.CaptureFloor)) {
			return ErrInvalid
		}
		if p.Start != nil && (s.EvaluatedAt == nil || p.Since.After(*s.EvaluatedAt) || !s.validEvidence(*p.Start, *p.Since) || p.Observation == nil || p.Start.Sequence > p.Observation.Sequence || p.Start.CollectedAt.After(p.Observation.CollectedAt)) {
			return ErrInvalid
		}
		if s.complete() && p.Observation != nil && (s.SourceFloor == nil || *p.Observation.Source != *s.SourceFloor || s.Policy.Source == nil || p.Observation.Source.Binding() != *s.Policy.Source || p.Start != nil && p.Start.Source.Binding() != p.Observation.Source.Binding()) {
			return ErrInvalid
		}
		if !s.Policy.Enabled && (p.Status != "unknown" || p.Observation != nil || p.Since != nil) {
			return ErrInvalid
		}
		switch p.Status {
		case "unknown":
			if p.Observation != nil || p.Since != nil {
				return ErrInvalid
			}
		case "running":
			if !s.Policy.Enabled || p.Observation == nil || p.Observation.State != "running" || p.Since != nil || open[p.Name] {
				return ErrInvalid
			}
		case "pending":
			if !s.Policy.Enabled || p.Observation == nil || !bad(p.Observation.State) || p.Start == nil || !bad(p.Start.State) || open[p.Name] {
				return ErrInvalid
			}
		case "attention":
			if !s.Policy.Enabled || p.Observation == nil || !open[p.Name] || p.Start != nil && p.Start.State != "running" {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	return nil
}
func equalNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func contains(a []string, n string) bool {
	for _, v := range a {
		if v == n {
			return true
		}
	}
	return false
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
	if len(b) == 0 || len(b) > MaxStateBytes {
		return State{}, ErrInvalid
	}
	var s State
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF {
		return State{}, ErrInvalid
	}
	canonical, e := Encode(s)
	if e != nil || !bytes.Equal(b, canonical) {
		return State{}, ErrInvalid
	}
	return s, nil
}
