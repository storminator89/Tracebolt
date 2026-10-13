// Package windowscapacity evaluates an explicitly enabled manager policy against
// existing caller-visible, quota-aware Windows system-volume percentage samples.
// It has no collector, service-action, AI or alarm-delivery authority.
package windowscapacity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/model"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsservicehealth"
)

const (
	MaxAge        = 120 * time.Second
	Confirmation  = 60 * time.Second
	MaxGap        = 90 * time.Second
	Retention     = 30 * 24 * time.Hour
	MaxIncidents  = 100
	MaxDevices    = 25
	MaxStateBytes = 128 << 10
	MaxCounter    = uint64(1<<53 - 1)
	SchemaVersion = "tracebolt.windows-capacity-view.v1"
)

var ErrInvalid = errors.New("windows_capacity_invalid")
var incidentPattern = regexp.MustCompile(`^wcapacity_[0-9a-f]{16}$`)

// Input is deliberately separate from Linux HealthInputs and provider admission.
type Input struct {
	windowscontact.Input
	CurrentLeaf string
	Disk        model.Metric
	// Already-consented basic samples, selected only by the resource policy adapter.
	CPU    model.Metric
	Memory model.Metric
	// Service metadata shares this accepted-source transaction, not the percentage engine.
	Services windowsservicehealth.Sample
}
type Policy struct {
	Enabled          bool   `json:"enabled"`
	ThresholdPercent int    `json:"thresholdPercent"`
	Revision         uint64 `json:"revision"`
}
type Observation struct {
	Value       float64   `json:"value"`
	CollectedAt time.Time `json:"collectedAt"`
	ReceivedAt  time.Time `json:"receivedAt"`
	Sequence    uint64    `json:"sequence"`
}
type Incident struct {
	ID                  string       `json:"id"`
	PolicyRevision      uint64       `json:"policyRevision"`
	ThresholdPercent    int          `json:"thresholdPercent"`
	OpenedAt            time.Time    `json:"openedAt"`
	LastConfirmedAt     time.Time    `json:"lastConfirmedAt"`
	OpeningObservation  Observation  `json:"openingObservation"`
	LastHighObservation Observation  `json:"lastHighObservation"`
	ResolvedAt          *time.Time   `json:"resolvedAt"`
	RecoveryObservation *Observation `json:"recoveryObservation"`
	ClosedReason        string       `json:"closedReason"`
}
type State struct {
	Version            int          `json:"version"`
	DeviceID           string       `json:"deviceId"`
	InvitationID       string       `json:"invitationId"`
	CertificateHash    string       `json:"certificateHash"`
	Epoch              string       `json:"epoch"`
	Policy             Policy       `json:"policy"`
	PolicyChangedAt    *time.Time   `json:"policyChangedAt"`
	Status             string       `json:"status"`
	EvaluatedAt        *time.Time   `json:"evaluatedAt"`
	Observation        *Observation `json:"observation"`
	PendingSince       *time.Time   `json:"pendingSince"`
	RecoverySince      *time.Time   `json:"recoverySince"`
	PendingObservation *Observation `json:"pendingObservation"`
	RecoveryStart      *Observation `json:"recoveryStart"`
	SequenceFloor      uint64       `json:"sequenceFloor"`
	ReceiptFloor       *time.Time   `json:"receiptFloor"`
	CaptureFloor       *time.Time   `json:"captureFloor"`
	Incidents          []Incident   `json:"incidents"`
	NextID             uint64       `json:"nextId"`
}
type View struct {
	SchemaVersion        string       `json:"schemaVersion"`
	DeviceID             string       `json:"deviceId"`
	ServerNow            time.Time    `json:"serverNow"`
	CertificateExpiresAt time.Time    `json:"certificateExpiresAt"`
	Policy               Policy       `json:"policy"`
	Status               string       `json:"status"`
	EvaluatedAt          *time.Time   `json:"evaluatedAt"`
	Observation          *Observation `json:"observation"`
	Incidents            []Incident   `json:"incidents"`
}

func New() State {
	return State{Version: 1, Policy: Policy{ThresholdPercent: 90}, Status: "disabled", Incidents: []Incident{}}
}
func stamp(t time.Time) *time.Time { t = t.UTC().Round(0); return &t }
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Location() == time.UTC
}
func optionalTime(t *time.Time) bool { return t == nil || validTime(*t) }
func Fresh(t, now time.Time) bool    { return validTime(t) && !now.Before(t) && now.Sub(t) <= MaxAge }
func validPercent(v float64) bool    { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 100 }
func ValidPolicy(p Policy) bool {
	return p.ThresholdPercent >= 50 && p.ThresholdPercent <= 99 && p.Revision <= MaxCounter && (!p.Enabled || p.Revision > 0)
}
func validObservation(o Observation, now time.Time) bool {
	return validPercent(o.Value) && validTime(o.CollectedAt) && validTime(o.ReceivedAt) && !o.CollectedAt.After(now) && !o.ReceivedAt.After(now) && o.Sequence > 0 && o.Sequence <= MaxCounter
}
func (in Input) authorized(now time.Time) bool {
	return in.Authorized && validTime(in.AuthorityUntil) && now.Before(in.AuthorityUntil)
}
func (in Input) observation(now time.Time) *Observation {
	if !in.authorized(now) || in.Disk.Quality != "healthy" || in.Disk.Unit != "%" || in.Disk.Value == nil || !validPercent(*in.Disk.Value) || !Fresh(in.Disk.CollectedAt, now) || !Fresh(in.ReceivedAt, now) || in.Sequence == 0 || in.Sequence > MaxCounter {
		return nil
	}
	return &Observation{Value: *in.Disk.Value, CollectedAt: in.Disk.CollectedAt.UTC(), ReceivedAt: in.ReceivedAt.UTC(), Sequence: in.Sequence}
}
func (s State) binding(in Input) bool {
	return s.DeviceID == in.DeviceID && s.InvitationID == in.InvitationID && s.CertificateHash == in.CertificateHash
}
func (s *State) bind(in Input) error {
	if !windowscontact.ValidDeviceID(in.DeviceID) || !enrollmentcrypto.ValidID(in.InvitationID, "invite_") || !enrollmentcrypto.ValidHash(in.CertificateHash) {
		return ErrInvalid
	}
	if s.DeviceID != "" && !s.binding(in) {
		return ErrInvalid
	}
	s.DeviceID = in.DeviceID
	s.InvitationID = in.InvitationID
	s.CertificateHash = in.CertificateHash
	return nil
}

func (s *State) reset() {
	s.Status = "unknown"
	if !s.Policy.Enabled {
		s.Status = "disabled"
	}
	s.Observation = nil
	s.PendingSince = nil
	s.RecoverySince = nil
	s.PendingObservation = nil
	s.RecoveryStart = nil
}
func (s *State) open() *Incident {
	for i := range s.Incidents {
		if s.Incidents[i].ResolvedAt == nil {
			return &s.Incidents[i]
		}
	}
	return nil
}

// Public transitions are atomic even when validation or clock checks fail.
func (s *State) transition(change func(*State) error) error {
	raw, err := Encode(*s)
	if err != nil {
		return err
	}
	copy, err := Decode(raw)
	if err != nil {
		return err
	}
	if err = change(&copy); err != nil {
		return err
	}
	if copy.Validate() != nil {
		return ErrInvalid
	}
	*s = copy
	return nil
}
func (s *State) Configure(in Input, enabled bool, threshold int, expected uint64, now time.Time) error {
	return s.transition(func(copy *State) error { return copy.configure(in, enabled, threshold, expected, now) })
}
func (s *State) Evaluate(in Input, now time.Time, epoch string) error {
	return s.transition(func(copy *State) error { return copy.evaluate(in, now, epoch) })
}

// Configure changes only manager policy. Policy changes close an episode with an
// explicit non-recovery reason and reset all confirmation timers.
func (s *State) configure(in Input, enabled bool, threshold int, expected uint64, now time.Time) error {
	if s.Validate() != nil || !validTime(now) || !in.authorized(now) || s.Policy.Revision != expected || expected >= MaxCounter || threshold < 50 || threshold > 99 || s.EvaluatedAt != nil && now.Before(*s.EvaluatedAt) || s.PolicyChangedAt != nil && now.Before(*s.PolicyChangedAt) {
		return ErrInvalid
	}
	if err := s.bind(in); err != nil {
		return err
	}
	if s.Policy.Enabled == enabled && s.Policy.ThresholdPercent == threshold {
		return nil
	}
	if incident := s.open(); incident != nil {
		incident.ResolvedAt = stamp(now)
		incident.ClosedReason = "policy-changed"
	}
	s.Policy = Policy{Enabled: enabled, ThresholdPercent: threshold, Revision: expected + 1}
	s.PolicyChangedAt = stamp(now)
	s.EvaluatedAt = nil
	s.Epoch = ""
	s.reset()
	s.prune(now)
	return s.Validate()
}

// Evaluate uses original sample times. Unknown interrupts waiting periods but
// never resolves an existing incident. A process restart changes epoch.
func (s *State) evaluate(in Input, now time.Time, epoch string) error {
	if s.Validate() != nil || !validTime(now) || !windowscontact.ValidEpoch(epoch) || !windowscontact.ValidDeviceID(in.DeviceID) {
		return ErrInvalid
	}
	if !s.Policy.Enabled {
		return nil
	}
	if !s.binding(in) {
		return ErrInvalid
	}
	if s.EvaluatedAt != nil && now.Before(*s.EvaluatedAt) {
		return ErrInvalid
	}
	continuity := s.Epoch == epoch && s.EvaluatedAt != nil && now.Sub(*s.EvaluatedAt) <= MaxGap
	if !continuity {
		s.reset()
	}
	s.Epoch = epoch
	s.EvaluatedAt = stamp(now)
	o := in.observation(now)
	// Persistent monotonic floors survive missing/partial observations, restart,
	// disabling and policy replacement. Neither a fallback nor a delayed frame can
	// erase the last accepted receipt/capture provenance.
	monotonic := in.authorized(now) && in.Sequence > 0 && in.Sequence <= MaxCounter && validTime(in.ReceivedAt) && !in.ReceivedAt.After(now)
	if monotonic && s.ReceiptFloor != nil {
		monotonic = in.Sequence >= s.SequenceFloor && !in.ReceivedAt.Before(*s.ReceiptFloor) && (in.Sequence != s.SequenceFloor || in.ReceivedAt.Equal(*s.ReceiptFloor))
	}
	if monotonic {
		s.SequenceFloor = in.Sequence
		s.ReceiptFloor = stamp(in.ReceivedAt)
	} else {
		o = nil
	}
	if validTime(in.Disk.CollectedAt) && !in.Disk.CollectedAt.After(now) {
		if s.CaptureFloor != nil && in.Disk.CollectedAt.Before(*s.CaptureFloor) {
			o = nil
		} else if monotonic {
			s.CaptureFloor = stamp(in.Disk.CollectedAt)
		}
	}
	if s.PolicyChangedAt != nil && now.Before(*s.PolicyChangedAt) {
		o = nil
	}
	if o == nil {
		s.reset()
		s.prune(now)
		return s.Validate()
	}
	s.Observation = o
	high := o.Value >= float64(s.Policy.ThresholdPercent)
	low := o.Value <= float64(s.Policy.ThresholdPercent-5)
	incident := s.open()
	if incident != nil {
		s.Status = "pressure"
		s.PendingSince = nil
		s.PendingObservation = nil
		if high {
			if o.Sequence > incident.LastHighObservation.Sequence && o.CollectedAt.After(incident.LastHighObservation.CollectedAt) {
				incident.LastConfirmedAt = now
				incident.LastHighObservation = *o
			}
			s.RecoverySince = nil
			s.RecoveryStart = nil
		} else if low && o.Sequence > incident.LastHighObservation.Sequence && !o.CollectedAt.Before(incident.LastHighObservation.CollectedAt) {
			if s.RecoverySince == nil {
				s.RecoverySince = stamp(now)
				s.RecoveryStart = o
			}
			if now.Sub(*s.RecoverySince) >= Confirmation && o.Sequence > s.RecoveryStart.Sequence && o.CollectedAt.Sub(s.RecoveryStart.CollectedAt) >= Confirmation {
				incident.ResolvedAt = stamp(now)
				incident.RecoveryObservation = o
				incident.ClosedReason = "within-policy"
				s.RecoverySince = nil
				s.RecoveryStart = nil
				s.Status = "within-policy"
			}
		} else {
			s.RecoverySince = nil
			s.RecoveryStart = nil
		}
	} else if high {
		s.RecoverySince = nil
		s.RecoveryStart = nil
		s.Status = "pending"
		if s.PendingSince == nil {
			s.PendingSince = stamp(now)
			s.PendingObservation = o
		}
		if now.Sub(*s.PendingSince) >= Confirmation && o.Sequence > s.PendingObservation.Sequence && o.CollectedAt.Sub(s.PendingObservation.CollectedAt) >= Confirmation {
			if s.NextID >= MaxCounter {
				return ErrInvalid
			}
			s.NextID++
			row := Incident{ID: fmt.Sprintf("wcapacity_%016x", s.NextID), PolicyRevision: s.Policy.Revision, ThresholdPercent: s.Policy.ThresholdPercent, OpenedAt: now, LastConfirmedAt: now, OpeningObservation: *o, LastHighObservation: *o}
			s.Incidents = append([]Incident{row}, s.Incidents...)
			s.PendingSince = nil
			s.PendingObservation = nil
			s.Status = "pressure"
		}
	} else {
		s.PendingSince = nil
		s.RecoverySince = nil
		s.PendingObservation = nil
		s.RecoveryStart = nil
		s.Status = "within-policy"
	}
	s.prune(now)
	return s.Validate()
}
func (s *State) prune(now time.Time) {
	out := make([]Incident, 0, len(s.Incidents))
	for _, r := range s.Incidents {
		if r.ResolvedAt != nil && !now.Before(*r.ResolvedAt) && now.Sub(*r.ResolvedAt) > Retention {
			continue
		}
		if len(out) < MaxIncidents {
			out = append(out, r)
		}
	}
	s.Incidents = out
}
func (s State) View(in Input, now time.Time, epoch string) View {
	status := s.Status
	observation := s.Observation
	if s.Policy.Enabled && (s.Epoch != epoch || epoch == "" || s.EvaluatedAt == nil || !Fresh(*s.EvaluatedAt, now) || !in.authorized(now) || !s.binding(in) || observation == nil || !Fresh(observation.CollectedAt, now) || !Fresh(observation.ReceivedAt, now)) {
		status = "unknown"
		observation = nil
	}
	current := in.observation(now)
	if s.Policy.Enabled && observation != nil && (current == nil || *current != *observation) {
		status = "unknown"
		observation = nil
	}
	incidents := append([]Incident{}, s.Incidents...)
	return View{SchemaVersion: SchemaVersion, DeviceID: in.DeviceID, ServerNow: now, CertificateExpiresAt: in.AuthorityUntil, Policy: s.Policy, Status: status, EvaluatedAt: s.EvaluatedAt, Observation: observation, Incidents: incidents}
}
func (s State) Validate() error {
	if s.Version != 1 || !ValidPolicy(s.Policy) || s.Incidents == nil || len(s.Incidents) > MaxIncidents || s.NextID > MaxCounter || !optionalTime(s.EvaluatedAt) || !optionalTime(s.PolicyChangedAt) || !optionalTime(s.PendingSince) || !optionalTime(s.RecoverySince) {
		return ErrInvalid
	}
	if s.DeviceID == "" {
		if s.InvitationID != "" || s.CertificateHash != "" || s.Policy.Revision != 0 || s.Policy.Enabled || s.PolicyChangedAt != nil || s.NextID != 0 || len(s.Incidents) != 0 || s.EvaluatedAt != nil || s.Epoch != "" || s.Observation != nil || s.Status != "disabled" || s.PendingSince != nil || s.RecoverySince != nil || s.PendingObservation != nil || s.RecoveryStart != nil || s.SequenceFloor != 0 || s.ReceiptFloor != nil || s.CaptureFloor != nil {
			return ErrInvalid
		}
		return nil
	}
	if !windowscontact.ValidDeviceID(s.DeviceID) || !regexp.MustCompile(`^invite_[0-9a-f]{32}$`).MatchString(s.InvitationID) || s.InvitationID == "invite_"+strings.Repeat("0", 32) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s.CertificateHash) || s.CertificateHash == strings.Repeat("0", 64) || s.Epoch != "" && !windowscontact.ValidEpoch(s.Epoch) || s.Policy.Revision > 0 && s.PolicyChangedAt == nil {
		return ErrInvalid
	}
	if s.EvaluatedAt == nil {
		if s.Epoch != "" || s.Observation != nil || s.PendingSince != nil || s.RecoverySince != nil {
			return ErrInvalid
		}
	} else if s.Epoch == "" {
		return ErrInvalid
	}
	at := s.PolicyChangedAt
	if s.EvaluatedAt != nil && (at == nil || s.EvaluatedAt.After(*at)) {
		at = s.EvaluatedAt
	}
	if s.Observation != nil && (s.EvaluatedAt == nil || !validObservation(*s.Observation, *s.EvaluatedAt) || !Fresh(s.Observation.CollectedAt, *s.EvaluatedAt) || !Fresh(s.Observation.ReceivedAt, *s.EvaluatedAt)) {
		return ErrInvalid
	}
	if s.SequenceFloor > MaxCounter || !optionalTime(s.ReceiptFloor) || !optionalTime(s.CaptureFloor) || s.SequenceFloor == 0 != (s.ReceiptFloor == nil) || s.CaptureFloor != nil && s.ReceiptFloor == nil {
		return ErrInvalid
	}
	if s.ReceiptFloor != nil && (at == nil || s.ReceiptFloor.After(*at)) || s.CaptureFloor != nil && (at == nil || s.CaptureFloor.After(*at)) {
		return ErrInvalid
	}
	if (s.PendingSince == nil) != (s.PendingObservation == nil) || (s.RecoverySince == nil) != (s.RecoveryStart == nil) {
		return ErrInvalid
	}
	if s.PendingObservation != nil && (!validObservation(*s.PendingObservation, *s.PendingSince) || !Fresh(s.PendingObservation.CollectedAt, *s.PendingSince) || !Fresh(s.PendingObservation.ReceivedAt, *s.PendingSince) || s.PendingObservation.Value < float64(s.Policy.ThresholdPercent)) {
		return ErrInvalid
	}
	if s.RecoveryStart != nil && (!validObservation(*s.RecoveryStart, *s.RecoverySince) || !Fresh(s.RecoveryStart.CollectedAt, *s.RecoverySince) || !Fresh(s.RecoveryStart.ReceivedAt, *s.RecoverySince) || s.RecoveryStart.Value > float64(s.Policy.ThresholdPercent-5)) {
		return ErrInvalid
	}
	if s.Observation != nil && (s.ReceiptFloor == nil || s.CaptureFloor == nil || s.Observation.Sequence != s.SequenceFloor || !s.Observation.ReceivedAt.Equal(*s.ReceiptFloor) || !s.Observation.CollectedAt.Equal(*s.CaptureFloor)) {
		return ErrInvalid
	}
	open := 0
	previousID := s.NextID + 1
	for i, r := range s.Incidents {
		var n uint64
		if !incidentPattern.MatchString(r.ID) {
			return ErrInvalid
		}
		if _, e := fmt.Sscanf(r.ID, "wcapacity_%x", &n); e != nil || n == 0 || n >= previousID || n > s.NextID {
			return ErrInvalid
		}
		previousID = n
		if r.PolicyRevision == 0 || r.PolicyRevision > s.Policy.Revision || r.ThresholdPercent < 50 || r.ThresholdPercent > 99 || !validTime(r.OpenedAt) || !validTime(r.LastConfirmedAt) || at == nil || r.LastConfirmedAt.Before(r.OpenedAt) || r.LastConfirmedAt.After(*at) || !validObservation(r.OpeningObservation, r.OpenedAt) || !Fresh(r.OpeningObservation.CollectedAt, r.OpenedAt) || !Fresh(r.OpeningObservation.ReceivedAt, r.OpenedAt) || r.OpeningObservation.Value < float64(r.ThresholdPercent) || !validObservation(r.LastHighObservation, r.LastConfirmedAt) || !Fresh(r.LastHighObservation.CollectedAt, r.LastConfirmedAt) || !Fresh(r.LastHighObservation.ReceivedAt, r.LastConfirmedAt) || r.LastHighObservation.Value < float64(r.ThresholdPercent) || r.LastHighObservation.Sequence < r.OpeningObservation.Sequence || r.LastHighObservation.CollectedAt.Before(r.OpeningObservation.CollectedAt) {
			return ErrInvalid
		}
		if r.ResolvedAt == nil {
			open++
			if i != 0 || r.ClosedReason != "" || r.RecoveryObservation != nil || !s.Policy.Enabled || r.PolicyRevision != s.Policy.Revision || r.ThresholdPercent != s.Policy.ThresholdPercent {
				return ErrInvalid
			}
		} else {
			if !validTime(*r.ResolvedAt) || r.ResolvedAt.Before(r.LastConfirmedAt) || r.ResolvedAt.After(*at) || i > 0 && s.Incidents[i-1].OpenedAt.Before(*r.ResolvedAt) {
				return ErrInvalid
			}
			switch r.ClosedReason {
			case "policy-changed":
				if r.RecoveryObservation != nil || r.PolicyRevision >= s.Policy.Revision {
					return ErrInvalid
				}
			case "within-policy":
				o := r.RecoveryObservation
				if o == nil || !validObservation(*o, *r.ResolvedAt) || !Fresh(o.CollectedAt, *r.ResolvedAt) || !Fresh(o.ReceivedAt, *r.ResolvedAt) || o.Value > float64(r.ThresholdPercent-5) || o.Sequence <= r.LastHighObservation.Sequence || o.CollectedAt.Before(r.LastHighObservation.CollectedAt) {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
		}
	}
	if open > 1 {
		return ErrInvalid
	}
	if s.PendingSince != nil && (s.EvaluatedAt == nil || s.PendingSince.After(*s.EvaluatedAt)) {
		return ErrInvalid
	}
	if s.RecoverySince != nil && (s.EvaluatedAt == nil || s.RecoverySince.After(*s.EvaluatedAt)) {
		return ErrInvalid
	}
	switch s.Status {
	case "disabled":
		if s.Policy.Enabled || s.Observation != nil || s.PendingSince != nil || s.RecoverySince != nil || open != 0 {
			return ErrInvalid
		}
	case "unknown":
		if !s.Policy.Enabled || s.Observation != nil || s.PendingSince != nil || s.RecoverySince != nil {
			return ErrInvalid
		}
	case "within-policy":
		if !s.Policy.Enabled || s.Observation == nil || open != 0 || s.PendingSince != nil || s.RecoverySince != nil || s.Observation.Value >= float64(s.Policy.ThresholdPercent) {
			return ErrInvalid
		}
	case "pending":
		if !s.Policy.Enabled || s.Observation == nil || open != 0 || s.PendingSince == nil || s.RecoverySince != nil || s.Observation.Value < float64(s.Policy.ThresholdPercent) {
			return ErrInvalid
		}
	case "pressure":
		if !s.Policy.Enabled || s.Observation == nil || open != 1 || s.PendingSince != nil || s.RecoverySince != nil && s.Observation.Value > float64(s.Policy.ThresholdPercent-5) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
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
