// Package windowscontact evaluates authenticated Windows report receipts only.
// It makes no claim about endpoint availability, inventory, or endpoint health.
package windowscontact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	Interval      = 30 * time.Second
	MaxAge        = 120 * time.Second
	Confirmation  = 60 * time.Second
	MaxGap        = 90 * time.Second
	Retention     = 30 * 24 * time.Hour
	MaxIncidents  = 100
	MaxDevices    = 25
	MaxStateBytes = 128 << 10
	MaxCounter    = uint64(1<<53 - 1)
)

var ErrInvalid = errors.New("windows_contact_invalid")
var devicePattern = regexp.MustCompile(`^agent_[0-9a-f]{32}$`)
var epochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var invitationPattern = regexp.MustCompile(`^invite_[0-9a-f]{32}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Input contains only the original accepted receipt and current authority.
// On source failures, rotate the monitor epoch (or explicitly evaluate with
// Authorized=false); never invent a fresh receipt or erase retained history.
type Input struct {
	DeviceID        string
	Authorized      bool
	AuthorityUntil  time.Time
	ReceivedAt      time.Time
	Sequence        uint64
	InvitationID    string
	CertificateHash string
}

type Incident struct {
	ID                 string     `json:"id"`
	Kind               string     `json:"kind"`
	OpenedAt           time.Time  `json:"openedAt"`
	LastConfirmedAt    time.Time  `json:"lastConfirmedAt"`
	LastAcceptedAt     time.Time  `json:"lastAcceptedAt"`
	Sequence           uint64     `json:"sequence"`
	RecoveryAcceptedAt *time.Time `json:"recoveryAcceptedAt"`
	RecoverySequence   uint64     `json:"recoverySequence"`
	ResolvedAt         *time.Time `json:"resolvedAt"`
	ClosedReason       string     `json:"closedReason,omitempty"`
}

// State is a private durable ledger. Epoch and identity bindings never appear in
// View. A process must use a new, stable epoch for its entire evaluator lifetime.
type State struct {
	Version         int        `json:"version"`
	DeviceID        string     `json:"deviceId"`
	Epoch           string     `json:"epoch"`
	InvitationID    string     `json:"invitationId"`
	CertificateHash string     `json:"certificateHash"`
	Status          string     `json:"status"`
	LastAcceptedAt  *time.Time `json:"lastAcceptedAt"`
	Sequence        uint64     `json:"sequence"`
	EvaluatedAt     *time.Time `json:"evaluatedAt"`
	PendingSince    *time.Time `json:"pendingSince"`
	RecoverySince   *time.Time `json:"recoverySince"`
	Incidents       []Incident `json:"incidents"`
	NextID          uint64     `json:"nextId"`
}

type View struct {
	SchemaVersion        string     `json:"schemaVersion"`
	CertificateExpiresAt *time.Time `json:"certificateExpiresAt"`
	DeviceID             string     `json:"deviceId"`
	ServerNow            time.Time  `json:"serverNow"`
	Status               string     `json:"status"`
	LastAcceptedAt       *time.Time `json:"lastAcceptedAt"`
	Sequence             uint64     `json:"sequence"`
	EvaluatedAt          *time.Time `json:"evaluatedAt"`
	Incidents            []Incident `json:"incidents"`
}

func New() State { return State{Version: 1, Status: "unknown", Incidents: []Incident{}} }
func ValidDeviceID(id string) bool {
	return devicePattern.MatchString(id) && id != "agent_"+strings.Repeat("0", 32)
}
func ValidEpoch(epoch string) bool {
	return epochPattern.MatchString(epoch) && epoch != strings.Repeat("0", 32)
}
func stamp(t time.Time) *time.Time { t = t.UTC().Round(0); return &t }
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Location() == time.UTC
}
func validOptional(t *time.Time) bool { return t == nil || validTime(*t) }
func validBinding(invitation, hash string) bool {
	return invitation == "" && hash == "" || invitationPattern.MatchString(invitation) && strings.TrimPrefix(invitation, "invite_") != strings.Repeat("0", 32) && hashPattern.MatchString(hash) && hash != strings.Repeat("0", 64)
}
func (in Input) valid() bool {
	return ValidDeviceID(in.DeviceID) && in.Sequence <= MaxCounter && validBinding(in.InvitationID, in.CertificateHash) && (!in.Authorized || in.InvitationID != "" && validTime(in.AuthorityUntil.UTC()))
}
func (in Input) authorized(now time.Time) bool {
	return in.Authorized && !in.AuthorityUntil.IsZero() && now.Before(in.AuthorityUntil)
}
func (s *State) reset() { s.Status = "unknown"; s.PendingSince = nil; s.RecoverySince = nil }
func (s *State) open() *Incident {
	for i := range s.Incidents {
		if s.Incidents[i].ResolvedAt == nil {
			return &s.Incidents[i]
		}
	}
	return nil
}

// Evaluate performs one manager-side evaluation. Re-reading an unchanged
// receipt may confirm elapsed evaluation time but never advances its original
// receipt time. Missing authority, restarts, clock rollback and gaps reset all
// transition timers, and never resolve an incident or reconstruct stopped time.
func (s *State) Evaluate(in Input, now time.Time, epoch string) error {
	copy := *s
	copy.Incidents = append([]Incident{}, s.Incidents...)
	if err := copy.evaluate(in, now, epoch); err != nil {
		return err
	}
	if _, err := Encode(copy); err != nil {
		return err
	}
	*s = copy
	return nil
}

func (s *State) evaluate(in Input, now time.Time, epoch string) error {
	if s.Validate() != nil || !in.valid() || !ValidEpoch(epoch) {
		return ErrInvalid
	}
	now = now.UTC().Round(0)
	if !validTime(now) || s.DeviceID != "" && s.DeviceID != in.DeviceID {
		return ErrInvalid
	}
	if in.Authorized && s.InvitationID != "" && (s.InvitationID != in.InvitationID || s.CertificateHash != in.CertificateHash) {
		return ErrInvalid
	}
	s.DeviceID = in.DeviceID
	if s.Epoch != epoch {
		s.reset()
		s.Epoch = epoch
	}
	if s.EvaluatedAt != nil && now.Before(*s.EvaluatedAt) {
		s.reset()
		return nil
	}
	if s.EvaluatedAt == nil || now.Sub(*s.EvaluatedAt) > MaxGap {
		s.reset()
	}
	s.EvaluatedAt = stamp(now)
	defer s.prune(now)
	if !in.authorized(now) {
		s.reset()
		return nil
	}
	if s.InvitationID == "" {
		s.reset()
		s.InvitationID, s.CertificateHash = in.InvitationID, in.CertificateHash
		s.LastAcceptedAt, s.Sequence = nil, 0
	}
	if in.ReceivedAt.IsZero() || in.Sequence == 0 || in.ReceivedAt.After(now) {
		s.reset()
		return nil
	}
	at := in.ReceivedAt.UTC().Round(0)
	if !validTime(at) {
		s.reset()
		return nil
	}
	if s.LastAcceptedAt != nil && (in.Sequence < s.Sequence || in.Sequence == s.Sequence && !at.Equal(*s.LastAcceptedAt) || in.Sequence > s.Sequence && at.Before(*s.LastAcceptedAt)) {
		s.reset()
		return nil
	}
	// A newer receipt cannot bridge a period during which the prior accepted
	// report had already become stale, even if evaluator ticks were continuous.
	// Compare original receipt times before replacing the previous evidence.
	if s.LastAcceptedAt != nil && in.Sequence > s.Sequence && at.Sub(*s.LastAcceptedAt) > MaxAge {
		s.RecoverySince = nil
	}
	if s.LastAcceptedAt == nil || in.Sequence > s.Sequence {
		s.LastAcceptedAt, s.Sequence = stamp(at), in.Sequence
	}
	open := s.open()
	if now.Sub(*s.LastAcceptedAt) > MaxAge {
		s.RecoverySince = nil
		if open != nil {
			s.Status = "overdue"
			if !now.Before(open.LastConfirmedAt) {
				open.LastConfirmedAt = now
			}
			return nil
		}
		if s.PendingSince == nil {
			s.PendingSince = stamp(now)
		}
		s.Status = "pending"
		if now.Sub(*s.PendingSince) >= Confirmation {
			if s.NextID == MaxCounter {
				return ErrInvalid
			}
			s.NextID++
			s.Incidents = append([]Incident{{ID: fmt.Sprintf("wcontact_%016x", s.NextID), Kind: "overdue-report", OpenedAt: now, LastConfirmedAt: now, LastAcceptedAt: *s.LastAcceptedAt, Sequence: s.Sequence}}, s.Incidents...)
			s.PendingSince = nil
			s.Status = "overdue"
		}
		return nil
	}
	s.PendingSince = nil
	if open == nil {
		s.Status = "recent"
		s.RecoverySince = nil
		return nil
	}
	s.Status = "overdue"
	// A fresh accepted report must postdate the confirmed overdue observation.
	// This also prevents recovery under a clock rolled back behind the incident.
	if s.LastAcceptedAt.Before(open.LastConfirmedAt) || now.Before(open.LastConfirmedAt) {
		s.RecoverySince = nil
		return nil
	}
	if s.RecoverySince == nil {
		s.RecoverySince = stamp(now)
	}
	if now.Sub(*s.RecoverySince) >= Confirmation {
		open.ResolvedAt, open.ClosedReason = stamp(now), "reports-resumed"
		open.RecoveryAcceptedAt, open.RecoverySequence = stamp(*s.LastAcceptedAt), s.Sequence
		s.RecoverySince = nil
		s.Status = "recent"
	}
	return nil
}

func (s *State) prune(now time.Time) {
	out := make([]Incident, 0, len(s.Incidents))
	for _, in := range s.Incidents {
		if in.ResolvedAt == nil || now.Sub(*in.ResolvedAt) <= Retention {
			out = append(out, in)
		}
	}
	for len(out) > MaxIncidents {
		for i := len(out) - 1; i >= 0; i-- {
			if out[i].ResolvedAt != nil {
				out = append(out[:i], out[i+1:]...)
				break
			}
		}
	}
	s.Incidents = out
}

// View is strictly read-only. Durable history is visible even when current
// authority or process continuity cannot establish a current contact status.
func (s State) View(in Input, now time.Time, epoch string) View {
	now = now.UTC().Round(0)
	status := s.Status
	if s.Validate() != nil || !in.valid() || s.DeviceID != in.DeviceID || !in.authorized(now) || epoch != s.Epoch || !ValidEpoch(epoch) || s.EvaluatedAt == nil || now.Before(*s.EvaluatedAt) || now.Sub(*s.EvaluatedAt) > MaxAge || s.InvitationID != in.InvitationID || s.CertificateHash != in.CertificateHash || s.LastAcceptedAt == nil || in.Sequence != s.Sequence || !in.ReceivedAt.Equal(*s.LastAcceptedAt) || s.LastAcceptedAt.After(now) || status == "recent" && now.Sub(*s.LastAcceptedAt) > MaxAge {
		status = "unknown"
	}
	incidents := append([]Incident{}, s.Incidents...)
	for i := range incidents {
		if incidents[i].ResolvedAt != nil {
			incidents[i].ResolvedAt = stamp(*incidents[i].ResolvedAt)
		}
		if incidents[i].RecoveryAcceptedAt != nil {
			incidents[i].RecoveryAcceptedAt = stamp(*incidents[i].RecoveryAcceptedAt)
		}
	}
	var accepted, evaluated, expires *time.Time
	if !in.AuthorityUntil.IsZero() {
		expires = stamp(in.AuthorityUntil)
	}
	if s.LastAcceptedAt != nil {
		accepted = stamp(*s.LastAcceptedAt)
	}
	if s.EvaluatedAt != nil {
		evaluated = stamp(*s.EvaluatedAt)
	}
	sequence := s.Sequence
	if s.DeviceID != "" && s.DeviceID != in.DeviceID || s.InvitationID != "" && (s.InvitationID != in.InvitationID || s.CertificateHash != in.CertificateHash) {
		incidents, accepted, evaluated, sequence = []Incident{}, nil, nil, 0
	}
	if in.Authorized && in.valid() {
		accepted, sequence = nil, in.Sequence
		if !in.ReceivedAt.IsZero() {
			accepted = stamp(in.ReceivedAt)
		}
	}
	return View{SchemaVersion: "tracebolt.windows-contact-view.v1", CertificateExpiresAt: expires, DeviceID: in.DeviceID, ServerNow: now, Status: status, LastAcceptedAt: accepted, Sequence: sequence, EvaluatedAt: evaluated, Incidents: incidents}
}

// Validate rejects noncanonical identifiers and impossible transition states.
func (s State) Validate() error {
	if s.Version != 1 || s.NextID > MaxCounter || s.Sequence > MaxCounter || s.Incidents == nil || len(s.Incidents) > MaxIncidents || !validBinding(s.InvitationID, s.CertificateHash) || !validOptional(s.LastAcceptedAt) || !validOptional(s.EvaluatedAt) || !validOptional(s.PendingSince) || !validOptional(s.RecoverySince) {
		return ErrInvalid
	}
	if s.DeviceID == "" {
		if s.Epoch != "" || s.Status != "unknown" || s.LastAcceptedAt != nil || s.EvaluatedAt != nil || s.Sequence != 0 || s.NextID != 0 || len(s.Incidents) != 0 || s.InvitationID != "" || s.CertificateHash != "" || s.PendingSince != nil || s.RecoverySince != nil {
			return ErrInvalid
		}
		return nil
	}
	if !ValidDeviceID(s.DeviceID) || !ValidEpoch(s.Epoch) || s.EvaluatedAt == nil || (s.LastAcceptedAt == nil) != (s.Sequence == 0) || s.LastAcceptedAt != nil && (s.LastAcceptedAt.After(*s.EvaluatedAt) || s.InvitationID == "") || len(s.Incidents) > 0 && s.LastAcceptedAt == nil {
		return ErrInvalid
	}
	for _, at := range []*time.Time{s.PendingSince, s.RecoverySince} {
		if at != nil && (s.LastAcceptedAt == nil || at.After(*s.EvaluatedAt)) {
			return ErrInvalid
		}
	}
	openCount := 0
	previous := s.NextID + 1
	var newerOpenedAt *time.Time
	for i, in := range s.Incidents {
		n, err := strconv.ParseUint(strings.TrimPrefix(in.ID, "wcontact_"), 16, 64)
		if err != nil || in.ID != fmt.Sprintf("wcontact_%016x", n) || n == 0 || n >= previous || n > s.NextID || in.Kind != "overdue-report" || !validTime(in.OpenedAt) || !validTime(in.LastConfirmedAt) || in.LastConfirmedAt.Before(in.OpenedAt) || in.LastConfirmedAt.After(*s.EvaluatedAt) || !validOptional(in.ResolvedAt) || !validTime(in.LastAcceptedAt) || in.OpenedAt.Sub(in.LastAcceptedAt) <= MaxAge || in.Sequence == 0 || in.Sequence > s.Sequence || in.LastAcceptedAt.After(*s.LastAcceptedAt) || !validOptional(in.RecoveryAcceptedAt) {
			return ErrInvalid
		}
		previous = n
		if newerOpenedAt != nil && (in.ResolvedAt == nil || in.ResolvedAt.After(*newerOpenedAt)) {
			return ErrInvalid
		}
		newerOpenedAt = stamp(in.OpenedAt)
		if in.ResolvedAt == nil {
			openCount++
			if i != 0 || in.ClosedReason != "" || in.RecoveryAcceptedAt != nil || in.RecoverySequence != 0 {
				return ErrInvalid
			}
		} else if in.ClosedReason != "reports-resumed" || in.ResolvedAt.Before(in.LastConfirmedAt) || in.ResolvedAt.After(*s.EvaluatedAt) || in.RecoveryAcceptedAt == nil || in.RecoverySequence <= in.Sequence || in.RecoverySequence > s.Sequence || in.RecoveryAcceptedAt.After(*s.LastAcceptedAt) || in.RecoveryAcceptedAt.Before(in.LastConfirmedAt) || in.RecoveryAcceptedAt.After(*in.ResolvedAt) || in.ResolvedAt.Sub(*in.RecoveryAcceptedAt) > MaxAge {
			return ErrInvalid
		}
	}
	if openCount > 1 {
		return ErrInvalid
	}
	switch s.Status {
	case "unknown":
		if s.PendingSince != nil || s.RecoverySince != nil {
			return ErrInvalid
		}
	case "recent":
		if s.LastAcceptedAt == nil || openCount != 0 || s.PendingSince != nil || s.RecoverySince != nil || s.EvaluatedAt.Sub(*s.LastAcceptedAt) > MaxAge {
			return ErrInvalid
		}
	case "pending":
		if s.LastAcceptedAt == nil || openCount != 0 || s.PendingSince == nil || s.RecoverySince != nil || s.EvaluatedAt.Sub(*s.LastAcceptedAt) <= MaxAge || s.EvaluatedAt.Sub(*s.PendingSince) >= Confirmation {
			return ErrInvalid
		}
	case "overdue":
		if s.LastAcceptedAt == nil || openCount != 1 || s.PendingSince != nil || s.RecoverySince != nil && (s.EvaluatedAt.Sub(*s.RecoverySince) >= Confirmation || s.EvaluatedAt.Sub(*s.LastAcceptedAt) > MaxAge || s.RecoverySince.Before(s.Incidents[0].LastConfirmedAt)) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// Decode accepts exactly our canonical bounded serialization: unknown members,
// duplicate keys, missing fields, whitespace variants and trailing values fail.
func Decode(raw []byte) (State, error) {
	if len(raw) == 0 || len(raw) > MaxStateBytes {
		return State{}, ErrInvalid
	}
	var state State
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&state) != nil || d.Decode(new(any)) != io.EOF || state.Validate() != nil {
		return State{}, ErrInvalid
	}
	canonical, err := Encode(state)
	if err != nil || !bytes.Equal(raw, canonical) {
		return State{}, ErrInvalid
	}
	return state, nil
}

func Encode(state State) ([]byte, error) {
	if state.Validate() != nil {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(state)
	if err != nil || len(raw) > MaxStateBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}
