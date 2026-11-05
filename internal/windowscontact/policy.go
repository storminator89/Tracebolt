package windowscontact

import (
	"errors"
	"time"
)

var ErrConflict = errors.New("windows_contact_policy_conflict")

// PolicyRequest records deliberate, revision-bound operator consent.
type PolicyRequest struct {
	ExpectedRevision uint64 `json:"expectedRevision"`
	RequestID        string `json:"requestId"`
	GraceSeconds     int    `json:"graceSeconds"`
	Acknowledged     bool   `json:"acknowledged"`
}

// Policy is private durable policy and retry/post-change evidence.
type Policy struct {
	Revision            uint64        `json:"revision"`
	GraceSeconds        int           `json:"graceSeconds"`
	ChangedAt           time.Time     `json:"changedAt"`
	LastRequestID       string        `json:"lastRequestId"`
	LastRequest         PolicyRequest `json:"lastRequest"`
	AwaitingFreshReport bool          `json:"awaitingFreshReport"`
	ReportFloor         uint64        `json:"reportFloor"`
}

// PolicyView deliberately omits request bodies and internal receipt floors.
type PolicyView struct {
	Revision            uint64    `json:"revision"`
	GraceSeconds        int       `json:"graceSeconds"`
	ChangedAt           time.Time `json:"changedAt"`
	LastRequestID       string    `json:"lastRequestId"`
	AwaitingFreshReport bool      `json:"awaitingFreshReport"`
}

func ValidGraceSeconds(n int) bool { return n == 120 || n == 300 || n == 900 || n == 3600 }
func (s State) GraceSeconds() int {
	if s.Policy == nil {
		return 120
	}
	return s.Policy.GraceSeconds
}
func (s State) PolicyRevision() uint64 {
	if s.Policy == nil {
		return 0
	}
	return s.Policy.Revision
}
func (s State) incidentGraceSeconds() int {
	if s.Policy == nil {
		return 0
	}
	return s.Policy.GraceSeconds
}
func (p *Policy) clone() *Policy {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}
func (r PolicyRequest) valid() bool {
	return r.ExpectedRevision < MaxCounter && ValidEpoch(r.RequestID) && ValidGraceSeconds(r.GraceSeconds) && r.Acknowledged
}
func (s State) validatePolicy() error {
	p := s.Policy
	if p == nil {
		return nil
	}
	if p.Revision == 0 || p.Revision > MaxCounter || !ValidGraceSeconds(p.GraceSeconds) || !validTime(p.ChangedAt) || s.EvaluatedAt == nil || p.ChangedAt.After(*s.EvaluatedAt) || !ValidEpoch(p.LastRequestID) || p.ReportFloor > MaxCounter || !p.LastRequest.valid() || p.LastRequest.ExpectedRevision != p.Revision-1 || p.LastRequestID != p.LastRequest.RequestID || p.GraceSeconds != p.LastRequest.GraceSeconds || s.InvitationID == "" {
		return ErrInvalid
	}
	if p.AwaitingFreshReport && (s.Status == "recent" || s.Status == "pending" || s.RecoverySince != nil) {
		return ErrInvalid
	}
	if !p.AwaitingFreshReport && (s.LastAcceptedAt == nil || s.Sequence <= p.ReportFloor || !s.LastAcceptedAt.After(p.ChangedAt)) {
		return ErrInvalid
	}
	return nil
}

// Configure never evaluates a receipt or resolves an incident. Each actual edit
// requires a newly accepted fresh post-change report before another incident.
// Exact replays of the latest request are no-ops; old revisions conflict.
func (s *State) Configure(in Input, req PolicyRequest, now time.Time, epoch string) error {
	now = now.UTC().Round(0)
	if s.Validate() != nil || !in.valid() || !in.authorized(now) || !ValidEpoch(epoch) || !validTime(now) || !req.valid() || s.DeviceID != "" && s.DeviceID != in.DeviceID || s.InvitationID != "" && (s.InvitationID != in.InvitationID || s.CertificateHash != in.CertificateHash) || s.EvaluatedAt != nil && now.Before(*s.EvaluatedAt) {
		return ErrInvalid
	}
	if s.Policy != nil && s.Policy.LastRequestID == req.RequestID {
		if s.Policy.LastRequest == req {
			return nil
		}
		return ErrConflict
	}
	if req.ExpectedRevision != s.PolicyRevision() {
		return ErrConflict
	}
	if s.PolicyRevision() >= MaxCounter {
		return ErrConflict
	}
	c := *s
	c.Policy = s.Policy.clone()
	if c.Policy == nil {
		c.Policy = &Policy{}
	}
	c.Version = 2
	c.DeviceID, c.InvitationID, c.CertificateHash, c.Epoch = in.DeviceID, in.InvitationID, in.CertificateHash, epoch
	c.reset()
	c.EvaluatedAt = stamp(now)
	p := c.Policy
	p.Revision++
	p.GraceSeconds, p.ChangedAt, p.LastRequestID, p.LastRequest = req.GraceSeconds, now, req.RequestID, req
	p.AwaitingFreshReport = true
	p.ReportFloor = c.Sequence
	if in.Sequence > p.ReportFloor {
		p.ReportFloor = in.Sequence
	}
	if _, err := Encode(c); err != nil {
		return err
	}
	*s = c
	return nil
}
