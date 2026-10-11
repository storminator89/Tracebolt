// Package windowsactionjob holds the durable, bounded selected Windows action workflow.
package windowsactionjob

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/windowsaction"
	"time"
)

const Version = "tracebolt.windows-service-action-record.v1"
const PreviewVersion = "tracebolt.windows-service-action-preview.v1"
const MaxRecordBytes = 524288

var ErrNotFound = errors.New("windows_action_not_found")
var ErrConflict = errors.New("windows_action_conflict")

type Preview struct {
	Version   string                `json:"version"`
	ID        string                `json:"id"`
	Binding   windowsaction.Binding `json:"binding"`
	Operation string                `json:"operation"`
	ActorID   string                `json:"actorId"`
	Sequence  uint64                `json:"sequence,string"`
	CreatedAt time.Time             `json:"createdAt"`
	ExpiresAt time.Time             `json:"expiresAt"`
	Digest    string                `json:"digest"`
}
type Job struct {
	Preview    Preview                `json:"preview"`
	ApprovedAt time.Time              `json:"approvedAt"`
	Envelope   []byte                 `json:"envelope"`
	ClaimedAt  *time.Time             `json:"claimedAt"`
	Results    []windowsaction.Result `json:"results"`
}
type Record struct {
	Version            string                      `json:"version"`
	Binding            windowsaction.Binding       `json:"binding"`
	PublicKey          []byte                      `json:"publicKey"`
	ClockFloor         time.Time                   `json:"clockFloor"`
	RejectedClockFloor *time.Time                  `json:"rejectedClockFloor,omitempty"`
	Sequence           uint64                      `json:"sequence,string"`
	Capabilities       *windowsaction.Capabilities `json:"capabilities"`
	Preview            *Preview                    `json:"preview"`
	Jobs               []Job                       `json:"jobs"`
}
type Delivery struct {
	Identity      windowsaction.Identity `json:"identity"`
	State         string                 `json:"state"`
	StartDeadline time.Time              `json:"startDeadline"`
}
type Grant struct {
	Identity windowsaction.Identity `json:"identity"`
	Envelope []byte                 `json:"envelope"`
}

func validTime(t time.Time) bool {
	return t.Location() == time.UTC && t.Unix() > 0 && t.Unix() <= 253402300799
}
func previewDigest(p Preview) string {
	p.Digest = ""
	b, _ := json.Marshal(p)
	return windowsaction.Digest(b)
}
func validPreview(p Preview, b windowsaction.Binding) bool {
	return p.Version == PreviewVersion && p.Binding == b && enrollmentcrypto.ValidID(p.ID, "action_") && enrollmentcrypto.ValidID(p.ActorID, "operator_") && windowsaction.ValidOperation(p.Operation) && p.Sequence > 0 && validTime(p.CreatedAt) && validTime(p.ExpiresAt) && p.ExpiresAt.Sub(p.CreatedAt) == time.Minute && p.Digest == previewDigest(p)
}
func New(b windowsaction.Binding, key ed25519.PublicKey, now time.Time) (Record, error) {
	r := Record{Version: Version, Binding: b, PublicKey: bytes.Clone(key), ClockFloor: now, Jobs: []Job{}}
	return r, Validate(r)
}
func (j Job) Identity() windowsaction.Identity {
	i, _ := windowsaction.IdentityFor(j.Envelope)
	return i
}
func (j Job) Deadline() time.Time {
	p, _ := windowsaction.Decode(j.Envelope)
	return time.Unix(p.Deadline, 0).UTC()
}
func (j Job) State(now time.Time) string {
	if len(j.Results) > 0 {
		r := j.Results[len(j.Results)-1]
		if r.Outcome == "intervention-required" {
			return "needs_intervention"
		}
		if r.Phase == "complete" {
			return "complete"
		}
	}
	if j.ClaimedAt != nil {
		return "claimed"
	}
	if !now.Before(j.Deadline()) {
		return "expired"
	}
	return "approved"
}

// EffectiveClockFloor includes final rejection observations, which never renew
// enrollment authority or any capability, approval, deadline or claim timestamp.
func (r Record) EffectiveClockFloor() time.Time {
	if r.RejectedClockFloor != nil && r.RejectedClockFloor.After(r.ClockFloor) {
		return *r.RejectedClockFloor
	}
	return r.ClockFloor
}
func (r Record) Ready(now time.Time) string {
	if !validTime(now) || now.Before(r.EffectiveClockFloor()) {
		return "clock"
	}
	if len(r.Jobs) >= 64 {
		return "capacity"
	}
	if len(r.Jobs) > 0 {
		switch r.Jobs[len(r.Jobs)-1].State(now) {
		case "approved", "claimed", "needs_intervention":
			return "job_pending"
		}
	}
	c := r.Capabilities
	if c == nil {
		return "awaiting_broker"
	}
	if !c.Enabled {
		return "disabled"
	}
	if c.Busy {
		return "broker_busy"
	}
	if c.CapturedAt > now.Unix() || now.Unix()-c.CapturedAt >= 60 {
		return "stale"
	}
	return "ready"
}
func (r *Record) Report(c windowsaction.Capabilities, now time.Time) error {
	if windowsaction.ValidateCapabilities(c) != nil || c.Binding != r.Binding || c.CapturedAt > now.Unix() || now.Unix()-c.CapturedAt >= 60 {
		return windowsaction.ErrInvalid
	}
	if old := r.Capabilities; old != nil && (c.CapturedAt < old.CapturedAt || c.CapturedAt == old.CapturedAt && c != *old) {
		return ErrConflict
	}
	r.Capabilities = &c
	return nil
}
func (r *Record) MakePreview(id, actor, target, operation string, now time.Time) error {
	if !enrollmentcrypto.ValidID(id, "action_") || !enrollmentcrypto.ValidID(actor, "operator_") || target != r.Binding.Target || !windowsaction.ValidOperation(operation) {
		return windowsaction.ErrInvalid
	}
	if r.Ready(now) != "ready" {
		return windowsaction.ErrUnavailable
	}
	p := Preview{Version: PreviewVersion, ID: id, Binding: r.Binding, Operation: operation, ActorID: actor, Sequence: r.Sequence + 1, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	p.Digest = previewDigest(p)
	r.Preview = &p
	return nil
}
func (r *Record) Approve(id, digest, actor string, now time.Time, sign func(windowsaction.Permit) ([]byte, error)) error {
	for _, j := range r.Jobs {
		if j.Preview.ID == id {
			if j.Preview.Digest == digest && j.Preview.ActorID == actor {
				return nil
			}
			return ErrConflict
		}
	}
	p := r.Preview
	if p == nil || p.ID != id || p.Digest != digest || p.ActorID != actor {
		return ErrConflict
	}
	if !now.Before(p.ExpiresAt) {
		return windowsaction.ErrExpired
	}
	if r.Ready(now) != "ready" {
		return windowsaction.ErrUnavailable
	}
	permit := windowsaction.Permit{Version: windowsaction.Version, Binding: r.Binding, Operation: p.Operation, JobID: p.ID, Sequence: p.Sequence, OperatorID: actor, ApprovalDigest: p.Digest, IssuedAt: now.Unix(), NotBefore: now.Unix(), Deadline: now.Unix() + 60}
	raw, e := sign(permit)
	if e != nil {
		return e
	}
	saved, e := windowsaction.CheckSignature(raw, ed25519.PublicKey(r.PublicKey))
	if e != nil || saved != permit {
		return windowsaction.ErrBinding
	}
	r.Jobs = append(r.Jobs, Job{Preview: *p, ApprovedAt: now, Envelope: bytes.Clone(raw), Results: []windowsaction.Result{}})
	r.Sequence = p.Sequence
	r.Preview = nil
	return nil
}
func (r *Record) Claim(i windowsaction.Identity, now time.Time) (Grant, error) {
	if len(r.Jobs) == 0 {
		return Grant{}, ErrNotFound
	}
	j := &r.Jobs[len(r.Jobs)-1]
	if j.Identity() != i {
		return Grant{}, ErrConflict
	}
	if j.ClaimedAt != nil {
		return Grant{}, windowsaction.ErrConsumed
	}
	if !now.Before(j.Deadline()) {
		return Grant{}, windowsaction.ErrExpired
	}
	c := r.Capabilities
	if c == nil || !c.Enabled || c.Busy || c.CapturedAt > now.Unix() || now.Unix()-c.CapturedAt >= 60 {
		return Grant{}, windowsaction.ErrUnavailable
	}
	j.ClaimedAt = &now
	return Grant{i, bytes.Clone(j.Envelope)}, nil
}
func resultAdvances(a, b windowsaction.Result) bool {
	rank := map[string]int{"admitted": 1, "dispatching": 2, "complete": 3}
	return rank[b.Phase] > rank[a.Phase] && (!a.StopAttempted || b.StopAttempted) && (!a.StopRequested || b.StopRequested) && (!a.StoppedObserved || b.StoppedObserved) && (!a.StartAttempted || b.StartAttempted) && (!a.StartRequested || b.StartRequested) && (!a.RunningObserved || b.RunningObserved) && b.Observations >= a.Observations
}
func (r *Record) Accept(result windowsaction.Result) error {
	if windowsaction.ValidateResult(result) != nil {
		return windowsaction.ErrInvalid
	}
	for n := range r.Jobs {
		j := &r.Jobs[n]
		if j.Identity() != result.Identity {
			continue
		}
		if j.ClaimedAt == nil || result.Operation != j.Preview.Operation || result.Target != j.Preview.Binding.Target || result.Deadline != j.Deadline().Unix() {
			return ErrConflict
		}
		for _, old := range j.Results {
			if old == result {
				return nil
			}
		}
		if len(j.Results) >= 3 || len(j.Results) > 0 && !resultAdvances(j.Results[len(j.Results)-1], result) {
			return ErrConflict
		}
		j.Results = append(j.Results, result)
		return nil
	}
	return ErrNotFound
}
func Validate(r Record) error {
	if r.RejectedClockFloor != nil && !validTime(*r.RejectedClockFloor) {
		return windowsaction.ErrIntegrity
	}
	if r.Version != Version || !windowsaction.ValidBinding(r.Binding) || !keyvalidation.Ed25519(r.PublicKey) || windowsaction.Digest(r.PublicKey) != r.Binding.KeyID || !validTime(r.ClockFloor) || len(r.Jobs) > 64 || r.Sequence != uint64(len(r.Jobs)) {
		return windowsaction.ErrIntegrity
	}
	if c := r.Capabilities; c != nil && (windowsaction.ValidateCapabilities(*c) != nil || c.Binding != r.Binding || c.CapturedAt > r.ClockFloor.Unix()) {
		return windowsaction.ErrIntegrity
	}
	if p := r.Preview; p != nil && (!validPreview(*p, r.Binding) || p.Sequence != r.Sequence+1 || p.CreatedAt.After(r.ClockFloor)) {
		return windowsaction.ErrIntegrity
	}
	ids := map[string]bool{}
	for n, j := range r.Jobs {
		p := j.Preview
		if !validPreview(p, r.Binding) || p.Sequence != uint64(n+1) || ids[p.ID] || !validTime(j.ApprovedAt) || j.ApprovedAt.Before(p.CreatedAt) || !j.ApprovedAt.Before(p.ExpiresAt) || j.ApprovedAt.After(r.ClockFloor) || len(j.Results) > 3 {
			return windowsaction.ErrIntegrity
		}
		ids[p.ID] = true
		permit, e := windowsaction.CheckSignature(j.Envelope, ed25519.PublicKey(r.PublicKey))
		if e != nil || permit.Binding != r.Binding || permit.JobID != p.ID || permit.Sequence != p.Sequence || permit.OperatorID != p.ActorID || permit.ApprovalDigest != p.Digest || permit.Operation != p.Operation || permit.IssuedAt != j.ApprovedAt.Unix() || permit.NotBefore != permit.IssuedAt || permit.Deadline != permit.IssuedAt+60 {
			return windowsaction.ErrIntegrity
		}
		if j.ClaimedAt != nil && (!validTime(*j.ClaimedAt) || j.ClaimedAt.Before(j.ApprovedAt) || !j.ClaimedAt.Before(j.Deadline()) || j.ClaimedAt.After(r.ClockFloor)) {
			return windowsaction.ErrIntegrity
		}
		if len(j.Results) > 0 && j.ClaimedAt == nil {
			return windowsaction.ErrIntegrity
		}
		for k, result := range j.Results {
			if windowsaction.ValidateResult(result) != nil || result.Identity != j.Identity() || result.Operation != p.Operation || result.Target != r.Binding.Target || result.Deadline != permit.Deadline || k > 0 && !resultAdvances(j.Results[k-1], result) {
				return windowsaction.ErrIntegrity
			}
		}
	}
	return nil
}
