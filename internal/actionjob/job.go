// Package actionjob is the bounded durable manager workflow for one typed action.
// It never executes actions, provisions trust, or infers human approval.
package actionjob

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/actionhelper"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

const (
	Version         = "tracebolt.service-action-record.v1"
	PreviewVersion  = "tracebolt.service-action-preview.v1"
	ApprovalVersion = "tracebolt.service-action-approval.v1"
	MaxJobs         = 64
	MaxRecordBytes  = 512 << 10
	Freshness       = 60 * time.Second
	PreviewLifetime = 60 * time.Second
	Approved        = "approved"
	Claimed         = "claimed"
)

var (
	ErrInvalid     = errors.New("service_action_invalid")
	ErrUnavailable = errors.New("service_action_unavailable")
	ErrConflict    = errors.New("service_action_conflict")
	ErrExpired     = errors.New("service_action_expired")
	ErrConsumed    = errors.New("service_action_consumed")
	ErrCapacity    = errors.New("service_action_capacity")
	ErrNotFound    = errors.New("service_action_not_found")
)

type Identity struct {
	JobID          string `json:"jobId"`
	Sequence       uint64 `json:"sequence,string"`
	EnvelopeDigest string `json:"envelopeDigest"`
}
type Delivery struct {
	Identity      Identity  `json:"identity"`
	State         string    `json:"state"`
	StartDeadline time.Time `json:"startDeadline"`
}
type Grant struct {
	Identity Identity `json:"identity"`
	Envelope []byte   `json:"envelope"`
}
type Preview struct {
	Version           string            `json:"version"`
	ID                string            `json:"id"`
	DeviceID          string            `json:"deviceId"`
	ActorID           string            `json:"actorId"`
	Sequence          uint64            `json:"sequence,string"`
	Plan              actionpermit.Plan `json:"plan"`
	PlanDigest        string            `json:"planDigest"`
	RootPolicyDigest  string            `json:"rootPolicyDigest"`
	KeyID             string            `json:"keyId"`
	IncarnationDigest string            `json:"incarnationDigest"`
	TransportProfile  string            `json:"transportProfile"`
	CreatedAt         time.Time         `json:"createdAt"`
	ExpiresAt         time.Time         `json:"expiresAt"`
	Digest            string            `json:"digest"`
}
type Approval struct {
	Version       string    `json:"version"`
	PreviewDigest string    `json:"previewDigest"`
	ActorID       string    `json:"actorId"`
	ApprovedAt    time.Time `json:"approvedAt"`
}
type Job struct {
	Preview          Preview               `json:"preview"`
	Approval         Approval              `json:"approval"`
	Envelope         []byte                `json:"envelope"`
	ClaimedAt        *time.Time            `json:"claimedAt"`
	Results          []actionhelper.Result `json:"results"`
	ResultReceivedAt []time.Time           `json:"resultReceivedAt"`
}
type Record struct {
	Version                string                     `json:"version"`
	ManagerID              string                     `json:"managerId"`
	PublicKey              []byte                     `json:"publicKey"`
	DeviceID               string                     `json:"deviceId"`
	IncarnationDigest      string                     `json:"incarnationDigest"`
	ClockFloor             time.Time                  `json:"clockFloor"`
	Capabilities           *actionhelper.Capabilities `json:"capabilities"`
	CapabilitiesReceivedAt *time.Time                 `json:"capabilitiesReceivedAt"`
	Preview                *Preview                   `json:"preview"`
	Jobs                   []Job                      `json:"jobs"`
}

func ValidIdentity(i Identity) bool {
	return enrollmentcrypto.ValidID(i.JobID, "action_") && i.Sequence > 0 && actionpermit.ValidDigest(i.EnvelopeDigest)
}
func ValidTime(t time.Time) bool {
	return t.Location() == time.UTC && t.Unix() > 0 && t.Unix() <= 253402300799
}
func digest(v any) string              { b, _ := json.Marshal(v); return actionpermit.Digest(b) }
func PreviewDigest(p Preview) string   { p.Digest = ""; return digest(p) }
func ApprovalDigest(a Approval) string { return digest(a) }
func validPreview(p Preview) bool {
	d, e := actionpermit.PlanDigest(p.Plan)
	return e == nil && p.Version == PreviewVersion && enrollmentcrypto.ValidID(p.ID, "action_") && enrollmentcrypto.ValidID(p.DeviceID, "agent_") && enrollmentcrypto.ValidID(p.ActorID, "operator_") && p.Sequence > 0 && p.PlanDigest == d && actionpermit.ValidDigest(p.RootPolicyDigest) && actionpermit.ValidDigest(p.KeyID) && actionpermit.ValidDigest(p.IncarnationDigest) && (p.TransportProfile == actionhelper.ProductionTLS || p.TransportProfile == actionhelper.DisposableHTTPTest) && ValidTime(p.CreatedAt) && ValidTime(p.ExpiresAt) && p.ExpiresAt.Equal(p.CreatedAt.Add(PreviewLifetime)) && p.Digest == PreviewDigest(p)
}
func New(manager, device, incarnation string, key ed25519.PublicKey, now time.Time) (Record, error) {
	r := Record{Version: Version, ManagerID: manager, DeviceID: device, IncarnationDigest: incarnation, PublicKey: bytes.Clone(key), ClockFloor: now, Jobs: []Job{}}
	if Validate(r) != nil {
		return Record{}, ErrInvalid
	}
	return r, nil
}
func Validate(r Record) error {
	if r.Version != Version || !enrollmentcrypto.ValidID(r.ManagerID, "manager_") || !enrollmentcrypto.ValidID(r.DeviceID, "agent_") || !actionpermit.ValidDigest(r.IncarnationDigest) || !keyvalidation.Ed25519(r.PublicKey) || !ValidTime(r.ClockFloor) || len(r.Jobs) > MaxJobs || r.Jobs == nil {
		return ErrInvalid
	}
	if (r.Capabilities == nil) != (r.CapabilitiesReceivedAt == nil) {
		return ErrInvalid
	}
	if r.Capabilities != nil {
		c := *r.Capabilities
		if actionhelper.ValidateCapabilities(c) != nil || c.ManagerID != r.ManagerID || c.EndpointID != r.DeviceID || c.IncarnationDigest != r.IncarnationDigest || c.KeyID != actionpermit.Digest(r.PublicKey) || !ValidTime(*r.CapabilitiesReceivedAt) || r.CapabilitiesReceivedAt.After(r.ClockFloor) || time.Unix(c.CapturedAt, 0).After(r.CapabilitiesReceivedAt.Add(5*time.Second)) {
			return ErrInvalid
		}
	}
	ids := map[string]bool{}
	for n, j := range r.Jobs {
		p := j.Preview
		if !validPreview(p) || p.DeviceID != r.DeviceID || p.KeyID != actionpermit.Digest(r.PublicKey) || p.IncarnationDigest != r.IncarnationDigest || p.Sequence != uint64(n+1) || ids[p.ID] || p.CreatedAt.After(r.ClockFloor) {
			return ErrInvalid
		}
		ids[p.ID] = true
		a := j.Approval
		if a.Version != ApprovalVersion || a.PreviewDigest != p.Digest || a.ActorID != p.ActorID || !ValidTime(a.ApprovedAt) || a.ApprovedAt.Before(p.CreatedAt) || !a.ApprovedAt.Before(p.ExpiresAt) || a.ApprovedAt.After(r.ClockFloor) {
			return ErrInvalid
		}
		permit, e := actionpermit.Decode(j.Envelope)
		if e != nil || permit.ManagerID != r.ManagerID || permit.KeyID != p.KeyID || permit.EndpointID != p.DeviceID || permit.IncarnationDigest != p.IncarnationDigest || permit.JobID != p.ID || permit.Sequence != p.Sequence || permit.Plan != p.Plan || permit.PlanDigest != p.PlanDigest || permit.OperatorID != p.ActorID || permit.ApprovalDigest != ApprovalDigest(a) || permit.RootPolicyDigest != p.RootPolicyDigest || permit.IssuedAt != a.ApprovedAt.Unix() || permit.NotBefore != permit.IssuedAt {
			return ErrInvalid
		}
		v, e := actionpermit.NewVerifier(actionpermit.LocalPins{ManagerID: r.ManagerID, PublicKey: r.PublicKey, EndpointID: r.DeviceID, IncarnationDigest: r.IncarnationDigest, RootPolicyDigest: p.RootPolicyDigest, MaxLifetimeSeconds: 120, Services: []actionpermit.ServiceRule{{Unit: p.Plan.Unit, UnitPolicyDigest: p.Plan.UnitPolicyDigest}}})
		if e != nil {
			return ErrInvalid
		}
		if _, e = v.CheckSignature(j.Envelope); e != nil {
			return ErrInvalid
		}
		if j.ClaimedAt != nil && (!ValidTime(*j.ClaimedAt) || j.ClaimedAt.Before(a.ApprovedAt) || j.ClaimedAt.Unix() >= permit.StartDeadline || j.ClaimedAt.After(r.ClockFloor)) {
			return ErrInvalid
		}
		if len(j.Results) > 3 || len(j.Results) != len(j.ResultReceivedAt) || len(j.Results) > 0 && j.ClaimedAt == nil {
			return ErrInvalid
		}
		for k, result := range j.Results {
			if validJobResult(j, result, j.ResultReceivedAt[k]) != nil || j.ResultReceivedAt[k].After(r.ClockFloor) {
				return ErrInvalid
			}
			if k > 0 && (transition(j.Results[k-1], result) != nil || j.ResultReceivedAt[k].Before(j.ResultReceivedAt[k-1])) {
				return ErrInvalid
			}
		}
		if n < len(r.Jobs)-1 && !CanFollow(j, r.Jobs[n+1].Preview.CreatedAt) {
			return ErrInvalid
		}
	}
	if r.Preview != nil {
		p := *r.Preview
		if !validPreview(p) || p.DeviceID != r.DeviceID || p.KeyID != actionpermit.Digest(r.PublicKey) || p.IncarnationDigest != r.IncarnationDigest || p.Sequence != uint64(len(r.Jobs)+1) || ids[p.ID] || p.CreatedAt.After(r.ClockFloor) || len(r.Jobs) > 0 && !CanFollow(r.Jobs[len(r.Jobs)-1], p.CreatedAt) {
			return ErrInvalid
		}
	}
	return nil
}
func (j Job) Identity() Identity {
	return Identity{j.Preview.ID, j.Preview.Sequence, actionpermit.Digest(j.Envelope)}
}
func (j Job) Deadline() time.Time {
	p, e := actionpermit.Decode(j.Envelope)
	if e != nil {
		return time.Time{}
	}
	return time.Unix(p.StartDeadline, 0).UTC()
}
func (j Job) State(now time.Time) string {
	if len(j.Results) > 0 {
		p := j.Results[len(j.Results)-1].Phase
		if p != actionstate.Admitted && p != actionstate.Dispatching {
			return p
		}
	}
	if j.ClaimedAt != nil {
		return Claimed
	}
	if !now.Before(j.Deadline()) {
		return actionstate.Expired
	}
	return Approved
}
func CanFollow(j Job, now time.Time) bool {
	s := j.State(now)
	return s == actionstate.OperationCompleted || s == actionstate.NotStarted || s == actionstate.Expired
}
func (r Record) Ready(profile string, now time.Time) string {
	if len(r.Jobs) >= MaxJobs {
		return "capacity"
	}
	if len(r.Jobs) > 0 && !CanFollow(r.Jobs[len(r.Jobs)-1], now) {
		if r.Jobs[len(r.Jobs)-1].State(now) == actionstate.NeedsIntervention {
			return "needs_intervention"
		}
		return "action_in_progress"
	}
	if r.Capabilities == nil {
		return "helper_unavailable"
	}
	c := r.Capabilities
	if !c.Enabled {
		return "helper_disabled"
	}
	if c.TransportProfile != profile || (profile == actionhelper.DisposableHTTPTest && !c.HTTPTestAcknowledged) {
		return "helper_unavailable"
	}
	if !ValidTime(now) || now.Before(r.ClockFloor) || now.Unix() < c.CapturedAt-5 || now.Sub(time.Unix(c.CapturedAt, 0)) >= Freshness || r.CapabilitiesReceivedAt == nil || now.Before(*r.CapabilitiesReceivedAt) || now.Sub(*r.CapabilitiesReceivedAt) >= Freshness {
		return "helper_stale"
	}
	return "ready"
}
func (r *Record) Report(c actionhelper.Capabilities, now time.Time) error {
	if Validate(*r) != nil || !ValidTime(now) || now.Before(r.ClockFloor) || actionhelper.ValidateCapabilities(c) != nil || c.ManagerID != r.ManagerID || c.EndpointID != r.DeviceID || c.IncarnationDigest != r.IncarnationDigest || c.KeyID != actionpermit.Digest(r.PublicKey) || now.Unix() < c.CapturedAt-5 || now.Sub(time.Unix(c.CapturedAt, 0)) >= Freshness {
		return ErrInvalid
	}
	if r.Capabilities != nil && c.CapturedAt < r.Capabilities.CapturedAt {
		return ErrConflict
	}
	if r.Capabilities != nil && c.CapturedAt == r.Capabilities.CapturedAt {
		if digest(c) != digest(*r.Capabilities) {
			return ErrConflict
		}
		return nil
	}
	r.Capabilities = &c
	r.CapabilitiesReceivedAt = &now
	r.ClockFloor = now
	return nil
}
func (r *Record) MakePreview(id, actor, unit, profile string, now time.Time) (Preview, error) {
	if Validate(*r) != nil || r.Ready(profile, now) != "ready" {
		return Preview{}, ErrUnavailable
	}
	var plan actionpermit.Plan
	for _, s := range r.Capabilities.Services {
		if s.Unit == unit {
			plan = actionpermit.Plan{Version: actionpermit.PlanVersion, Action: actionpermit.TryRestartService, Unit: unit, UnitPolicyDigest: s.UnitPolicyDigest}
		}
	}
	d, e := actionpermit.PlanDigest(plan)
	if e != nil {
		return Preview{}, ErrInvalid
	}
	p := Preview{Version: PreviewVersion, ID: id, DeviceID: r.DeviceID, ActorID: actor, Sequence: uint64(len(r.Jobs) + 1), Plan: plan, PlanDigest: d, RootPolicyDigest: r.Capabilities.RootPolicyDigest, KeyID: r.Capabilities.KeyID, IncarnationDigest: r.IncarnationDigest, TransportProfile: profile, CreatedAt: now, ExpiresAt: now.Add(PreviewLifetime)}
	p.Digest = PreviewDigest(p)
	if !validPreview(p) {
		return Preview{}, ErrInvalid
	}
	r.Preview = &p
	r.ClockFloor = now
	return p, nil
}

// Approve returns metadata only. The signed bytes remain internal until Claim.
func (r *Record) Approve(id, previewDigest, actor, profile string, now time.Time, sign func(actionpermit.Permit) ([]byte, error)) (Job, error) {
	if Validate(*r) != nil || !ValidTime(now) || now.Before(r.ClockFloor) {
		return Job{}, ErrInvalid
	}
	for _, j := range r.Jobs {
		if j.Preview.ID == id {
			if j.Preview.Digest != previewDigest || j.Preview.ActorID != actor {
				return Job{}, ErrConflict
			}
			return j, nil
		}
	}
	if r.Preview == nil || r.Preview.ID != id || r.Preview.Digest != previewDigest || r.Preview.ActorID != actor {
		return Job{}, ErrConflict
	}
	p := *r.Preview
	if !now.Before(p.ExpiresAt) {
		return Job{}, ErrExpired
	}
	if r.Ready(profile, now) != "ready" || p.TransportProfile != profile || p.RootPolicyDigest != r.Capabilities.RootPolicyDigest {
		return Job{}, ErrUnavailable
	}
	match := false
	for _, s := range r.Capabilities.Services {
		if s.Unit == p.Plan.Unit && s.UnitPolicyDigest == p.Plan.UnitPolicyDigest {
			match = true
		}
	}
	if !match || sign == nil {
		return Job{}, ErrUnavailable
	}
	a := Approval{ApprovalVersion, p.Digest, actor, now}
	life := r.Capabilities.MaxLifetimeSeconds
	if life > 60 {
		life = 60
	}
	permit := actionpermit.Permit{Version: actionpermit.Version, ManagerID: r.ManagerID, KeyID: p.KeyID, EndpointID: r.DeviceID, IncarnationDigest: r.IncarnationDigest, JobID: id, Sequence: p.Sequence, Plan: p.Plan, PlanDigest: p.PlanDigest, OperatorID: actor, ApprovalDigest: ApprovalDigest(a), RootPolicyDigest: p.RootPolicyDigest, IssuedAt: now.Unix(), NotBefore: now.Unix(), StartDeadline: now.Unix() + life}
	raw, e := sign(permit)
	if e != nil {
		return Job{}, ErrUnavailable
	}
	signedPermit, decodeErr := actionpermit.Decode(raw)
	if decodeErr != nil || signedPermit != permit {
		return Job{}, ErrInvalid
	}
	j := Job{Preview: p, Approval: a, Envelope: raw, Results: []actionhelper.Result{}, ResultReceivedAt: []time.Time{}}
	copy := *r
	copy.Jobs = append(append([]Job{}, r.Jobs...), j)
	copy.Preview = nil
	copy.ClockFloor = now
	if Validate(copy) != nil {
		return Job{}, ErrInvalid
	}
	*r = copy
	return j, nil
}
func (r *Record) Claim(id Identity, profile string, now time.Time) (Grant, error) {
	if Validate(*r) != nil || !ValidTime(now) || now.Before(r.ClockFloor) || !ValidIdentity(id) {
		return Grant{}, ErrInvalid
	}
	if len(r.Jobs) == 0 {
		return Grant{}, ErrNotFound
	}
	j := &r.Jobs[len(r.Jobs)-1]
	if j.Identity() != id {
		return Grant{}, ErrConflict
	}
	if j.ClaimedAt != nil {
		return Grant{}, ErrConsumed
	}
	if !now.Before(j.Deadline()) {
		return Grant{}, ErrExpired
	}
	if r.Capabilities == nil || !r.Capabilities.Enabled || r.Capabilities.TransportProfile != profile || j.Preview.TransportProfile != profile || r.Capabilities.RootPolicyDigest != j.Preview.RootPolicyDigest || now.Sub(time.Unix(r.Capabilities.CapturedAt, 0)) >= Freshness {
		return Grant{}, ErrUnavailable
	}
	j.ClaimedAt = &now
	r.ClockFloor = now
	return Grant{id, bytes.Clone(j.Envelope)}, nil
}
func validJobResult(j Job, x actionhelper.Result, received time.Time) error {
	if actionhelper.ValidateResult(x) != nil || j.ClaimedAt == nil || !ValidTime(received) || received.Before(*j.ClaimedAt) || x.JobID != j.Preview.ID || x.Sequence != j.Preview.Sequence || x.EnvelopeDigest != actionpermit.Digest(j.Envelope) || x.ConsumedAt < j.Approval.ApprovedAt.Add(-5*time.Second).UnixMicro() || ((x.Phase != actionstate.Expired && x.ConsumedAt >= j.Deadline().UnixMicro()) || (x.Phase == actionstate.Expired && (x.ConsumedAt < j.Deadline().UnixMicro() || x.DispatchAt != 0))) || x.DispatchAt >= j.Deadline().UnixMicro() || x.TransitionAt > received.Add(5*time.Second).UnixMicro() {
		return ErrInvalid
	}
	return nil
}
func transition(a, b actionhelper.Result) error {
	if a == b {
		return nil
	}
	if a.JobID != b.JobID || a.Sequence != b.Sequence || a.EnvelopeDigest != b.EnvelopeDigest || a.ConsumedAt != b.ConsumedAt || b.TransitionAt < a.TransitionAt || (a.DispatchAt != 0 && a.DispatchAt != b.DispatchAt) {
		return ErrConflict
	}
	if b.Phase == actionstate.Expired {
		return ErrConflict
	}
	switch a.Phase {
	case actionstate.Admitted:
		if b.Phase == actionstate.Admitted {
			return ErrConflict
		}
	case actionstate.Dispatching:
		if b.Phase == actionstate.Admitted || b.Phase == actionstate.Dispatching {
			return ErrConflict
		}
	default:
		return ErrConflict
	}
	return nil
}
func (r *Record) Accept(x actionhelper.Result, now time.Time) error {
	if Validate(*r) != nil || !ValidTime(now) || now.Before(r.ClockFloor) {
		return ErrInvalid
	}
	for n := range r.Jobs {
		j := &r.Jobs[n]
		if j.Preview.ID != x.JobID {
			continue
		}
		if validJobResult(*j, x, now) != nil {
			return ErrInvalid
		}
		for _, old := range j.Results {
			if old == x {
				return nil
			}
		}
		if len(j.Results) >= 3 {
			return ErrCapacity
		}
		if len(j.Results) > 0 && transition(j.Results[len(j.Results)-1], x) != nil {
			return ErrConflict
		}
		j.Results = append(j.Results, x)
		j.ResultReceivedAt = append(j.ResultReceivedAt, now)
		r.ClockFloor = now
		return nil
	}
	return ErrNotFound
}

// ObserveExpiry makes observed deadlines a durable clock lower bound. A manager
// rollback must never turn expired, unclaimed authority back into a live grant.
// It deliberately does not expire or cancel a claimed execution.
func (r *Record) ObserveExpiry(now time.Time) bool {
	if !ValidTime(now) || now.Before(r.ClockFloor) {
		return false
	}
	floor := r.ClockFloor
	if r.Preview != nil && !now.Before(r.Preview.ExpiresAt) && r.Preview.ExpiresAt.After(floor) {
		floor = r.Preview.ExpiresAt
	}
	if len(r.Jobs) > 0 {
		j := r.Jobs[len(r.Jobs)-1]
		if j.ClaimedAt == nil && !now.Before(j.Deadline()) && j.Deadline().After(floor) {
			floor = j.Deadline()
		}
	}
	if floor.After(r.ClockFloor) {
		r.ClockFloor = floor
		return true
	}
	return false
}
