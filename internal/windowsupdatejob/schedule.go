package windowsupdatejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
)

const BackgroundScheduleDisclosure = "Allow a named operator with both install and scheduling permission to approve one exact cached Windows update revision for one immutable UTC dispatch window of 1–60 minutes starting within 24 hours. The separately activated background service and authenticated observer must be available. Fresh signed matching readiness and active-idle shared-owner evidence are required before one short-lived permit. Approval consumes one of the original 32 jobs even if canceled, blocked or expired. Installation can continue past the window; no downloads, license acceptance, reboot, automatic retry or unlock is authorized."

const ScheduleVersion = "tracebolt.windows-selected-update-schedule.v1"
const ScheduleDisclosure = "Allow a named operator to prospectively approve one exact cached Windows update revision for one fixed UTC start window. At the first eligible authenticated observer poll within that window, fresh signed readiness must match the reviewed facts before one short-lived installation permit may be issued. Installation may interrupt applications and continue past the window. The elevated executor must be separately launched in the foreground. No download, license acceptance, automatic reboot, automatic retry or persistent elevated service is authorized. Cancellation after delivery cannot stop installation."

// ScheduleApproval is prospective authority, distinct from the later issuance
// time. Its original reviewed facts, window, grant and generation never renew.
type ScheduleApproval struct {
	Version            string  `json:"version"`
	Baseline           Preview `json:"baseline"`
	ApprovedAt         int64   `json:"approvedAt"`
	StartAt            int64   `json:"startAt"`
	EndAt              int64   `json:"endAt"`
	AuthorityExpiresAt int64   `json:"authorityExpiresAt"`
	Generation         uint64  `json:"generation,string"`
	Digest             string  `json:"digest"`
}

func scheduleDigest(a ScheduleApproval) string {
	a.Digest = ""
	b, _ := json.Marshal(a)
	return actionpermit.Digest(append([]byte("Tracebolt prospective cached WUA schedule v1\x00"), b...))
}
func (a ScheduleApproval) Validate() error {
	if a.Version != ScheduleVersion || a.Baseline.Validate() != nil || a.Baseline.Readiness.Purpose != "" || a.Baseline.Readiness.Reason() != "ready" || a.ApprovedAt < a.Baseline.CreatedAt || a.ApprovedAt >= a.Baseline.ExpiresAt || a.StartAt <= a.ApprovedAt || a.StartAt-a.ApprovedAt > 86400 || !validTime(a.EndAt) || a.EndAt-a.StartAt < 60 || a.EndAt-a.StartAt > 3600 || !validTime(a.AuthorityExpiresAt) || a.EndAt > a.AuthorityExpiresAt || a.Generation != 1 || a.Digest != scheduleDigest(a) {
		return ErrInvalid
	}
	return nil
}
func (p Permit) IssuedAt() int64 {
	if p.Schedule != nil {
		return p.PermitIssuedAt
	}
	return p.ApprovedAt
}
func (p Permit) validateScheduled() error {
	a := p.Schedule
	if a == nil || (p.Version != ScheduledPermitVersion && p.Version != ReusablePermitVersion) || a.Validate() != nil || p.Preview.Validate() != nil || p.Sequence == 0 || p.ApprovedAt != a.ApprovedAt || p.PermitIssuedAt < p.Preview.CreatedAt || p.PermitIssuedAt >= p.Preview.ExpiresAt || p.PermitIssuedAt < a.StartAt || p.Preview.ExpiresAt > a.EndAt || p.Preview.ID != a.Baseline.ID || p.Preview.ActorID != a.Baseline.ActorID || p.Preview.Binding != a.Baseline.Binding || !SameFacts(p.Preview.Readiness, a.Baseline.Readiness) || p.Preview.Readiness.CapturedAt < a.StartAt {
		return ErrInvalid
	}
	return nil
}

type ScheduledIntent struct {
	Approval          ScheduleApproval `json:"approval"`
	BaselineChallenge []byte           `json:"baselineChallenge"`
	BaselineReport    []byte           `json:"baselineReport"`
	TriggeredAt       int64            `json:"triggeredAt"`
	OutcomeAt         int64            `json:"outcomeAt"`
}
type ScheduleView struct {
	Version        string `json:"version"`
	Digest         string `json:"digest"`
	ApprovedAt     int64  `json:"approvedAt"`
	StartAt        int64  `json:"startAt"`
	EndAt          int64  `json:"endAt"`
	PermitIssuedAt int64  `json:"permitIssuedAt"`
	Revoked        bool   `json:"revoked"`
}

func scheduleView(j Job) *ScheduleView {
	if j.Schedule == nil {
		return nil
	}
	a := j.Schedule.Approval
	v := &ScheduleView{Version: ScheduleVersion, Digest: a.Digest, ApprovedAt: a.ApprovedAt, StartAt: a.StartAt, EndAt: a.EndAt, Revoked: j.Reason == "schedule_authority_revoked"}
	if len(j.Envelope) > 0 {
		v.PermitIssuedAt = j.Preview.CreatedAt
	}
	return v
}
func reservedOperations(r Record) int {
	n := 0
	for _, j := range r.Jobs {
		if len(j.Envelope) > 0 || j.Schedule != nil {
			n++
		}
	}
	return n
}
func (r Record) validateScheduleAuthority() error {
	if !r.Consent.ScheduleAcknowledged {
		if r.ScheduleGeneration != 0 || r.ScheduleRevokedAt != 0 || r.SchedulePolicyFloor != 0 {
			return ErrIntegrity
		}
		for _, j := range r.Jobs {
			if j.Schedule != nil {
				return ErrIntegrity
			}
		}
		return nil
	}
	if r.SchedulePolicyFloor != 0 && !validTime(r.SchedulePolicyFloor) {
		return ErrIntegrity
	}
	if r.ScheduleGeneration != 1 && r.ScheduleGeneration != 2 || r.ScheduleGeneration == 1 && r.ScheduleRevokedAt != 0 || r.ScheduleGeneration == 2 && (!validTime(r.ScheduleRevokedAt) || r.ScheduleRevokedAt > r.ClockFloor) {
		return ErrIntegrity
	}
	return nil
}
func (r Record) validateScheduledJob(j Job) error {
	s := j.Schedule
	a := s.Approval
	if j.Download() || !r.Consent.ScheduleAcknowledged || a.Validate() != nil || a.Baseline.ID != j.ID || a.Baseline.ActorID != j.ActorID || a.Baseline.Binding != r.Consent.Binding || a.Baseline.Readiness.Selection != j.Selection || a.ApprovedAt > r.ClockFloor || a.EndAt > r.Consent.ExpiresAt {
		return ErrIntegrity
	}
	c, e := VerifyChallenge(s.BaselineChallenge, r.PublicKey)
	if e != nil || c.JobID != j.ID || c.Binding != r.Consent.Binding || c.Selection != j.Selection || c.IssuedAt > a.Baseline.CreatedAt || c.Deadline < a.Baseline.ExpiresAt {
		return ErrIntegrity
	}
	report, e := VerifyStatement(s.BaselineReport, r.ExecutorPublicKey)
	if e != nil || report.Kind != "readiness" || report.Binding != r.Consent.Binding || report.JobID != j.ID || report.ReferenceDigest != actionpermit.Digest(s.BaselineChallenge) || report.Readiness == nil || *report.Readiness != a.Baseline.Readiness || report.Deadline != c.Deadline || report.ExpiresAt < a.Baseline.ExpiresAt {
		return ErrIntegrity
	}
	if s.TriggeredAt == 0 {
		if !bytes.Equal(j.Challenge, s.BaselineChallenge) || !bytes.Equal(j.ReadinessReport, s.BaselineReport) || j.Preview == nil || *j.Preview != a.Baseline || j.RequestedAt != c.IssuedAt || len(j.Envelope) != 0 || j.State != "scheduled" && j.State != "schedule_canceled" && j.State != "schedule_blocked" && j.State != "schedule_expired" {
			return ErrIntegrity
		}
	} else {
		fresh, e := VerifyChallenge(j.Challenge, r.PublicKey)
		if e != nil || s.TriggeredAt < a.StartAt || s.TriggeredAt >= a.EndAt || s.TriggeredAt > r.ClockFloor || j.RequestedAt != s.TriggeredAt || fresh.Sequence <= c.Sequence || fresh.Deadline > a.EndAt || bytes.Equal(j.Challenge, s.BaselineChallenge) || j.State == "scheduled" || j.State == "preview" {
			return ErrIntegrity
		}
	}
	terminal := j.State == "schedule_canceled" || j.State == "schedule_blocked" || j.State == "schedule_expired"
	if terminal {
		if s.OutcomeAt < a.ApprovedAt || s.OutcomeAt > max(r.ClockFloor, r.SchedulePolicyFloor) {
			return ErrIntegrity
		}
	} else if s.OutcomeAt != 0 {
		return ErrIntegrity
	}
	if len(j.Envelope) > 0 {
		p, e := Verify(j.Envelope, r.PublicKey)
		if e != nil || p.Schedule == nil || *p.Schedule != a {
			return ErrIntegrity
		}
	}
	if r.ScheduleRevokedAt != 0 && (j.State == "scheduled" || j.State == "requested" || j.State == "approved") {
		return ErrIntegrity
	}
	return nil
}
func scheduleActive(j Job, n int64) bool {
	if j.Schedule == nil {
		return false
	}
	switch j.State {
	case "scheduled":
		return n < j.Schedule.Approval.EndAt
	case "requested":
		var e challengeEnvelope
		if json.Unmarshal(j.Challenge, &e) != nil {
			return true
		} // corrupted state remains blocking
		return n < min(e.Challenge.Deadline, j.Schedule.Approval.EndAt)
	case "approved":
		return j.Preview != nil && n < j.Preview.ExpiresAt
	case "claimed":
		return true
	}
	return false
}
func (m *Manager) schedulingAvailable(actor string) bool {
	return m.record.Consent.ScheduleAcknowledged && m.record.ScheduleGeneration == 1 && m.record.ScheduleRevokedAt == 0 && m.scheduleAllowed != nil && m.scheduleAllowed(actor) && m.operatorAllowed != nil && m.operatorAllowed(actor)
}
func (m *Manager) scheduleAuthorized(j *Job) bool {
	return j.Schedule != nil && j.Schedule.Approval.Generation == m.record.ScheduleGeneration && m.schedulingAvailable(j.ActorID)
}

func (m *Manager) Schedule(ctx context.Context, device, actor, id, d string, start, end int64, ack bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if device != m.Binding().DeviceID || !ack || !enrollmentcrypto.ValidID(actor, "operator_") || !actionpermit.ValidDigest(d) {
		return ErrInvalid
	}
	return m.transaction(ctx, func(c Current, n int64) error {
		if !m.schedulingAvailable(actor) {
			return ErrAuthority
		}
		for i := range m.record.Jobs {
			j := &m.record.Jobs[i]
			if j.ID != id {
				continue
			}
			if j.Schedule != nil {
				a := j.Schedule.Approval
				if a.Baseline.Digest == d && a.Baseline.ActorID == actor && a.StartAt == start && a.EndAt == end {
					return nil
				}
				return ErrConflict
			}
			if j.Download() || j.ActorID != actor || j.State != "preview" || j.Preview == nil || j.Preview.Digest != d || len(j.ReadinessReport) == 0 {
				return ErrConflict
			}
			if n >= j.Preview.ExpiresAt || m.blocked(n, id) {
				return ErrExpired
			}
			a := ScheduleApproval{Version: ScheduleVersion, Baseline: *j.Preview, ApprovedAt: n, StartAt: start, EndAt: end, AuthorityExpiresAt: min(c.LeafNotAfter, m.record.Consent.ExpiresAt), Generation: m.record.ScheduleGeneration}
			a.Digest = scheduleDigest(a)
			if a.Validate() != nil {
				return ErrInvalid
			}
			if m.record.Consent.Reusable() {
				if m.record.Sequence == ^uint64(0) {
					return ErrConflict
				}
				m.record.Sequence++
				j.Occurrence = m.record.Sequence
			}
			j.Schedule = &ScheduledIntent{Approval: a, BaselineChallenge: bytes.Clone(j.Challenge), BaselineReport: bytes.Clone(j.ReadinessReport)}
			j.State = "scheduled"
			j.Reason = "schedule_waiting"
			return m.save(n)
		}
		return ErrConflict
	})
}
func (m *Manager) CancelSchedule(ctx context.Context, device, actor, id, d string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if device != m.Binding().DeviceID || !enrollmentcrypto.ValidID(actor, "operator_") || !actionpermit.ValidDigest(d) {
		return ErrInvalid
	}
	return m.transaction(ctx, func(_ Current, n int64) error {
		if m.scheduleAllowed == nil || !m.scheduleAllowed(actor) || m.operatorAllowed == nil || !m.operatorAllowed(actor) {
			return ErrAuthority
		}
		for i := range m.record.Jobs {
			j := &m.record.Jobs[i]
			if j.ID != id {
				continue
			}
			if j.Schedule == nil || j.ActorID != actor || j.Schedule.Approval.Digest != d {
				return ErrConflict
			}
			if j.State == "schedule_canceled" {
				return nil
			}
			if j.ClaimedAt != 0 || j.State == "complete" {
				return ErrConsumed
			}
			if j.State != "scheduled" && j.State != "requested" && j.State != "approved" {
				return ErrConflict
			}
			j.State = "schedule_canceled"
			j.Reason = "schedule_canceled"
			j.Schedule.OutcomeAt = n
			return m.save(n)
		}
		return ErrConflict
	})
}

// RevokeScheduling is irreversible for the original local grant. Removing and
// later re-adding a named capability cannot undo this durable generation fence.
func (m *Manager) RevokeScheduling(ctx context.Context, device, actor string, ack bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if device != m.Binding().DeviceID || !ack || !enrollmentcrypto.ValidID(actor, "operator_") {
		return ErrInvalid
	}
	return m.transaction(ctx, func(_ Current, n int64) error {
		if !m.record.Consent.ScheduleAcknowledged || m.scheduleAllowed == nil || !m.scheduleAllowed(actor) || m.operatorAllowed == nil || !m.operatorAllowed(actor) {
			return ErrAuthority
		}
		if m.record.ScheduleRevokedAt != 0 {
			return nil
		}
		m.record.ScheduleGeneration = 2
		m.record.ScheduleRevokedAt = n
		for i := range m.record.Jobs {
			j := &m.record.Jobs[i]
			if j.Schedule != nil && (j.State == "scheduled" || j.State == "requested" || j.State == "approved") {
				j.State = "schedule_blocked"
				j.Reason = "schedule_authority_revoked"
				j.Schedule.OutcomeAt = n
			}
		}
		return m.save(n)
	})
}
func (m *Manager) reconcileSchedules(n int64) bool {
	changed := false
	for i := range m.record.Jobs {
		j := &m.record.Jobs[i]
		if j.Schedule == nil || j.State != "scheduled" && j.State != "requested" && j.State != "approved" {
			continue
		}
		reason := ""
		state := "schedule_blocked"
		if !m.scheduleAuthorized(j) {
			reason = "schedule_authority_revoked"
		} else if n >= j.Schedule.Approval.EndAt {
			reason = "schedule_window_expired"
			state = "schedule_expired"
		} else if j.State == "requested" {
			c, e := VerifyChallenge(j.Challenge, m.record.PublicKey)
			if e != nil || n >= c.Deadline {
				reason = "schedule_readiness_expired"
				state = "schedule_expired"
			}
		} else if j.State == "approved" && n >= j.Preview.ExpiresAt {
			reason = "schedule_permit_expired"
			state = "schedule_expired"
		}
		if reason != "" {
			j.State = state
			j.Reason = reason
			j.Schedule.OutcomeAt = n
			changed = true
		}
	}
	return changed
}

// ConfigureSchedulePolicy is startup-only. Reconcile absence before admitting
// the relay, so an effective capability removal survives re-addition/restart.
func (m *Manager) ConfigureSchedulePolicy(ctx context.Context, allowed func(string) bool) error {
	if m == nil || ctx == nil || allowed == nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed || m.scheduleAllowed != nil {
		return ErrInvalid
	}
	m.scheduleAllowed = allowed
	if !m.record.Consent.ScheduleAcknowledged {
		return nil
	}
	active := false
	for _, j := range m.record.Jobs {
		if j.Schedule != nil && (j.State == "scheduled" || j.State == "requested" || j.State == "approved") {
			active = true
			break
		}
	}
	if !active {
		return nil
	}
	if m.transactionStore != nil {
		store, ok := m.transactionStore.(SchedulePolicyStore)
		if !ok {
			return ErrAuthority
		}
		ctx = WithFinalCheck(ctx, func() error {
			if m.configurationCheck != nil {
				return m.configurationCheck()
			}
			return nil
		})
		r, e := store.ReconcileWindowsUpdateSchedulePolicy(ctx, m.binding, m.key.Public().(ed25519.PublicKey), m.now, func(actor string) bool { return m.operatorAllowed != nil && m.operatorAllowed(actor) && allowed(actor) })
		if e != nil {
			return e
		}
		raw, e := EncodeRecord(r)
		if e != nil {
			return e
		}
		m.record = r
		m.raw = raw
		return nil
	}
	return m.transaction(ctx, func(_ Current, n int64) error {
		if m.reconcileSchedules(n) {
			return m.save(n)
		}
		return nil
	})
}
func (r *Registry) ConfigureSchedulePolicy(ctx context.Context, allowed func(string) bool) error {
	if r == nil {
		return ErrInvalid
	}
	for _, m := range r.ordered {
		if e := m.ConfigureSchedulePolicy(ctx, allowed); e != nil {
			return e
		}
	}
	return nil
}

// Only authenticated relay Pending calls this. No timer, view or operator read
// can issue a challenge. A persisted trigger is never regenerated after loss.
func (m *Manager) triggerSchedule(c Current, n int64) error {
	changed := m.reconcileSchedules(n)
	for i := range m.record.Jobs {
		j := &m.record.Jobs[i]
		if j.Schedule == nil || j.State != "scheduled" || n < j.Schedule.Approval.StartAt {
			continue
		}
		if m.record.ReadinessSequence == ^uint64(0) {
			j.State = "schedule_blocked"
			j.Reason = "schedule_sequence_exhausted"
			j.Schedule.OutcomeAt = n
			changed = true
			continue
		}
		m.record.ReadinessSequence++
		raw, e := SignChallenge(Challenge{Version: RelayVersion, Binding: m.Binding(), JobID: j.ID, Selection: j.Selection, IssuedAt: n, Sequence: m.record.ReadinessSequence, Deadline: min(n+120, c.LeafNotAfter, m.record.Consent.ExpiresAt, j.Schedule.Approval.EndAt)}, m.key)
		if e != nil {
			return e
		}
		j.Challenge = raw
		j.RequestedAt = n
		j.ReadinessClaimedAt = 0
		j.ReadinessReport = nil
		j.Preview = nil
		j.Schedule.TriggeredAt = n
		j.State = "requested"
		j.Reason = "readiness_pending"
		changed = true
	}
	if changed {
		return m.save(n)
	}
	return nil
}
func (m *Manager) issueScheduled(j *Job, n int64) error {
	if !m.scheduleAuthorized(j) {
		return ErrAuthority
	}
	if !SameFacts(j.Preview.Readiness, j.Schedule.Approval.Baseline.Readiness) || j.Preview.Readiness.Reason() != "ready" {
		j.State = "schedule_blocked"
		j.Reason = "schedule_readiness_changed"
		j.Schedule.OutcomeAt = n
		return nil
	}
	if e := CheckScheduledMutationIssue(m.record, *j, n); e != nil {
		return e
	}
	if !m.record.Consent.Reusable() {
		if m.record.Sequence >= MaxJobs {
			return ErrConflict
		}
		m.record.Sequence++
	}
	a := j.Schedule.Approval
	p := Permit{Version: ScheduledPermitVersion, Preview: *j.Preview, Sequence: m.record.Sequence, ApprovedAt: a.ApprovedAt, PermitIssuedAt: n, Schedule: &a}
	if m.record.Consent.Reusable() {
		p.Version = ReusablePermitVersion
		p.Sequence = j.Occurrence
	}
	raw, e := Sign(p, m.key)
	if e != nil {
		return e
	}
	j.Envelope = raw
	j.ApprovedAt = a.ApprovedAt
	j.State = "approved"
	j.Reason = "ready"
	return nil
}

// CheckScheduleTransition is the enrollment transaction's immutable-history
// guard. It allows only one trigger, one report/permit and terminal cancellation.
func CheckScheduleTransition(before, after Record) error {
	if after.SchedulePolicyFloor < before.SchedulePolicyFloor {
		return ErrConflict
	}
	if after.ScheduleGeneration != before.ScheduleGeneration || after.ScheduleRevokedAt != before.ScheduleRevokedAt {
		if before.ScheduleGeneration != 1 || before.ScheduleRevokedAt != 0 || after.ScheduleGeneration != 2 || after.ScheduleRevokedAt <= 0 {
			return ErrConflict
		}
	}
	oldByID := map[string]Job{}
	nextByID := map[string]Job{}
	for _, j := range before.Jobs {
		oldByID[j.ID] = j
	}
	for _, j := range after.Jobs {
		nextByID[j.ID] = j
	}
	for _, next := range after.Jobs {
		if next.Schedule == nil {
			continue
		}
		old, exists := oldByID[next.ID]
		if !exists {
			return ErrConflict
		}
		if old.Schedule == nil {
			if old.State != "preview" || old.Preview == nil || len(old.Envelope) != 0 || next.State != "scheduled" || next.Schedule.TriggeredAt != 0 || next.Schedule.OutcomeAt != 0 || next.Schedule.Approval.Baseline != *old.Preview || !bytes.Equal(next.Schedule.BaselineChallenge, old.Challenge) || !bytes.Equal(next.Schedule.BaselineReport, old.ReadinessReport) {
				return ErrConflict
			}
			old.Schedule = next.Schedule
			old.Occurrence = next.Occurrence
			old.State = next.State
			old.Reason = next.Reason
		} else {
			a, b := *old.Schedule, *next.Schedule
			if a.Approval != b.Approval || !bytes.Equal(a.BaselineChallenge, b.BaselineChallenge) || !bytes.Equal(a.BaselineReport, b.BaselineReport) {
				return ErrConflict
			}
			terminal := next.State == "schedule_canceled" || next.State == "schedule_blocked" || next.State == "schedule_expired"
			switch {
			case old.State == next.State:
				if old.State == "requested" && old.ReadinessClaimedAt == 0 && next.ReadinessClaimedAt != 0 {
					old.ReadinessClaimedAt = next.ReadinessClaimedAt
				}
			case old.State == "scheduled" && next.State == "requested":
				if a.TriggeredAt != 0 || b.TriggeredAt == 0 || next.ReadinessClaimedAt != 0 || next.Preview != nil || len(next.ReadinessReport) != 0 {
					return ErrConflict
				}
				old.Challenge = next.Challenge
				old.RequestedAt = next.RequestedAt
				old.ReadinessClaimedAt = 0
				old.ReadinessReport = nil
				old.Preview = nil
				a.TriggeredAt = b.TriggeredAt
			case old.State == "requested" && (next.State == "approved" || next.State == "schedule_blocked" && len(next.ReadinessReport) > 0):
				if old.ReadinessClaimedAt == 0 || len(old.ReadinessReport) > 0 || len(next.ReadinessReport) == 0 {
					return ErrConflict
				}
				old.ReadinessReport = next.ReadinessReport
				old.Preview = next.Preview
				old.Envelope = next.Envelope
				old.ApprovedAt = next.ApprovedAt
				if terminal {
					a.OutcomeAt = b.OutcomeAt
				}
			case old.State == "approved" && next.State == "claimed":
				old.ClaimedAt = next.ClaimedAt
			case old.State == "claimed" && next.State == "complete":
				old.Result = next.Result
				old.ResultReport = next.ResultReport
			case (old.State == "scheduled" || old.State == "requested" || old.State == "approved") && terminal:
				if a.OutcomeAt != 0 || b.OutcomeAt == 0 {
					return ErrConflict
				}
				a.OutcomeAt = b.OutcomeAt
			default:
				return ErrConflict
			}
			old.Schedule = &a
			if old.State != next.State {
				old.Reason = next.Reason
			}
			old.State = next.State
		}
		ClearRetirementFields(&old)
		ClearRetirementFields(&next)
		x, _ := json.Marshal(old)
		y, _ := json.Marshal(next)
		if !bytes.Equal(x, y) {
			return ErrConflict
		}
	}
	for _, old := range before.Jobs {
		if old.Schedule != nil {
			next, ok := nextByID[old.ID]
			if (!ok || next.Schedule == nil) && !CanCompactRetiredJob(before, after, old) {
				return ErrConflict
			}
		}
	}
	return nil
}

// SchedulePolicyStore is a startup-only terminalization seam. It deliberately
// does not require a live leaf: an expired/retired registry member must neither
// block other devices nor resurrect an old prospective approval after re-add.
type SchedulePolicyStore interface {
	ReconcileWindowsUpdateSchedulePolicy(context.Context, Binding, ed25519.PublicKey, func() time.Time, func(string) bool) (Record, error)
}

// TerminalizeSchedulePolicy can only retain authority or remove it. Its separate
// rejection floor does not renew the last successful enrollment authority time.
func TerminalizeSchedulePolicy(r *Record, n int64, allowed func(string) bool) error {
	if r == nil || r.Validate() != nil || allowed == nil || !validTime(n) || n < max(r.ClockFloor, r.SchedulePolicyFloor) {
		return ErrExpired
	}
	if !r.Consent.ScheduleAcknowledged {
		return nil
	}
	for i := range r.Jobs {
		j := &r.Jobs[i]
		if j.Schedule == nil || j.State != "scheduled" && j.State != "requested" && j.State != "approved" {
			continue
		}
		state, reason := "", ""
		if !allowed(j.ActorID) || r.ScheduleRevokedAt != 0 {
			state, reason = "schedule_blocked", "schedule_authority_revoked"
		} else if !scheduleActive(*j, n) {
			state, reason = "schedule_expired", "schedule_window_expired"
		}
		if state != "" {
			j.State = state
			j.Reason = reason
			j.Schedule.OutcomeAt = n
		}
	}
	r.SchedulePolicyFloor = n
	return r.Validate()
}

// CheckScheduledMutationIssue is evaluated before signing and again by the
// enrollment commit fence after blocking work. A stale/busy observation does not
// change the intent: the same immutable saved readiness report may reconcile
// while its original deadline and fixed window still permit issuance.
func CheckScheduledMutationIssue(r Record, j Job, n int64) error {
	// Fresh reusable manual approval has the same final freshness fence as its
	// scheduled form. Native admission still independently owns exclusion.
	if r.Consent.Reusable() && j.Schedule == nil {
		s, e := VerifyStatement(r.MutationReport, r.ExecutorPublicKey)
		if e != nil || s.Kind != "mutation" || s.Binding != r.Consent.Binding || s.Mutation == nil || !s.Mutation.Active || s.Mutation.Blocked || s.Mutation.Phase != "idle" || s.IssuedAt > n || n-s.IssuedAt >= 60 || n >= s.ExpiresAt {
			return ErrUnavailable
		}
		return nil
	}
	if (!r.Consent.Background() || !r.Consent.ScheduleAcknowledged) || j.Schedule == nil {
		return nil
	}
	a := j.Schedule.Approval
	if n < a.StartAt || n >= a.EndAt {
		return ErrExpired
	}
	s, e := VerifyStatement(r.MutationReport, r.ExecutorPublicKey)
	if e != nil || s.Kind != "mutation" || s.Binding != r.Consent.Binding || s.Mutation == nil || !s.Mutation.Active || s.Mutation.Blocked || s.Mutation.Phase != "idle" || s.IssuedAt < a.StartAt || s.IssuedAt > n || n-s.IssuedAt >= 60 || n >= s.ExpiresAt {
		return ErrUnavailable
	}
	return nil
}
