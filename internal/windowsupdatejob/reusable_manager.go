package windowsupdatejob

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
)

type RetirementView struct {
	State       string `json:"state"`
	RequestedAt int64  `json:"requestedAt,omitempty"`
	ClaimedAt   int64  `json:"claimedAt,omitempty"`
	RetiredAt   int64  `json:"retiredAt,omitempty"`
}

func digestBytes(b []byte) string { return actionpermit.Digest(b) }
func retirementView(j Job, now int64) *RetirementView {
	v := &RetirementView{State: "blocked"}
	if j.State == "complete" && j.Result != nil && j.Result.Outcome == "succeeded" && len(j.ResultReport) > 0 {
		v.State = "available"
	}
	if len(j.RetirePermit) > 0 {
		v.State = "pending"
		var e retirementEnvelope
		if json.Unmarshal(j.RetirePermit, &e) == nil {
			v.RequestedAt = e.Permit.IssuedAt
			if now >= e.Permit.ExpiresAt {
				v.State = "blocked"
			}
		}
		v.ClaimedAt = j.RetireClaimedAt
	}
	if len(j.RetireReport) > 0 {
		v.State = "retired"
		var e retirementReportEnvelope
		if json.Unmarshal(j.RetireReport, &e) == nil {
			v.RetiredAt = e.Report.IssuedAt
		}
	}
	return v
}
func retiredPublicJob(j RetiredJob) PublicJob {
	result := j.Result
	return PublicJob{Purpose: j.Result.Purpose, ID: j.JobID, Selection: j.Selection, State: "complete", Reason: "ready", Result: &result, Occurrence: j.Occurrence, ResultDigest: j.ResultDigest, Retirement: &RetirementView{State: "retired", RetiredAt: j.RetiredAt}}
}

func (r Record) validateReusable() error {
	if !r.Consent.Reusable() {
		if r.RetiredFloor != 0 || r.RetiredChain != "" || r.RetiredBaseFloor != 0 || r.RetiredBaseChain != "" || len(r.Recent) != 0 {
			return ErrIntegrity
		}
		for _, j := range r.Jobs {
			if j.Occurrence != 0 || len(j.RetirePermit) != 0 || j.RetireClaimedAt != 0 || len(j.RetireReport) != 0 {
				return ErrIntegrity
			}
			if len(j.Envelope) > 0 {
				p, e := Verify(j.Envelope, r.PublicKey)
				if e != nil || p.Reusable() {
					return ErrIntegrity
				}
			}
		}
		return nil
	}
	if len(r.Jobs) > 1 || r.RetiredFloor > r.Sequence || r.Sequence-r.RetiredFloor > 1 || (r.RetiredFloor == 0) != (r.RetiredChain == "") || r.RetiredFloor > 0 && !actionpermit.ValidDigest(r.RetiredChain) || len(r.Recent) != int(min(r.RetiredFloor, uint64(MaxRecentJobs))) {
		return ErrIntegrity
	}
	if r.RetiredBaseFloor != r.RetiredFloor-uint64(len(r.Recent)) || (r.RetiredBaseFloor == 0) != (r.RetiredBaseChain == "") || r.RetiredBaseFloor > 0 && !actionpermit.ValidDigest(r.RetiredBaseChain) {
		return ErrIntegrity
	}
	chain := r.RetiredBaseChain
	for i, j := range r.Recent {
		if j.Validate() != nil || j.Occurrence != r.RetiredFloor-uint64(len(r.Recent)-1-i) || j.RetiredAt > r.ClockFloor {
			return ErrIntegrity
		}
		chain = retiredChain(chain, j)
	}
	if chain != r.RetiredChain {
		return ErrIntegrity
	}
	var occurrence uint64
	for _, j := range r.Jobs {
		approved := len(j.Envelope) > 0 || j.Schedule != nil
		if approved != (j.Occurrence != 0) || j.Occurrence > r.Sequence {
			return ErrIntegrity
		}
		occurrence = j.Occurrence
		if len(j.Envelope) > 0 {
			p, e := Verify(j.Envelope, r.PublicKey)
			if e != nil || !p.Reusable() || p.Sequence != j.Occurrence {
				return ErrIntegrity
			}
		}
		if len(j.RetirePermit) == 0 {
			if j.RetireClaimedAt != 0 || len(j.RetireReport) > 0 {
				return ErrIntegrity
			}
		} else {
			p, e := VerifyRetirement(j.RetirePermit, r.PublicKey)
			if e != nil || j.State != "complete" || j.Result == nil || j.Result.Outcome != "succeeded" || len(j.ResultReport) == 0 || p.Binding != r.Consent.Binding || p.JobID != j.ID || p.Selection != j.Selection || p.Occurrence != j.Occurrence || p.EnvelopeDigest != actionpermit.Digest(j.Envelope) || p.ResultDigest != actionpermit.Digest(j.ResultReport) || p.IssuedAt < j.Result.CompletedAt || p.IssuedAt > r.ClockFloor || p.ExpiresAt > r.Consent.ExpiresAt {
				return ErrIntegrity
			}
			if j.RetireClaimedAt != 0 && (j.RetireClaimedAt < p.IssuedAt || j.RetireClaimedAt >= p.ExpiresAt || j.RetireClaimedAt > r.ClockFloor) {
				return ErrIntegrity
			}
			if len(j.RetireReport) > 0 {
				a, e := VerifyRetirementReport(j.RetireReport, r.ExecutorPublicKey)
				if e != nil || j.RetireClaimedAt == 0 || a.Binding != p.Binding || a.JobID != p.JobID || a.Selection != p.Selection || a.Occurrence != p.Occurrence || a.ReferenceDigest != actionpermit.Digest(j.RetirePermit) || a.EnvelopeDigest != p.EnvelopeDigest || a.ResultDigest != p.ResultDigest || a.IssuedAt < j.RetireClaimedAt || a.IssuedAt >= p.ExpiresAt || a.IssuedAt > r.ClockFloor || a.ExpiresAt > r.Consent.ExpiresAt || j.Occurrence != r.RetiredFloor || len(r.Recent) == 0 || r.Recent[len(r.Recent)-1].RetirementDigest != actionpermit.Digest(j.RetireReport) {
					return ErrIntegrity
				}
			}
		}
		if j.Occurrence != 0 && (len(j.RetireReport) == 0 && j.Occurrence != r.RetiredFloor+1 || len(j.RetireReport) > 0 && j.Occurrence != r.RetiredFloor) {
			return ErrIntegrity
		}
	}
	if max(r.RetiredFloor, occurrence) != r.Sequence {
		return ErrIntegrity
	}
	return nil
}

// Retire requests exact, reviewed evidence compaction. A successful result alone
// cannot release a native owner: the endpoint must prove its saved receipt too.
func (m *Manager) Retire(ctx context.Context, device, actor, id string, occurrence uint64, envelopeDigest, resultDigest string, ack bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if device != m.Binding().DeviceID || !ack || !enrollmentcrypto.ValidID(actor, "operator_") || !enrollmentcrypto.ValidID(id, "update_") || occurrence == 0 || !actionpermit.ValidDigest(envelopeDigest) || !actionpermit.ValidDigest(resultDigest) {
		return ErrInvalid
	}
	return m.transaction(ctx, func(c Current, n int64) error {
		if !m.record.Consent.Reusable() {
			return ErrAuthority
		}
		for i := range m.record.Jobs {
			j := &m.record.Jobs[i]
			if j.ID != id {
				continue
			}
			if j.Download() != downloadRequest(ctx) || j.Occurrence != occurrence || actionpermit.Digest(j.Envelope) != envelopeDigest || actionpermit.Digest(j.ResultReport) != resultDigest || j.State != "complete" || j.Result == nil || j.Result.Outcome != "succeeded" || len(j.ResultReport) == 0 {
				return ErrConflict
			}
			if len(j.RetirePermit) > 0 {
				p, e := VerifyRetirement(j.RetirePermit, m.record.PublicKey)
				if e != nil || p.ActorID != actor {
					return ErrConflict
				}
				return nil
			}
			p := RetirementPermit{Version: RetirementVersion, Binding: m.Binding(), JobID: id, Selection: j.Selection, Occurrence: occurrence, EnvelopeDigest: envelopeDigest, ResultDigest: resultDigest, ActorID: actor, IssuedAt: n, ExpiresAt: min(n+300, c.LeafNotAfter, m.record.Consent.ExpiresAt)}
			raw, e := SignRetirement(p, m.key)
			if e != nil {
				return e
			}
			j.RetirePermit = raw
			return m.save(n)
		}
		return ErrConflict
	})
}
func (m *Manager) ClaimRetirement(ctx context.Context, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx == nil {
		return nil, ErrInvalid
	}
	ctx = context.WithValue(ctx, retirementClaimKey{}, id)
	var raw []byte
	e := m.transaction(ctx, func(c Current, n int64) error {
		if !m.record.Consent.Reusable() {
			return ErrAuthority
		}
		for i := range m.record.Jobs {
			j := &m.record.Jobs[i]
			if j.ID != id {
				continue
			}
			p, e := VerifyRetirement(j.RetirePermit, m.record.PublicKey)
			if e != nil || len(j.RetireReport) > 0 {
				return ErrConflict
			}
			if m.transactionStore != nil && !m.operationAllowed(p.ActorID, j.Download()) {
				return ErrAuthority
			}
			if n >= p.ExpiresAt {
				return ErrExpired
			}
			if j.RetireClaimedAt == 0 {
				j.RetireClaimedAt = n
				if e = m.save(n); e != nil {
					return e
				}
			}
			if e = CheckRetirementClaimFinal(ctx, m.record, c, m.now().Unix()); e != nil {
				return e
			}
			raw = bytes.Clone(j.RetirePermit)
			return nil
		}
		return ErrConflict
	})
	if e != nil {
		return nil, e
	}
	return raw, nil
}
func (m *Manager) reportRetirement(ctx context.Context, raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.transaction(ctx, func(_ Current, n int64) error {
		if !m.record.Consent.Reusable() {
			return ErrAuthority
		}
		a, e := VerifyRetirementReport(raw, m.record.ExecutorPublicKey)
		if e != nil || a.Binding != m.Binding() {
			return ErrAuthority
		}
		for _, old := range m.record.Recent {
			if old.Occurrence == a.Occurrence && old.JobID == a.JobID && old.RetirementDigest == actionpermit.Digest(raw) {
				return nil
			}
		}
		for i := range m.record.Jobs {
			j := &m.record.Jobs[i]
			if j.ID != a.JobID {
				continue
			}
			p, e := VerifyRetirement(j.RetirePermit, m.record.PublicKey)
			if e != nil || j.RetireClaimedAt == 0 || j.Result == nil || j.Result.Outcome != "succeeded" || a.Occurrence != j.Occurrence || a.Selection != j.Selection || a.ReferenceDigest != actionpermit.Digest(j.RetirePermit) || a.EnvelopeDigest != actionpermit.Digest(j.Envelope) || a.ResultDigest != actionpermit.Digest(j.ResultReport) || a.IssuedAt < j.RetireClaimedAt || a.IssuedAt >= p.ExpiresAt {
				return ErrConflict
			}
			if a.IssuedAt > n || n >= a.ExpiresAt || a.ExpiresAt > m.record.Consent.ExpiresAt {
				return ErrExpired
			}
			j.RetireReport = bytes.Clone(raw)
			retired := RetiredJob{Occurrence: j.Occurrence, JobID: j.ID, Selection: j.Selection, Result: *j.Result, ResultDigest: a.ResultDigest, RetirementDigest: actionpermit.Digest(raw), RequestedAt: j.RequestedAt, ApprovedAt: j.ApprovedAt, ClaimedAt: j.ClaimedAt, RetiredAt: a.IssuedAt}
			m.record.RetiredFloor = j.Occurrence
			m.record.RetiredChain = retiredChain(m.record.RetiredChain, retired)
			m.record.Recent = append(m.record.Recent, retired)
			if len(m.record.Recent) > MaxRecentJobs {
				old := m.record.Recent[0]
				m.record.RetiredBaseFloor = old.Occurrence
				m.record.RetiredBaseChain = retiredChain(m.record.RetiredBaseChain, old)
				m.record.Recent = append([]RetiredJob(nil), m.record.Recent[len(m.record.Recent)-MaxRecentJobs:]...)
			}
			return m.save(n)
		}
		return ErrConflict
	})
}

func ClearRetirementFields(j *Job) { j.RetirePermit = nil; j.RetireClaimedAt = 0; j.RetireReport = nil }
func CanCompactRetiredJob(before, after Record, j Job) bool {
	if !before.Consent.Reusable() || len(j.RetireReport) == 0 || j.Occurrence > before.RetiredFloor || after.RetiredFloor < before.RetiredFloor {
		return false
	}
	for _, r := range after.Recent {
		if r.JobID == j.ID && r.Occurrence == j.Occurrence && r.RetirementDigest == actionpermit.Digest(j.RetireReport) {
			return true
		}
	}
	return false
}

// CheckReusableTransition is the enrollment transaction's immutable retirement
// guard. Only one exact signed acknowledgement can advance each floor/chain.
func CheckReusableTransition(before, after Record) error {
	if !before.Consent.Reusable() {
		return after.validateReusable()
	}
	if after.validateReusable() != nil || after.Sequence < before.Sequence || after.Sequence-before.Sequence > 1 || after.RetiredFloor < before.RetiredFloor || after.RetiredFloor-before.RetiredFloor > 1 {
		return ErrIntegrity
	}
	if after.RetiredFloor == before.RetiredFloor {
		if after.RetiredChain != before.RetiredChain || after.RetiredBaseFloor != before.RetiredBaseFloor || after.RetiredBaseChain != before.RetiredBaseChain || digest(after.Recent) != digest(before.Recent) {
			return ErrIntegrity
		}
	} else {
		if len(after.Recent) == 0 {
			return ErrIntegrity
		}
		last := after.Recent[len(after.Recent)-1]
		expected := append(append([]RetiredJob(nil), before.Recent...), last)
		baseFloor, baseChain := before.RetiredBaseFloor, before.RetiredBaseChain
		if len(expected) > MaxRecentJobs {
			baseFloor, baseChain = expected[0].Occurrence, retiredChain(baseChain, expected[0])
			expected = expected[len(expected)-MaxRecentJobs:]
		}
		if after.RetiredChain != retiredChain(before.RetiredChain, last) || after.RetiredBaseFloor != baseFloor || after.RetiredBaseChain != baseChain || digest(expected) != digest(after.Recent) {
			return ErrIntegrity
		}
	}
	advanced := false
	for _, old := range before.Jobs {
		found := false
		for _, next := range after.Jobs {
			if old.ID != next.ID {
				continue
			}
			found = true
			if old.Occurrence != 0 && next.Occurrence != old.Occurrence {
				return ErrIntegrity
			}
			if len(old.RetirePermit) > 0 && !bytes.Equal(old.RetirePermit, next.RetirePermit) || old.RetireClaimedAt != 0 && old.RetireClaimedAt != next.RetireClaimedAt || len(old.RetireReport) > 0 && !bytes.Equal(old.RetireReport, next.RetireReport) {
				return ErrIntegrity
			}
			if len(next.RetirePermit) > 0 && len(old.RetirePermit) == 0 && (old.State != "complete" || old.Result == nil || old.Result.Outcome != "succeeded" || len(old.ResultReport) == 0) {
				return ErrIntegrity
			}
			if len(next.RetireReport) > 0 && len(old.RetireReport) == 0 {
				if old.RetireClaimedAt == 0 || after.RetiredFloor != old.Occurrence || old.Result == nil {
					return ErrIntegrity
				}
				ack, e := VerifyRetirementReport(next.RetireReport, after.ExecutorPublicKey)
				if e != nil {
					return ErrIntegrity
				}
				summary := RetiredJob{Occurrence: old.Occurrence, JobID: old.ID, Selection: old.Selection, Result: *old.Result, ResultDigest: actionpermit.Digest(old.ResultReport), RetirementDigest: actionpermit.Digest(next.RetireReport), RequestedAt: old.RequestedAt, ApprovedAt: old.ApprovedAt, ClaimedAt: old.ClaimedAt, RetiredAt: ack.IssuedAt}
				if len(after.Recent) == 0 || after.Recent[len(after.Recent)-1] != summary {
					return ErrIntegrity
				}
				advanced = true
			}
		}
		if !found && old.Occurrence != 0 && !CanCompactRetiredJob(before, after, old) {
			return ErrIntegrity
		}
	}
	if (after.RetiredFloor > before.RetiredFloor) != advanced {
		return ErrIntegrity
	}
	if after.Sequence > before.Sequence {
		found := false
		for _, j := range after.Jobs {
			if j.Occurrence == after.Sequence && (len(j.Envelope) > 0 || j.Schedule != nil) {
				found = true
			}
		}
		if !found {
			return ErrIntegrity
		}
	}
	return nil
}

type retirementClaimKey struct{}

// RetirementClaimRequested is operation-scoped, never supplied by network input.
func RetirementClaimRequested(ctx context.Context, id string) bool {
	requested, _ := ctx.Value(retirementClaimKey{}).(string)
	return requested != "" && requested == id
}
func CheckRetirementClaimFinal(ctx context.Context, r Record, c Current, n int64) error {
	id, _ := ctx.Value(retirementClaimKey{}).(string)
	if id == "" {
		return nil
	}
	for _, j := range r.Jobs {
		if j.ID != id {
			continue
		}
		p, e := VerifyRetirement(j.RetirePermit, r.PublicKey)
		if e != nil || len(j.RetireReport) > 0 || j.RetireClaimedAt == 0 {
			return ErrConflict
		}
		if n < r.ClockFloor || n < p.IssuedAt || n >= p.ExpiresAt || p.ExpiresAt > c.LeafNotAfter || p.ExpiresAt > r.Consent.ExpiresAt {
			return ErrExpired
		}
		return nil
	}
	return ErrConflict
}
