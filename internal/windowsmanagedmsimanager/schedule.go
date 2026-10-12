package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	msi "localrmm/internal/windowsmanagedmsi"
	"time"
)

func (m *Manager) scheduleAllowed(actor string) bool {
	return m.allowed(actor, "install") && m.schedulePolicy != nil && m.schedulePolicy(actor)
}

type schedulePolicyStore interface {
	ReconcileWindowsManagedMSISchedulePolicy(context.Context, msi.Binding, ed25519.PublicKey, func() time.Time, func(string) bool) (msi.Record, error)
}

func (m *Manager) ConfigureSchedulePolicy(ctx context.Context, allowed func(string) bool) error {
	if m == nil || ctx == nil || allowed == nil {
		return msi.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.schedulePolicy != nil || !m.OperatorPolicyConfigured() {
		return msi.ErrConflict
	}
	r, e := m.store.ReadRegisteredWindowsManagedMSI(msi.WithFinalCheck(ctx, m.configurationCheck), m.binding, m.key.Public().(ed25519.PublicKey))
	if e != nil {
		return e
	}
	m.schedulePolicy = allowed
	m.scheduledProfile = r.Grant.Scheduled()
	if !r.Grant.Scheduled() {
		return nil
	}
	store, ok := m.store.(schedulePolicyStore)
	if !ok {
		m.schedulePolicy = nil
		return msi.ErrUnavailable
	}
	_, e = store.ReconcileWindowsManagedMSISchedulePolicy(msi.WithFinalCheck(ctx, m.configurationCheck), m.binding, m.key.Public().(ed25519.PublicKey), m.now, m.scheduleAllowed)
	if e != nil {
		m.schedulePolicy = nil
	}
	return e
}
func (r *Registry) ConfigureSchedulePolicy(ctx context.Context, allowed func(string) bool) error {
	if r == nil || ctx == nil || allowed == nil {
		return msi.ErrInvalid
	}
	for _, m := range r.ordered {
		if e := m.ConfigureSchedulePolicy(ctx, allowed); e != nil {
			return e
		}
	}
	return nil
}

func (m *Manager) Schedule(ctx context.Context, actor string, q msi.ScheduleRequest) error {
	if m == nil || q.Validate() != nil {
		return msi.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.scheduleAllowed(actor) {
		return msi.ErrAuthority
	}
	ctx = msi.WithFinalCheck(ctx, func() error {
		if !m.scheduleAllowed(actor) {
			return msi.ErrAuthority
		}
		return nil
	})
	_, e := m.transaction(ctx, actor, "install", func(r *msi.Record, c msi.Current, n int64) error {
		if !r.Grant.Scheduled() || !r.Grant.InstallEnabled || !r.Grant.InstallAcknowledged {
			return msi.ErrAuthority
		}
		if r.Schedule != nil || len(r.InstallPermit) != 0 || len(r.RetirePermit) != 0 {
			return msi.ErrConsumed
		}
		if r.Artifact == nil || r.Jobs == nil || q.ArtifactID != msi.ArtifactIdentity(*r.Artifact) || q.ArtifactRetiredCount != r.ArtifactRetiredCount || q.BindingDigest != msi.BindingDigest(r.Grant.Binding) || q.TransferID != r.TransferID || q.JobSequence != r.Jobs.Sequence {
			return msi.ErrConflict
		}
		base, e := msi.VerifyReport(r.ReadinessReport, r.ExecutorPublicKey)
		p, pe := msi.VerifyPermit(r.ReadinessPermit, r.PublicKey)
		if e != nil || pe != nil || base.State != "ready" || base.Readiness == nil || q.ReadinessDigest != msi.Digest(r.ReadinessReport) || p.ActorID != actor || p.ScheduleDigest != "" || p.LeafDigest != c.LeafDigest {
			return msi.ErrConflict
		}
		if n >= p.ExpiresAt || base.CapturedAt > n || n-base.CapturedAt >= 60 || q.StartAt <= n || q.StartAt-n > 86400 || q.StartAt < p.ExpiresAt || q.EndAt > min(r.Grant.ExpiresAt, c.LeafNotAfter) {
			return msi.ErrExpired
		}
		a := msi.ScheduleApproval{Version: msi.ScheduleVersion, Request: q, RequestDigest: msi.ScheduleRequestDigest(q), ActorID: actor, ApprovedAt: n, GrantDigest: msi.GrantDigest(r.Grant), LeafDigest: c.LeafDigest, LeafExpiresAt: c.LeafNotAfter, BaselinePermitDigest: msi.Digest(r.ReadinessPermit)}
		a.Digest = a.CanonicalDigest()
		r.Schedule = &msi.ScheduledIntent{Approval: a, BaselinePermit: bytes.Clone(r.ReadinessPermit), BaselineReport: bytes.Clone(r.ReadinessReport), State: "scheduled"}
		return nil
	})
	return e
}
func (m *Manager) CancelSchedule(ctx context.Context, actor, digest string) error {
	if m == nil || !msi.ValidDigest(digest) {
		return msi.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.scheduleAllowed(actor) {
		return msi.ErrAuthority
	}
	ctx = msi.WithFinalCheck(ctx, func() error {
		if !m.scheduleAllowed(actor) {
			return msi.ErrAuthority
		}
		return nil
	})
	_, e := m.transaction(ctx, actor, "install", func(r *msi.Record, _ msi.Current, n int64) error {
		s := r.Schedule
		if s == nil || s.Approval.Digest != digest {
			return msi.ErrConflict
		}
		if s.Terminal() || s.PermitIssuedAt != 0 || len(r.InstallPermit) != 0 {
			return msi.ErrConsumed
		}
		s.State = "canceled"
		s.OutcomeAt = n
		return nil
	})
	return e
}

// Only the existing authenticated observer Poll calls this. It can consume one
// fresh readiness and one permit; no background worker, refresh, or rearming.
func (m *Manager) advanceScheduleLocked(ctx context.Context) error {
	_, e := m.transaction(ctx, "", "", func(r *msi.Record, c msi.Current, n int64) error {
		s := r.Schedule
		if s == nil || s.Terminal() || s.PermitIssuedAt != 0 {
			return nil
		}
		a := s.Approval
		q := a.Request
		if !m.scheduleAllowed(a.ActorID) || c.LeafDigest != a.LeafDigest || c.LeafNotAfter != a.LeafExpiresAt {
			s.State = "blocked"
			s.OutcomeAt = n
			return nil
		}
		if n >= q.EndAt {
			s.State = "expired"
			s.OutcomeAt = n
			return nil
		}
		if n < q.StartAt {
			return nil
		}
		if s.ReadinessIssuedAt == 0 {
			p, pe := msi.VerifyPermit(s.BaselinePermit, r.PublicKey)
			if pe != nil || p.Sequence == ^uint64(0) {
				return msi.ErrConsumed
			}
			p.Sequence++
			p.IssuedAt = n
			p.ExpiresAt = min(n+60, q.EndAt, r.Grant.ExpiresAt, c.LeafNotAfter)
			p.MaintenanceUntil = q.EndAt
			p.ScheduleDigest = a.Digest
			p.ScheduleStartAt = q.StartAt
			p.ScheduleEndAt = q.EndAt
			raw, se := msi.SignPermit(p, m.key)
			if se != nil {
				return se
			}
			r.ReadinessPermit = raw
			r.ReadinessClaimedAt = 0
			r.ReadinessReport = nil
			s.ReadinessIssuedAt = n
			s.State = "readiness_issued"
			return nil
		}
		rp, pe := msi.VerifyPermit(r.ReadinessPermit, r.PublicKey)
		if pe != nil {
			return pe
		}
		if n >= rp.ExpiresAt {
			s.State = "expired"
			s.OutcomeAt = n
			return nil
		}
		if len(r.ReadinessReport) == 0 {
			return nil
		}
		fresh, fe := msi.VerifyReport(r.ReadinessReport, r.ExecutorPublicKey)
		base, be := msi.VerifyReport(s.BaselineReport, r.ExecutorPublicKey)
		if fe != nil || be != nil || fresh.Readiness == nil || base.Readiness == nil || fresh.State != "ready" || !msi.SameScheduledFacts(*fresh.Readiness, *base.Readiness) || fresh.Readiness.MaintenanceWindowEnd != q.EndAt || fresh.CapturedAt < q.StartAt {
			s.State = "blocked"
			s.OutcomeAt = n
			return nil
		}
		if !msi.ScheduleDispatchReady(*r, n) {
			return nil
		}
		p := rp
		p.Kind = "install"
		p.IssuedAt = n
		p.ExpiresAt = min(rp.ExpiresAt, fresh.CapturedAt+60, q.EndAt, c.LeafNotAfter, r.Grant.ExpiresAt)
		p.ReadinessDigest = msi.Digest(r.ReadinessReport)
		raw, se := msi.SignPermit(p, m.key)
		if se != nil {
			return se
		}
		r.InstallPermit = raw
		s.PermitIssuedAt = n
		s.State = "permit_issued"
		return nil
	})
	return e
}

// A revocation first observed after COMMIT must survive capability restoration.
// This terminalization-only transaction emits no authority and does not replay
// the released operation; it uses the same exact reciprocal registration.
func (m *Manager) blockRevokedScheduleLocked() error {
	store, ok := m.store.(schedulePolicyStore)
	if !ok {
		return msi.ErrAuthority
	}
	_, e := store.ReconcileWindowsManagedMSISchedulePolicy(msi.WithFinalCheck(context.Background(), m.configurationCheck), m.binding, m.key.Public().(ed25519.PublicKey), m.now, m.scheduleAllowed)
	if e != nil {
		return e
	}
	return msi.ErrAuthority
}
