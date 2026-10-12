package windowsmanagedmsimanager

import (
	"context"
	msi "localrmm/internal/windowsmanagedmsi"
)

// Eligibility uses the same current-authority transaction as per-device approval.
// A renewed leaf must be excluded before confirming the other healthy devices.
// This reads exact evidence only; it creates neither intent nor permit.
func (m *Manager) scheduleWorklistEligibility(ctx context.Context, actor string, w msi.Worklist, target msi.WorklistTarget, digest string, startAt, endAt int64) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.scheduleAllowed(actor) {
		return "capability"
	}
	ctx = msi.WithFinalCheck(ctx, func() error {
		if !m.scheduleAllowed(actor) {
			return msi.ErrAuthority
		}
		return nil
	})
	reason := ""
	_, err := m.transaction(ctx, actor, "install", func(r *msi.Record, c msi.Current, n int64) error {
		if !worklistMatches(w, *r, target) || r.Schedule != nil || len(r.InstallPermit) != 0 || len(r.RetirePermit) != 0 {
			reason = "changed"
			return nil
		}
		p, pe := msi.VerifyPermit(r.ReadinessPermit, r.PublicKey)
		ready, re := msi.VerifyReport(r.ReadinessReport, r.ExecutorPublicKey)
		switch {
		case !r.Grant.Scheduled() || !r.Grant.InstallEnabled || !r.Grant.InstallAcknowledged || pe != nil || p.ActorID != actor || p.ScheduleDigest != "":
			reason = "capability"
		case p.LeafDigest != c.LeafDigest || re != nil || ready.Readiness == nil || ready.State != "ready" || msi.Digest(r.ReadinessReport) != digest:
			reason = "changed"
		case n >= p.ExpiresAt || ready.CapturedAt > n || n-ready.CapturedAt >= 60:
			reason = "expired"
		case startAt <= n || startAt-n > 86400 || startAt < p.ExpiresAt || endAt > min(r.Grant.ExpiresAt, c.LeafNotAfter):
			reason = "window"
		}
		return nil
	})
	if err != nil {
		return "unavailable"
	}
	return reason
}
