package windowsmanagedmsimanager

import (
	"context"
	msi "localrmm/internal/windowsmanagedmsi"
)

// Retire is a named, explicit review of one exact completed job. It grants only
// retirement of that job's app-owned payload and released owner metadata. It
// neither cancels an admitted install nor installs the next package.
func (m *Manager) Retire(ctx context.Context, actor, resultDigest string, ack bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !ack || !msi.ValidDigest(resultDigest) {
		return msi.ErrInvalid
	}
	_, e := m.transaction(ctx, actor, "install", func(r *msi.Record, c msi.Current, n int64) error {
		if !r.Grant.Reusable() || len(r.RetirePermit) > 0 || resultDigest != msi.Digest(r.ResultReport) {
			return msi.ErrConsumed
		}
		result, e := msi.VerifyReport(r.ResultReport, r.ExecutorPublicKey)
		if e != nil || !msi.SettledResult(result) {
			return msi.ErrUncertain
		}
		shared, e := msi.VerifyReport(r.MutationReport, r.ExecutorPublicKey)
		if e != nil || shared.Mutation == nil || !shared.Mutation.Active || shared.Mutation.Blocked || shared.Mutation.Phase != "idle" || shared.CapturedAt > n || n-shared.CapturedAt >= 60 {
			return msi.ErrUnavailable
		}
		p := msi.Permit{Version: msi.ReusableVersion, Kind: "retire", TransferID: r.TransferID, Binding: r.Grant.Binding, LeafDigest: c.LeafDigest, Package: r.Artifact.Package, NativeAcceptanceDigest: r.Artifact.NativeAcceptanceDigest, ActorID: actor, IssuedAt: n, ExpiresAt: min(n+60, r.Grant.ExpiresAt, c.LeafNotAfter), PackageReviewAccepted: true, TermsAccepted: true, RetireResultDigest: resultDigest, SynchronousReviewDigest: msi.SynchronousReviewDigest(r.Artifact.Package, r.Artifact.NativeAcceptanceDigest)}
		p = msi.PermitForGrant(p, r.Grant, r.Jobs.Sequence, *r.Artifact)
		r.RetirePermit, e = msi.SignPermit(p, m.key)
		return e
	})
	return e
}
