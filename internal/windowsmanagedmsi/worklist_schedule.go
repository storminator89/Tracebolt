package windowsmanagedmsi

import "strconv"

// ScheduleRequest preserves the existing signed/prospective approval contract.
// The worklist request is only an exact, short-lived foreground restriction.
func (q WorklistRequest) ScheduleRequest(a WorklistAcknowledgements) (ScheduleRequest, error) {
	if !q.Valid("schedule") || !a.Valid("schedule") {
		return ScheduleRequest{}, ErrInvalid
	}
	occ, _ := strconv.ParseUint(q.ArtifactRetiredCount, 10, 64)
	seq, _ := strconv.ParseUint(q.JobSequence, 10, 64)
	out := ScheduleRequest{ArtifactID: q.ArtifactID, ArtifactRetiredCount: occ, BindingDigest: q.BindingDigest, TransferID: q.TransferID, JobSequence: seq, ReadinessDigest: q.ReadinessDigest, StartAt: q.StartAt, EndAt: q.EndAt, PackageReviewAccepted: a.PackageReviewAccepted, TermsAccepted: a.TermsAccepted, ServiceRiskAccepted: a.ServiceRiskAccepted, SynchronousActionsAccepted: a.SynchronousReviewAccepted, ScheduleAccepted: a.ScheduleAccepted}
	return out, out.Validate()
}

// CheckWorklistScheduleAuthority runs at the worklist transaction's final edge.
// Confirming the list issues no schedule or permit, but cannot retain an approval
// for a replaced leaf, changed grant, or already expired original readiness.
func CheckWorklistScheduleAuthority(b WorklistBatch, records map[string]Record, currents map[string]Current, at int64) error {
	if b.Kind != "schedule" {
		return nil
	}
	for _, item := range b.Items {
		q := item.Request
		r, ok := records[q.DeviceID]
		c, current := currents[q.DeviceID]
		if !ok || !current || !r.Grant.Scheduled() || c.Binding != r.Grant.Binding || q.BindingDigest != BindingDigest(r.Grant.Binding) {
			return ErrAuthority
		}
		if r.Artifact == nil || r.Jobs == nil || q.ArtifactID != ArtifactIdentity(*r.Artifact) || q.ArtifactRetiredCount != strconv.FormatUint(r.ArtifactRetiredCount, 10) || q.TransferID != r.TransferID || q.JobSequence != strconv.FormatUint(r.Jobs.Sequence, 10) || r.Schedule != nil || len(r.InstallPermit) != 0 || len(r.RetirePermit) != 0 {
			return ErrConflict
		}
		p, e := VerifyPermit(r.ReadinessPermit, r.PublicKey)
		ready, re := VerifyReport(r.ReadinessReport, r.ExecutorPublicKey)
		if e != nil || re != nil || p.ActorID != b.ActorID || p.ScheduleDigest != "" || p.LeafDigest != c.LeafDigest || ready.Readiness == nil || ready.State != "ready" || Digest(r.ReadinessReport) != q.ReadinessDigest {
			return ErrConflict
		}
		if at >= b.ExpiresAt || at >= p.ExpiresAt || ready.CapturedAt > at || at-ready.CapturedAt >= 60 || q.StartAt <= at || q.StartAt-at > 86400 || q.StartAt < p.ExpiresAt || q.EndAt > min(r.Grant.ExpiresAt, c.LeafNotAfter) {
			return ErrExpired
		}
	}
	return nil
}
