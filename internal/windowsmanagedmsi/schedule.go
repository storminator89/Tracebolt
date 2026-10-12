package windowsmanagedmsi

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
)

const ScheduleVersion = "tracebolt.windows-managed-msi-schedule.v1"
const ScheduledRecordVersion = "tracebolt.windows-managed-msi-manager-record.v4"

// ScheduleRequest is one reviewed prospective approval for an already imported
// assignment. It contains no paths, commands, payloads, or replacement choice.
type ScheduleRequest struct {
	ArtifactID                 string `json:"artifactId"`
	ArtifactRetiredCount       uint64 `json:"artifactRetiredCount,string"`
	BindingDigest              string `json:"bindingDigest"`
	TransferID                 string `json:"transferId"`
	JobSequence                uint64 `json:"jobSequence,string"`
	ReadinessDigest            string `json:"readinessDigest"`
	StartAt                    int64  `json:"startAt"`
	EndAt                      int64  `json:"endAt"`
	PackageReviewAccepted      bool   `json:"packageReviewAccepted"`
	TermsAccepted              bool   `json:"termsAccepted"`
	ServiceRiskAccepted        bool   `json:"serviceRiskAccepted"`
	SynchronousActionsAccepted bool   `json:"synchronousActionsAccepted"`
	ScheduleAccepted           bool   `json:"scheduleAccepted"`
}

func (q ScheduleRequest) Validate() error {
	if !ValidDigest(q.ArtifactID) || !ValidDigest(q.BindingDigest) || !ValidTransferID(q.TransferID) || q.JobSequence == 0 || !ValidDigest(q.ReadinessDigest) || !ValidTime(q.StartAt) || !ValidTime(q.EndAt) || q.EndAt-q.StartAt < 60 || q.EndAt-q.StartAt > 600 || !q.PackageReviewAccepted || !q.TermsAccepted || !q.ServiceRiskAccepted || !q.SynchronousActionsAccepted || !q.ScheduleAccepted {
		return ErrInvalid
	}
	return nil
}
func ScheduleRequestDigest(q ScheduleRequest) string {
	b, _ := json.Marshal(q)
	return Digest(append([]byte("Tracebolt managed MSI schedule request v1\x00"), b...))
}

type ScheduleApproval struct {
	Version              string          `json:"version"`
	Request              ScheduleRequest `json:"request"`
	RequestDigest        string          `json:"requestDigest"`
	ActorID              string          `json:"actorId"`
	ApprovedAt           int64           `json:"approvedAt"`
	GrantDigest          string          `json:"grantDigest"`
	LeafDigest           string          `json:"leafDigest"`
	LeafExpiresAt        int64           `json:"leafExpiresAt"`
	BaselinePermitDigest string          `json:"baselinePermitDigest"`
	Digest               string          `json:"digest"`
}

func (a ScheduleApproval) CanonicalDigest() string {
	a.Digest = ""
	b, _ := json.Marshal(a)
	return Digest(append([]byte("Tracebolt prospective managed MSI schedule v1\x00"), b...))
}
func (a ScheduleApproval) Validate() error {
	if a.Version != ScheduleVersion || a.Request.Validate() != nil || a.RequestDigest != ScheduleRequestDigest(a.Request) || !enrollmentcrypto.ValidID(a.ActorID, "operator_") || !ValidTime(a.ApprovedAt) || a.Request.StartAt <= a.ApprovedAt || a.Request.StartAt-a.ApprovedAt > 86400 || !ValidDigest(a.GrantDigest) || !ValidDigest(a.LeafDigest) || !ValidTime(a.LeafExpiresAt) || a.Request.EndAt > a.LeafExpiresAt || !ValidDigest(a.BaselinePermitDigest) || a.Digest != a.CanonicalDigest() {
		return ErrInvalid
	}
	return nil
}

type ScheduledIntent struct {
	Approval          ScheduleApproval `json:"approval"`
	BaselinePermit    []byte           `json:"baselinePermit"`
	BaselineReport    []byte           `json:"baselineReport"`
	State             string           `json:"state"`
	ReadinessIssuedAt int64            `json:"readinessIssuedAt"`
	PermitIssuedAt    int64            `json:"permitIssuedAt"`
	OutcomeAt         int64            `json:"outcomeAt"`
}
type ScheduleView struct {
	Version           string `json:"version"`
	Digest            string `json:"digest"`
	RequestDigest     string `json:"requestDigest"`
	ActorID           string `json:"actorId"`
	ApprovedAt        int64  `json:"approvedAt"`
	StartAt           int64  `json:"startAt"`
	EndAt             int64  `json:"endAt"`
	ReadinessDigest   string `json:"readinessDigest"`
	State             string `json:"state"`
	ReadinessIssuedAt int64  `json:"readinessIssuedAt"`
	PermitIssuedAt    int64  `json:"permitIssuedAt"`
	OutcomeAt         int64  `json:"outcomeAt"`
	CanCancel         bool   `json:"canCancel"`
}

func (s *ScheduledIntent) View() *ScheduleView {
	if s == nil {
		return nil
	}
	a := s.Approval
	return &ScheduleView{Version: ScheduleVersion, Digest: a.Digest, RequestDigest: a.RequestDigest, ActorID: a.ActorID, ApprovedAt: a.ApprovedAt, StartAt: a.Request.StartAt, EndAt: a.Request.EndAt, ReadinessDigest: a.Request.ReadinessDigest, State: s.State, ReadinessIssuedAt: s.ReadinessIssuedAt, PermitIssuedAt: s.PermitIssuedAt, OutcomeAt: s.OutcomeAt, CanCancel: !s.Terminal() && s.PermitIssuedAt == 0}
}
func (s *ScheduledIntent) Terminal() bool {
	return s != nil && (s.State == "canceled" || s.State == "expired" || s.State == "blocked")
}
func GrantDigest(g Grant) string { b, _ := json.Marshal(g); return Digest(b) }

// SameScheduledFacts preserves every physical/package fact. Only capture time
// and the separately approved fixed maintenance end may differ from baseline.
func SameScheduledFacts(a, b Readiness) bool {
	a.CapturedAt = 0
	b.CapturedAt = 0
	a.MaintenanceWindowEnd = 0
	b.MaintenanceWindowEnd = 0
	return a == b
}
func ReusableWire(version string) bool {
	return version == ReusableVersion || version == ScheduledVersion
}
func GrantWire(g Grant) string {
	if g.Scheduled() {
		return ScheduledVersion
	}
	if g.Reusable() {
		return ReusableVersion
	}
	return Version
}
func (p Permit) validateSchedule() error {
	if p.ScheduleDigest == "" {
		if p.ScheduleStartAt != 0 || p.ScheduleEndAt != 0 {
			return ErrInvalid
		}
		return nil
	}
	if p.Version != ScheduledVersion || !ValidDigest(p.ScheduleDigest) || (p.Kind != "readiness" && p.Kind != "install") || !ValidTime(p.ScheduleStartAt) || !ValidTime(p.ScheduleEndAt) || p.ScheduleEndAt-p.ScheduleStartAt < 60 || p.ScheduleEndAt-p.ScheduleStartAt > 600 || p.IssuedAt < p.ScheduleStartAt || p.ExpiresAt > p.ScheduleEndAt || p.MaintenanceUntil != p.ScheduleEndAt {
		return ErrInvalid
	}
	return nil
}
func sameSchedulePermit(a, b Permit) bool {
	return a.ScheduleDigest == b.ScheduleDigest && a.ScheduleStartAt == b.ScheduleStartAt && a.ScheduleEndAt == b.ScheduleEndAt
}
func (r Record) validateSchedule() error {
	if !r.Grant.Scheduled() {
		if r.Schedule != nil || r.SchedulePolicyFloor != 0 {
			return ErrIntegrity
		}
		return nil
	}
	if r.SchedulePolicyFloor != 0 && !ValidTime(r.SchedulePolicyFloor) {
		return ErrIntegrity
	}
	s := r.Schedule
	if s == nil {
		return nil
	}
	a := s.Approval
	q := a.Request
	if a.Validate() != nil || r.Artifact == nil || r.Jobs == nil || q.ArtifactID != ArtifactIdentity(*r.Artifact) || q.ArtifactRetiredCount != r.ArtifactRetiredCount || q.BindingDigest != BindingDigest(r.Grant.Binding) || q.TransferID != r.TransferID || q.JobSequence != r.Jobs.Sequence || a.GrantDigest != GrantDigest(r.Grant) || a.ApprovedAt > r.ClockFloor || q.EndAt > r.Grant.ExpiresAt {
		return ErrIntegrity
	}
	p, e := VerifyPermit(s.BaselinePermit, r.PublicKey)
	v, ve := VerifyReport(s.BaselineReport, r.ExecutorPublicKey)
	if e != nil || ve != nil || p.Kind != "readiness" || p.ScheduleDigest != "" || !PermitMatchesGrant(p, r.Grant) || p.TransferID != r.TransferID || p.JobSequence != r.Jobs.Sequence || p.Package != r.Artifact.Package || p.NativeAcceptanceDigest != r.Artifact.NativeAcceptanceDigest || p.PublisherStatus != r.Artifact.PublisherStatus || p.PublisherEvidenceDigest != r.Artifact.PublisherEvidenceDigest || p.ActorID != a.ActorID || p.LeafDigest != a.LeafDigest || p.IssuedAt > a.ApprovedAt || a.ApprovedAt >= p.ExpiresAt || q.StartAt < p.ExpiresAt || Digest(s.BaselinePermit) != a.BaselinePermitDigest || Digest(s.BaselineReport) != q.ReadinessDigest || v.PermitDigest != a.BaselinePermitDigest || v.Kind != "readiness" || v.State != "ready" || v.Readiness == nil || v.Binding != p.Binding || v.TransferID != p.TransferID || v.Package != p.Package || v.JobSequence != p.JobSequence || v.NativeAcceptanceDigest != p.NativeAcceptanceDigest || v.Version != p.Version || v.CapturedAt < p.IssuedAt || v.CapturedAt > a.ApprovedAt || a.ApprovedAt-v.CapturedAt >= 60 || v.Readiness.MaintenanceWindowEnd != p.MaintenanceUntil || p.SynchronousReviewDigest != SynchronousReviewDigest(p.Package, p.NativeAcceptanceDigest) {
		return ErrIntegrity
	}
	if s.ReadinessIssuedAt == 0 {
		if !bytes.Equal(r.ReadinessPermit, s.BaselinePermit) || !bytes.Equal(r.ReadinessReport, s.BaselineReport) || s.PermitIssuedAt != 0 || len(r.InstallPermit) != 0 || (!s.Terminal() && s.State != "scheduled") {
			return ErrIntegrity
		}
	} else {
		fresh, fe := VerifyPermit(r.ReadinessPermit, r.PublicKey)
		if fe != nil || fresh.Sequence != p.Sequence+1 || fresh.Sequence <= p.Sequence || fresh.IssuedAt != s.ReadinessIssuedAt || s.ReadinessIssuedAt < q.StartAt || s.ReadinessIssuedAt >= q.EndAt || s.ReadinessIssuedAt > r.ClockFloor || fresh.ScheduleDigest != a.Digest || fresh.ScheduleStartAt != q.StartAt || fresh.ScheduleEndAt != q.EndAt || fresh.ActorID != a.ActorID || fresh.LeafDigest != a.LeafDigest || (!s.Terminal() && s.State != "readiness_issued" && s.State != "permit_issued") {
			return ErrIntegrity
		}
	}
	if s.PermitIssuedAt == 0 {
		if len(r.InstallPermit) != 0 || s.State == "permit_issued" {
			return ErrIntegrity
		}
	} else {
		install, ie := VerifyPermit(r.InstallPermit, r.PublicKey)
		if ie != nil || install.IssuedAt != s.PermitIssuedAt || s.PermitIssuedAt < s.ReadinessIssuedAt || install.ScheduleDigest != a.Digest || install.ScheduleStartAt != q.StartAt || install.ScheduleEndAt != q.EndAt || install.ActorID != a.ActorID || install.LeafDigest != a.LeafDigest || (!s.Terminal() && s.State != "permit_issued") {
			return ErrIntegrity
		}
	}
	if s.Terminal() {
		if !ValidTime(s.OutcomeAt) || s.OutcomeAt < a.ApprovedAt || s.OutcomeAt > max(r.ClockFloor, r.SchedulePolicyFloor) || s.State == "canceled" && s.PermitIssuedAt != 0 {
			return ErrIntegrity
		}
	} else if s.OutcomeAt != 0 {
		return ErrIntegrity
	}
	return nil
}
func ScheduleTransition(before, after Record) error {
	if after.SchedulePolicyFloor < before.SchedulePolicyFloor {
		return ErrConsumed
	}
	a, b := before.Schedule, after.Schedule
	if a == nil {
		return nil
	}
	if b == nil || !sameJSON(a.Approval, b.Approval) || !bytes.Equal(a.BaselinePermit, b.BaselinePermit) || !bytes.Equal(a.BaselineReport, b.BaselineReport) {
		return ErrConsumed
	}
	if a.Terminal() && !sameJSON(a, b) {
		return ErrConsumed
	}
	if a.ReadinessIssuedAt != 0 && a.ReadinessIssuedAt != b.ReadinessIssuedAt || a.PermitIssuedAt != 0 && a.PermitIssuedAt != b.PermitIssuedAt || a.OutcomeAt != 0 && a.OutcomeAt != b.OutcomeAt {
		return ErrConsumed
	}
	return nil
}

// ScheduleDispatchReady is repeated after storage/configuration waits. A signed
// shared observation is a prerequisite, never a substitute for the native fence.
func ScheduleDispatchReady(r Record, at int64) bool {
	s := r.Schedule
	if s == nil || s.Terminal() {
		return false
	}
	a := s.Approval
	fresh, e := VerifyReport(r.ReadinessReport, r.ExecutorPublicKey)
	base, be := VerifyReport(s.BaselineReport, r.ExecutorPublicKey)
	p, pe := VerifyPermit(r.ReadinessPermit, r.PublicKey)
	shared, se := VerifyReport(r.MutationReport, r.ExecutorPublicKey)
	return e == nil && be == nil && pe == nil && se == nil && fresh.Readiness != nil && base.Readiness != nil && fresh.State == "ready" && SameScheduledFacts(*fresh.Readiness, *base.Readiness) && fresh.Readiness.MaintenanceWindowEnd == a.Request.EndAt && fresh.CapturedAt >= a.Request.StartAt && fresh.CapturedAt <= at && at-fresh.CapturedAt < 60 && at < p.ExpiresAt && shared.Mutation != nil && shared.Mutation.Active && !shared.Mutation.Blocked && shared.Mutation.Phase == "idle" && shared.CapturedAt >= a.Request.StartAt && shared.CapturedAt <= at && at-shared.CapturedAt < 60
}
func ScheduleFinalDeadline(before, after Record, current Current, at int64) error {
	s := after.Schedule
	if s == nil {
		return nil
	}
	a := s.Approval
	if before.Schedule == nil {
		p, e := VerifyPermit(s.BaselinePermit, after.PublicKey)
		if e != nil || at >= p.ExpiresAt || at >= a.Request.StartAt || a.LeafDigest != current.LeafDigest || a.LeafExpiresAt != current.LeafNotAfter {
			return ErrExpired
		}
	}
	newReady := !bytes.Equal(before.ReadinessPermit, after.ReadinessPermit)
	newInstall := !bytes.Equal(before.InstallPermit, after.InstallPermit)
	claim := before.ReadinessClaimedAt != after.ReadinessClaimedAt || before.InstallClaimedAt != after.InstallClaimedAt
	if newReady || newInstall || claim {
		if s.Terminal() || at < a.Request.StartAt || at >= a.Request.EndAt || a.LeafDigest != current.LeafDigest || a.LeafExpiresAt != current.LeafNotAfter {
			return ErrExpired
		}
	}
	if (newInstall || before.InstallClaimedAt != after.InstallClaimedAt) && !ScheduleDispatchReady(after, at) {
		return ErrUnavailable
	}
	return nil
}

type schedulePolicyKey struct{}

func WithSchedulePolicy(ctx context.Context, allowed func(string) bool) context.Context {
	return context.WithValue(ctx, schedulePolicyKey{}, allowed)
}
func SchedulePolicyFrom(ctx context.Context) func(string) bool {
	f, _ := ctx.Value(schedulePolicyKey{}).(func(string) bool)
	return f
}

// Terminalization never writes dispatch evidence or changes an existing result.
// Policy time is separate from the authority clock so revoked/expired history
// can be blocked without manufacturing a newly admitted enrollment observation.
func TerminalizeSchedulePolicy(r *Record, floor int64, allowed func(string) bool) error {
	if r == nil || allowed == nil || !ValidTime(floor) {
		return ErrInvalid
	}
	if !r.Grant.Scheduled() {
		return nil
	}
	r.SchedulePolicyFloor = max(r.SchedulePolicyFloor, floor)
	s := r.Schedule
	if s == nil || s.Terminal() || len(r.ResultReport) > 0 {
		return nil
	}
	if !allowed(s.Approval.ActorID) {
		s.State = "blocked"
		s.OutcomeAt = floor
	} else if s.PermitIssuedAt == 0 && floor >= s.Approval.Request.EndAt {
		s.State = "expired"
		s.OutcomeAt = floor
	}
	return nil
}
