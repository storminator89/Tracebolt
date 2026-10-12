package windowsmanagedmsi

import (
	"bytes"
	"encoding/json"
	fence "localrmm/internal/windowsmutationfence"
)

const CoordinatedEndpointVersion = "tracebolt.windows-managed-msi-endpoint.v2"

func MutationParticipant(g Grant) fence.Participant {
	b, _ := json.Marshal(g.Binding)
	raw, _ := json.Marshal(g)
	return fence.Participant{Domain: fence.ManagedMSI, BindingDigest: Digest(b), GrantDigest: Digest(raw), ManagerKeyDigest: g.Binding.KeyID, ExecutorKeyDigest: g.Binding.ExecutorKeyID}
}
func ValidMutationRoster(r *fence.Roster, g Grant) bool {
	if r == nil || r.Validate() != nil || (g.Version != CoordinatedGrantVersion && !g.Reusable()) || g.Reusable() != r.ReusableMSI() || g.Scheduled() && r.Version != fence.BackgroundRosterVersion || g.Validate() != nil {
		return false
	}
	b := g.Binding
	return r.Plan.Identity == (fence.Identity{ManagerID: b.ManagerID, DeviceID: b.DeviceID, IncarnationDigest: b.IncarnationDigest}) && r.Plan.PlanDigest == g.MutationPlanDigest && g.PeerBindingDigest == r.WUA.BindingDigest && r.MSI == MutationParticipant(g)
}
func NewCoordinatedEndpointRecord(g Grant, manager, executor []byte, at int64, roster fence.Roster) (EndpointRecord, error) {
	r := EndpointRecord{Version: Version, Grant: g, ManagerPublicKey: append([]byte(nil), manager...), ExecutorPublicKey: append([]byte(nil), executor...), ClockFloor: at, PrefixDigest: Digest(nil)}
	r.Version = CoordinatedEndpointVersion
	r.Mutation = &roster
	if g.Reusable() {
		r.Version = ReusableEndpointVersion
		r.Jobs = NewJobLedger()
	}
	if g.Scheduled() {
		r.Version = ScheduledEndpointVersion
	}
	return r, r.Validate()
}

func mutationOwner(p Permit, raw []byte) fence.Owner {
	sequence := p.Sequence
	if p.Version == ReusableVersion || p.Version == ScheduledVersion {
		sequence = p.JobSequence
	}
	return fence.Owner{Domain: fence.ManagedMSI, JobID: p.TransferID, TransferID: p.TransferID, Sequence: sequence, PermitDigest: Digest(raw)}
}
func (r EndpointRecord) validateMutationCompletion() error {
	c := r.MutationCompletion
	if c == nil {
		return nil
	}
	p, e := VerifyPermit(r.InstallPermit, r.ManagerPublicKey)
	report, re := VerifyReport(r.ResultReport, r.ExecutorPublicKey)
	if r.Mutation == nil || c.Validate() != nil || e != nil || re != nil || report.Result == nil || c.FenceID != r.Mutation.FenceID || c.RosterDigest != r.Mutation.Digest() || c.Owner != mutationOwner(p, r.InstallPermit) || c.ResultDigest != Digest(r.ResultReport) || c.CompletedAt != report.Result.CompletedAt || !r.Attempted || !report.Result.ReturnCodeKnown || report.Result.Outcome == "uncertain" || report.Result.Outcome == "unexpected_restart" || report.Result.ReturnCode == 3010 && report.Result.RegistrationVerified != Yes {
		return ErrIntegrity
	}
	return nil
}
func (x *Endpoint) verifyMutationCompletion(receipt fence.Receipt) error {
	raw, e := x.store.Read("endpoint.json")
	var r EndpointRecord
	if e != nil || Canonical(raw, &r, MaxRecordBytes) != nil || r.Validate() != nil || r.MutationCompletion == nil || *r.MutationCompletion != receipt || !bytes.Equal(raw, x.raw) {
		return ErrIntegrity
	}
	return nil
}
func (x *Endpoint) finishBlocked(p Permit, raw []byte) error {
	result := Result{JobID: "software_" + p.TransferID[len("transfer_"):], EnvelopeDigest: Digest(raw), Outcome: "not_attempted", RegistrationVerified: Unknown, CompletedAt: x.now().UTC().Unix()}
	report, e := x.report(p, raw, "result", result.Outcome, nil, &result)
	if e != nil {
		return e
	}
	x.record.ResultReport = report
	return x.save()
}

func (r Record) validateMutationReport() error {
	if len(r.MutationReport) == 0 {
		return nil
	}
	s, e := VerifyReport(r.MutationReport, r.ExecutorPublicKey)
	if e != nil || r.Grant.MutationPlanDigest == "" || s.Kind != "mutation" || s.Binding != r.Grant.Binding || s.TransferID != r.TransferID || s.PermitDigest != Digest(r.DeliveryPermit) || r.Artifact == nil || s.Package != r.Artifact.Package || s.NativeAcceptanceDigest != r.Artifact.NativeAcceptanceDigest || s.CapturedAt > r.ClockFloor || s.CapturedAt >= r.Grant.ExpiresAt {
		return ErrIntegrity
	}
	return nil
}
func validMutationReportAdvance(before, after, key []byte) bool {
	if len(before) == 0 {
		return true
	}
	if len(after) == 0 {
		return false
	}
	a, e := VerifyReport(before, key)
	b, be := VerifyReport(after, key)
	return e == nil && be == nil && a.Mutation != nil && b.Mutation != nil && b.CapturedAt >= a.CapturedAt && b.Mutation.Revision >= a.Mutation.Revision && (b.Mutation.Revision != a.Mutation.Revision || *b.Mutation == *a.Mutation)
}
