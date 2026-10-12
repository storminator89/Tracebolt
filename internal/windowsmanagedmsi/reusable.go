package windowsmanagedmsi

import (
	"bytes"
	"encoding/json"
)

const (
	ReusableVersion             = "tracebolt.windows-managed-msi.v3"
	ReusableGrantVersion        = "tracebolt.windows-managed-msi-grant.v3"
	ReusableRecordVersion       = "tracebolt.windows-managed-msi-manager-record.v3"
	ReusableEndpointVersion     = "tracebolt.windows-managed-msi-endpoint.v3"
	ReusableOfferVersion        = "tracebolt.windows-managed-msi-setup-offer.v3"
	ReusableRegistrationVersion = "tracebolt.windows-managed-msi-setup-registration.v3"
	MaxRecentJobs               = 8
	// Each side retains at most one 128 MiB payload; combined custody is 256 MiB.
	MaxRetainedPayloadBytes = 128 << 20
	ReusableDisclosure      = "Allow centrally selected MSI jobs repeatedly under this original identity and original absolute expiry. Delivery and installation remain separate permissions. Every named package, publisher evidence (unsigned or unverified), terms, LocalSystem/custom-action risk, native evidence and maintenance window requires independent review and approval. No next job starts automatically. Only explicitly reviewed final results and exact shared-owner release allow retirement of app-owned package bytes; uncertainty retains evidence and blocks another job. Retirement does not uninstall, cancel, roll back, renew consent or reset replay floors."
)

// This is evidence of what the operator reviewed, never an Authenticode verdict.
func ValidPublisherEvidence(status, digest string) bool {
	return (status == "unsigned" || status == "unverified") && ValidDigest(digest)
}
func (p Permit) validateReusable() error {
	if p.Version == Version {
		if p.JobSequence != 0 || p.PublisherStatus != "" || p.PublisherEvidenceDigest != "" || p.RetireResultDigest != "" {
			return ErrInvalid
		}
		return nil
	}
	if !ReusableWire(p.Version) || p.JobSequence == 0 || !ValidPublisherEvidence(p.PublisherStatus, p.PublisherEvidenceDigest) || p.Kind != "retire" && p.RetireResultDigest != "" {
		return ErrInvalid
	}
	return nil
}
func PermitForGrant(p Permit, g Grant, sequence uint64, a Artifact) Permit {
	if g.Reusable() {
		p.Version = GrantWire(g)
		p.JobSequence = sequence
		p.PublisherStatus = a.PublisherStatus
		p.PublisherEvidenceDigest = a.PublisherEvidenceDigest
	}
	return p
}
func PermitMatchesGrant(p Permit, g Grant) bool {
	return p.Binding == g.Binding && p.Version == GrantWire(g)
}

type RetirementEvidence struct {
	ResultDigest  string `json:"resultDigest"`
	ReleaseDigest string `json:"releaseDigest"`
	CustodyDigest string `json:"custodyDigest"`
}

func (r RetirementEvidence) Validate() error {
	if !ValidDigest(r.ResultDigest) || !ValidDigest(r.ReleaseDigest) || !ValidDigest(r.CustodyDigest) {
		return ErrIntegrity
	}
	return nil
}

// Recent metadata is bounded. Chain commits to every reviewed retired summary,
// including those no longer projected. Floor never resets or reconstructs a job.
type RetiredJob struct {
	Sequence                uint64    `json:"sequence,string"`
	TransferID              string    `json:"transferId"`
	Package                 Selection `json:"package"`
	NativeAcceptanceDigest  string    `json:"nativeAcceptanceDigest"`
	PublisherStatus         string    `json:"publisherStatus"`
	PublisherEvidenceDigest string    `json:"publisherEvidenceDigest"`
	ResultDigest            string    `json:"resultDigest"`
	RetirementDigest        string    `json:"retirementDigest"`
	Outcome                 string    `json:"outcome"`
	CompletedAt             int64     `json:"completedAt"`
}
type JobLedger struct {
	Sequence     uint64       `json:"sequence,string"`
	RetiredFloor uint64       `json:"retiredFloor,string"`
	Chain        string       `json:"chain"`
	Recent       []RetiredJob `json:"recent"`
}

func NewJobLedger() *JobLedger {
	return &JobLedger{Chain: Digest([]byte("Tracebolt retired MSI jobs v3\x00")), Recent: []RetiredJob{}}
}
func (j *JobLedger) Validate() error {
	if j == nil || !ValidDigest(j.Chain) || j.Recent == nil || len(j.Recent) > MaxRecentJobs || j.RetiredFloor > j.Sequence || j.Sequence-j.RetiredFloor > 1 || uint64(len(j.Recent)) != min(j.RetiredFloor, uint64(MaxRecentJobs)) {
		return ErrIntegrity
	}
	for i, v := range j.Recent {
		if v.Sequence != j.RetiredFloor-uint64(len(j.Recent)-1-i) || !ValidTransferID(v.TransferID) || !ValidSelection(v.Package) || !ValidDigest(v.NativeAcceptanceDigest) || !ValidPublisherEvidence(v.PublisherStatus, v.PublisherEvidenceDigest) || !ValidDigest(v.ResultDigest) || !ValidDigest(v.RetirementDigest) || !ValidTime(v.CompletedAt) || !settledOutcome(v.Outcome) {
			return ErrIntegrity
		}
	}
	if j.RetiredFloor == 0 && j.Chain != NewJobLedger().Chain {
		return ErrIntegrity
	}
	return nil
}
func settledOutcome(s string) bool {
	return s == "succeeded" || s == "restart_required" || s == "busy" || s == "failed"
}
func SettledResult(r Report) bool {
	return r.Kind == "result" && r.Result != nil && r.Result.Attempted && r.Result.ReturnCodeKnown && settledOutcome(r.Result.Outcome) && (r.Result.ReturnCode != 3010 || r.Result.RegistrationVerified == Yes)
}
func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func AdvanceJobLedger(j *JobLedger, p Permit, result, retired Report, retiredRaw []byte) (*JobLedger, error) {
	if j.Validate() != nil || !ReusableWire(p.Version) || p.JobSequence != j.Sequence || j.Sequence == 0 || j.Sequence == ^uint64(0) || j.RetiredFloor+1 != j.Sequence || !SettledResult(result) || retired.Kind != "retired" || retired.Retirement == nil || retired.JobSequence != j.Sequence || retired.Retirement.Validate() != nil {
		return nil, ErrIntegrity
	}
	// The caller validates signed report/permit bindings before invoking this.
	v := RetiredJob{Sequence: j.Sequence, TransferID: p.TransferID, Package: p.Package, NativeAcceptanceDigest: p.NativeAcceptanceDigest, PublisherStatus: p.PublisherStatus, PublisherEvidenceDigest: p.PublisherEvidenceDigest, ResultDigest: retired.Retirement.ResultDigest, RetirementDigest: Digest(retiredRaw), Outcome: result.Result.Outcome, CompletedAt: result.CapturedAt}
	raw, _ := json.Marshal(v)
	n := &JobLedger{Sequence: j.Sequence + 1, RetiredFloor: j.Sequence, Chain: Digest(append([]byte(j.Chain+"\x00"), raw...)), Recent: append(append([]RetiredJob{}, j.Recent...), v)}
	if len(n.Recent) > MaxRecentJobs {
		n.Recent = n.Recent[len(n.Recent)-MaxRecentJobs:]
	}
	return n, n.Validate()
}
func (r Record) validateReusableRecord() error {
	if !r.Grant.Reusable() {
		if r.ArtifactRetiredCount != 0 || r.Version != RecordVersion || r.Jobs != nil || len(r.RetirePermit)+len(r.RetiredReport) != 0 || r.RetireClaimedAt != 0 {
			return ErrIntegrity
		}
		return nil
	}
	if (r.Version != ReusableRecordVersion && r.Version != ScheduledRecordVersion && !r.Catalogue()) || (r.Version == ScheduledRecordVersion || r.Version == ScheduledCatalogueManagerRecordVersion) != r.Grant.Scheduled() || r.Jobs.Validate() != nil {
		return ErrIntegrity
	}
	if r.Artifact == nil {
		if r.ArtifactRetiredCount != 0 || r.Jobs.Sequence != 0 {
			return ErrIntegrity
		}
	} else if !ValidPublisherEvidence(r.Artifact.PublisherStatus, r.Artifact.PublisherEvidenceDigest) {
		return ErrIntegrity
	}
	if r.TransferID == "" {
		if r.Jobs.Sequence != 0 || len(r.RetirePermit)+len(r.RetiredReport) != 0 || r.RetireClaimedAt != 0 {
			return ErrIntegrity
		}
		return nil
	}
	for _, raw := range [][]byte{r.DeliveryPermit, r.ReadinessPermit, r.InstallPermit} {
		if len(raw) == 0 {
			continue
		}
		p, e := VerifyPermit(raw, r.PublicKey)
		if e != nil || !PermitMatchesGrant(p, r.Grant) || p.JobSequence != r.Jobs.Sequence || p.PublisherStatus != r.Artifact.PublisherStatus || p.PublisherEvidenceDigest != r.Artifact.PublisherEvidenceDigest {
			return ErrIntegrity
		}
	}
	for _, raw := range [][]byte{r.DeliveryReport, r.ReadinessReport, r.ResultReport, r.MutationReport} {
		if len(raw) == 0 {
			continue
		}
		p, e := VerifyReport(raw, r.ExecutorPublicKey)
		if e != nil || p.Version != GrantWire(r.Grant) || p.JobSequence != r.Jobs.Sequence {
			return ErrIntegrity
		}
	}
	if len(r.RetirePermit) == 0 {
		if r.RetireClaimedAt != 0 || len(r.RetiredReport) != 0 {
			return ErrIntegrity
		}
		return nil
	}
	p, e := VerifyPermit(r.RetirePermit, r.PublicKey)
	result, re := VerifyReport(r.ResultReport, r.ExecutorPublicKey)
	delivery, de := VerifyPermit(r.DeliveryPermit, r.PublicKey)
	if e != nil || re != nil || de != nil || !SettledResult(result) || p.Kind != "retire" || !samePackage(p, delivery) || p.RetireResultDigest != Digest(r.ResultReport) || p.IssuedAt < result.CapturedAt || p.IssuedAt > r.ClockFloor || p.ExpiresAt > r.Grant.ExpiresAt || r.RetireClaimedAt != 0 && (r.RetireClaimedAt < p.IssuedAt || r.RetireClaimedAt >= p.ExpiresAt || r.RetireClaimedAt > r.ClockFloor) {
		return ErrIntegrity
	}
	if len(r.RetiredReport) > 0 {
		v, e := VerifyReport(r.RetiredReport, r.ExecutorPublicKey)
		if e != nil || r.RetireClaimedAt == 0 || v.Kind != "retired" || v.Binding != p.Binding || v.TransferID != p.TransferID || v.Package != p.Package || v.NativeAcceptanceDigest != p.NativeAcceptanceDigest || v.JobSequence != p.JobSequence || v.PermitDigest != Digest(r.RetirePermit) || v.Retirement.ResultDigest != p.RetireResultDigest || v.CapturedAt < r.RetireClaimedAt || v.CapturedAt >= p.ExpiresAt || v.CapturedAt > r.ClockFloor {
			return ErrIntegrity
		}
	}
	return nil
}
func NextManagerJob(r Record) (Record, error) {
	if !r.Grant.Reusable() || r.validateReusableRecord() != nil || len(r.RetiredReport) == 0 {
		return Record{}, ErrConsumed
	}
	p, _ := VerifyPermit(r.DeliveryPermit, r.PublicKey)
	result, _ := VerifyReport(r.ResultReport, r.ExecutorPublicKey)
	retired, _ := VerifyReport(r.RetiredReport, r.ExecutorPublicKey)
	j, e := AdvanceJobLedger(r.Jobs, p, result, retired, r.RetiredReport)
	if e != nil {
		return Record{}, e
	}
	return Record{Version: r.Version, Grant: r.Grant, PublicKey: r.PublicKey, ExecutorPublicKey: r.ExecutorPublicKey, Jobs: j, ClockFloor: r.ClockFloor, SchedulePolicyFloor: r.SchedulePolicyFloor}, nil
}
func prepareJobTransition(before, after Record) (Record, error) {
	if !before.Grant.Reusable() {
		return before, nil
	}
	if sameJSON(before.Jobs, after.Jobs) {
		return before, nil
	}
	if before.TransferID == "" && before.Jobs.Sequence == 0 && after.Jobs.Sequence == 1 && after.Jobs.RetiredFloor == 0 && after.Jobs.Chain == before.Jobs.Chain && len(after.Jobs.Recent) == 0 && after.TransferID != "" {
		before.Jobs = after.Jobs
		return before, nil
	}
	next, e := NextManagerJob(before)
	if e != nil || !sameJSON(next.Jobs, after.Jobs) || after.TransferID == "" || after.TransferID == before.TransferID || (!before.Catalogue() && after.ArtifactRetiredCount <= before.ArtifactRetiredCount || before.Catalogue() && after.ArtifactRetiredCount == before.ArtifactRetiredCount) {
		return before, ErrConsumed
	}
	return next, nil
}
