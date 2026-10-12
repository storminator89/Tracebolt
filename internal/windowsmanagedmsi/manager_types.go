package windowsmanagedmsi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/keyvalidation"
	"strings"
	"time"
)

const RecordVersion = "tracebolt.windows-managed-msi-manager-record.v1"

type Current struct {
	Binding        Binding
	LeafDigest     string
	LeafGeneration uint64
	LeafNotBefore  int64
	LeafNotAfter   int64
	Revoked        bool
	Enabled        bool
}
type Artifact struct {
	CustodyDigest           string    `json:"custodyDigest,omitempty"`
	PublisherStatus         string    `json:"publisherStatus,omitempty"`
	PublisherEvidenceDigest string    `json:"publisherEvidenceDigest,omitempty"`
	Package                 Selection `json:"package"`
	NativeAcceptanceDigest  string    `json:"nativeAcceptanceDigest"`
	IntentAt                int64     `json:"intentAt"`
	CompletedAt             int64     `json:"completedAt"`
	Offset                  int64     `json:"offset"`
	PrefixDigest            string    `json:"prefixDigest"`
	PendingIndex            uint32    `json:"pendingIndex"`
	PendingDigest           string    `json:"pendingDigest"`
	PendingSize             int       `json:"pendingSize"`
	LastChunkDigest         string    `json:"lastChunkDigest"`
}

// Record contains bounded metadata and signed evidence only, never MSI chunks.
// Upload intent is permanent even if its exact body never arrived or fsync failed.
type Record struct {
	Schedule            *ScheduledIntent `json:"schedule,omitempty"`
	SchedulePolicyFloor int64            `json:"schedulePolicyFloor,omitempty"`
	// Manager-owned occurrence metadata; never part of signed endpoint authority.
	ArtifactRetiredCount uint64            `json:"artifactRetiredCount,string,omitempty"`
	Jobs                 *JobLedger        `json:"jobs,omitempty"`
	RetirePermit         []byte            `json:"retirePermit,omitempty"`
	RetireClaimedAt      int64             `json:"retireClaimedAt,omitempty"`
	RetiredReport        []byte            `json:"retiredReport,omitempty"`
	MutationReport       []byte            `json:"mutationReport,omitempty"`
	Version              string            `json:"version"`
	Grant                Grant             `json:"grant"`
	PublicKey            ed25519.PublicKey `json:"publicKey"`
	ExecutorPublicKey    ed25519.PublicKey `json:"executorPublicKey"`
	Artifact             *Artifact         `json:"artifact,omitempty"`
	TransferID           string            `json:"transferId,omitempty"`
	DeliveryPermit       []byte            `json:"deliveryPermit,omitempty"`
	DeliveryClaimedAt    int64             `json:"deliveryClaimedAt"`
	DeliveryReport       []byte            `json:"deliveryReport,omitempty"`
	ReadinessPermit      []byte            `json:"readinessPermit,omitempty"`
	ReadinessClaimedAt   int64             `json:"readinessClaimedAt"`
	ReadinessReport      []byte            `json:"readinessReport,omitempty"`
	InstallPermit        []byte            `json:"installPermit,omitempty"`
	InstallClaimedAt     int64             `json:"installClaimedAt"`
	ResultReport         []byte            `json:"resultReport,omitempty"`
	ClockFloor           int64             `json:"clockFloor"`
}

func NewRecord(g Grant, key, executor ed25519.PublicKey, at int64) (Record, error) {
	r := Record{Version: RecordVersion, Grant: g, PublicKey: bytes.Clone(key), ExecutorPublicKey: bytes.Clone(executor), ClockFloor: at}
	if g.Reusable() {
		r.Version = ReusableRecordVersion
		if g.Scheduled() {
			r.Version = ScheduledRecordVersion
		}
		r.Jobs = NewJobLedger()
	}
	return r, r.Validate()
}
func (r Record) Validate() error {
	if r.validateMutationReport() != nil || r.validateSchedule() != nil {
		return ErrIntegrity
	}
	if r.validateReusableRecord() != nil || (r.Version != RecordVersion && r.Version != ReusableRecordVersion && r.Version != ScheduledRecordVersion && !r.Catalogue()) || r.Grant.Validate() != nil || !keyvalidation.Ed25519(r.PublicKey) || !keyvalidation.Ed25519(r.ExecutorPublicKey) || Digest(r.PublicKey) != r.Grant.Binding.KeyID || Digest(r.ExecutorPublicKey) != r.Grant.Binding.ExecutorKeyID || !ValidTime(r.ClockFloor) {
		return ErrIntegrity
	}
	if r.Artifact == nil {
		if r.TransferID != "" || len(r.DeliveryPermit)+len(r.ReadinessPermit)+len(r.InstallPermit)+len(r.DeliveryReport)+len(r.ReadinessReport)+len(r.ResultReport) != 0 || r.DeliveryClaimedAt+r.ReadinessClaimedAt+r.InstallClaimedAt != 0 {
			return ErrIntegrity
		}
		return nil
	}
	if r.Artifact.Validate(r.ClockFloor) != nil {
		return ErrIntegrity
	}
	a := r.Artifact
	if r.TransferID == "" {
		if len(r.DeliveryPermit)+len(r.ReadinessPermit)+len(r.InstallPermit)+len(r.DeliveryReport)+len(r.ReadinessReport)+len(r.ResultReport) != 0 || r.DeliveryClaimedAt+r.ReadinessClaimedAt+r.InstallClaimedAt != 0 {
			return ErrIntegrity
		}
		return nil
	}
	if !ValidTransferID(r.TransferID) || a.CompletedAt == 0 || len(r.DeliveryPermit) == 0 {
		return ErrIntegrity
	}
	for i, part := range []struct {
		kind           string
		permit, report []byte
		claim          int64
	}{{"deliver", r.DeliveryPermit, r.DeliveryReport, r.DeliveryClaimedAt}, {"readiness", r.ReadinessPermit, r.ReadinessReport, r.ReadinessClaimedAt}, {"install", r.InstallPermit, r.ResultReport, r.InstallClaimedAt}} {
		if len(part.permit) == 0 {
			if part.claim != 0 || len(part.report) != 0 {
				return ErrIntegrity
			}
			continue
		}
		p, e := VerifyPermit(part.permit, r.PublicKey)
		if e != nil || p.Kind != part.kind || !PermitMatchesGrant(p, r.Grant) || p.TransferID != r.TransferID || p.Package != a.Package || p.NativeAcceptanceDigest != a.NativeAcceptanceDigest || p.IssuedAt < a.CompletedAt || p.IssuedAt > r.ClockFloor || p.ExpiresAt > r.Grant.ExpiresAt || part.claim != 0 && (part.claim < p.IssuedAt || part.claim >= p.ExpiresAt || part.claim > r.ClockFloor) {
			return ErrIntegrity
		}
		if i > 0 {
			d, e := VerifyReport(r.DeliveryReport, r.ExecutorPublicKey)
			if e != nil || d.State != "imported" {
				return ErrIntegrity
			}
		}
		if i == 2 {
			ready, e := VerifyReport(r.ReadinessReport, r.ExecutorPublicKey)
			rp, pe := VerifyPermit(r.ReadinessPermit, r.PublicKey)
			if e != nil || pe != nil || ready.State != "ready" || p.ReadinessDigest != Digest(r.ReadinessReport) || p.Sequence != rp.Sequence || p.MaintenanceUntil != rp.MaintenanceUntil || p.ExpiresAt > rp.ExpiresAt || p.ActorID != rp.ActorID {
				return ErrIntegrity
			}
		}
		if len(part.report) != 0 {
			report, e := VerifyReport(part.report, r.ExecutorPublicKey)
			kind := part.kind
			if i == 0 {
				kind = "delivery"
			}
			if i == 2 {
				kind = "result"
			}
			if e != nil || part.claim == 0 || report.Kind != kind || report.Version != p.Version || report.JobSequence != p.JobSequence || report.Binding != p.Binding || report.TransferID != p.TransferID || report.PermitDigest != Digest(part.permit) || report.Package != p.Package || report.NativeAcceptanceDigest != p.NativeAcceptanceDigest || report.CapturedAt < part.claim || report.CapturedAt > r.ClockFloor || report.CapturedAt >= r.Grant.ExpiresAt {
				return ErrIntegrity
			}
			if i < 2 && report.CapturedAt >= p.ExpiresAt && !(i == 0 && report.State == "intervention_required") {
				return ErrIntegrity
			}
			if i == 2 && (report.Result == nil || report.Result.EnvelopeDigest != report.PermitDigest || report.Result.JobID != "software_"+strings.TrimPrefix(r.TransferID, "transfer_")) {
				return ErrIntegrity
			}
			if i == 1 && (report.Readiness == nil || report.Readiness.MaintenanceWindowEnd != p.MaintenanceUntil) {
				return ErrIntegrity
			}
		}
	}
	return nil
}
func EncodeRecord(r Record) ([]byte, error) {
	if r.Validate() != nil {
		return nil, ErrIntegrity
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > MaxRecordBytes {
		return nil, ErrIntegrity
	}
	return b, nil
}
func DecodeRecord(raw []byte) (Record, error) {
	var r Record
	if Canonical(raw, &r, MaxRecordBytes) != nil || r.Validate() != nil {
		return Record{}, ErrIntegrity
	}
	return r, nil
}
func Transition(before, after Record) error {
	if after.Validate() != nil || before.Version != after.Version || before.Grant != after.Grant || !bytes.Equal(before.PublicKey, after.PublicKey) || !bytes.Equal(before.ExecutorPublicKey, after.ExecutorPublicKey) || after.ClockFloor < before.ClockFloor {
		return ErrIntegrity
	}
	if before.Grant.Reusable() && !before.Catalogue() && after.ArtifactRetiredCount < before.ArtifactRetiredCount {
		return ErrConsumed
	}
	var err error
	before, err = prepareJobTransition(before, after)
	if err != nil {
		return err
	}
	if ScheduleTransition(before, after) != nil {
		return ErrConsumed
	}
	if !validMutationReportAdvance(before.MutationReport, after.MutationReport, after.ExecutorPublicKey) {
		return ErrIntegrity
	}
	if before.Artifact != nil && before.ArtifactRetiredCount != after.ArtifactRetiredCount {
		return ErrConsumed
	}
	if ArtifactTransition(before.Artifact, after.Artifact) != nil {
		return ErrConsumed
	}
	// A fresh explicit readiness request may supersede only an expired old
	// challenge, never any installation permit/claim/result. Its sequence advances
	// exactly once; it cannot reuse a lost old report or original deadline.
	if len(before.ReadinessPermit) != 0 && !bytes.Equal(before.ReadinessPermit, after.ReadinessPermit) {
		old, e := VerifyPermit(before.ReadinessPermit, before.PublicKey)
		next, ne := VerifyPermit(after.ReadinessPermit, after.PublicKey)
		if e != nil || ne != nil || len(before.InstallPermit) != 0 || len(after.InstallPermit) != 0 || next.Sequence != old.Sequence+1 || next.Sequence <= old.Sequence || next.IssuedAt < old.ExpiresAt || after.ReadinessClaimedAt != 0 || len(after.ReadinessReport) != 0 {
			return ErrConsumed
		}
		before.ReadinessPermit = after.ReadinessPermit
		before.ReadinessClaimedAt = 0
		before.ReadinessReport = nil
	}

	if before.TransferID != "" && before.TransferID != after.TransferID {
		return ErrConsumed
	}
	for _, pair := range [][2][]byte{{before.RetirePermit, after.RetirePermit}, {before.RetiredReport, after.RetiredReport}, {before.DeliveryPermit, after.DeliveryPermit}, {before.DeliveryReport, after.DeliveryReport}, {before.ReadinessPermit, after.ReadinessPermit}, {before.ReadinessReport, after.ReadinessReport}, {before.InstallPermit, after.InstallPermit}, {before.ResultReport, after.ResultReport}} {
		if len(pair[0]) != 0 && !bytes.Equal(pair[0], pair[1]) {
			return ErrConsumed
		}
	}
	for _, pair := range [][2]int64{{before.RetireClaimedAt, after.RetireClaimedAt}, {before.DeliveryClaimedAt, after.DeliveryClaimedAt}, {before.ReadinessClaimedAt, after.ReadinessClaimedAt}, {before.InstallClaimedAt, after.InstallClaimedAt}} {
		if pair[0] != 0 && pair[0] != pair[1] {
			return ErrConsumed
		}
	}
	return nil
}

// FinalDeadline runs after storage/configuration/session waits. Existing durable
// evidence survives expiry; new authority and first claims never do.
func FinalDeadline(before, after Record, current Current, at int64) error {
	if e := ScheduleFinalDeadline(before, after, current, at); e != nil {
		return e
	}
	for _, p := range []struct{ old, next, permit []byte }{{before.DeliveryReport, after.DeliveryReport, after.DeliveryPermit}, {before.ReadinessReport, after.ReadinessReport, after.ReadinessPermit}} {
		if len(p.next) != 0 && !bytes.Equal(p.old, p.next) {
			permit, e := VerifyPermit(p.permit, after.PublicKey)
			report, reportErr := VerifyReport(p.next, after.ExecutorPublicKey)
			if e != nil || reportErr != nil || at >= permit.ExpiresAt && !(report.Kind == "delivery" && report.State == "intervention_required") {
				return ErrExpired
			}
		}
	}

	for _, p := range []struct {
		old, next           []byte
		oldClaim, nextClaim int64
	}{{before.RetirePermit, after.RetirePermit, before.RetireClaimedAt, after.RetireClaimedAt}, {before.DeliveryPermit, after.DeliveryPermit, before.DeliveryClaimedAt, after.DeliveryClaimedAt}, {before.ReadinessPermit, after.ReadinessPermit, before.ReadinessClaimedAt, after.ReadinessClaimedAt}, {before.InstallPermit, after.InstallPermit, before.InstallClaimedAt, after.InstallClaimedAt}} {
		if len(p.next) == 0 || bytes.Equal(p.old, p.next) && p.oldClaim == p.nextClaim {
			continue
		}
		permit, e := VerifyPermit(p.next, after.PublicKey)
		if e != nil || at >= permit.ExpiresAt || permit.ExpiresAt > current.LeafNotAfter || permit.LeafDigest != current.LeafDigest {
			return ErrExpired
		}
	}
	return nil
}

type TransactionStore interface {
	WindowsManagedMSIEnrollmentBinding() enrollmentstate.Binding
	WindowsManagedMSITransaction(context.Context, Binding, ed25519.PublicKey, time.Time, func(*Record, Current, time.Time) error) (Record, time.Time, error)
	ReadRegisteredWindowsManagedMSI(context.Context, Binding, ed25519.PublicKey) (Record, error)
}
type finalCheckKey struct{}

func WithFinalCheck(ctx context.Context, check func() error) context.Context {
	old, _ := ctx.Value(finalCheckKey{}).(func() error)
	return context.WithValue(ctx, finalCheckKey{}, func() error {
		if check == nil {
			return ErrAuthority
		}
		if e := check(); e != nil {
			return e
		}
		if old != nil {
			return old()
		}
		return nil
	})
}
func CheckFinal(ctx context.Context) error {
	check, _ := ctx.Value(finalCheckKey{}).(func() error)
	if check != nil {
		return check()
	}
	return nil
}
