package windowsmanagedmsi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"sort"
	"strconv"
	"time"
)

const CatalogueVersion = "tracebolt.windows-managed-msi-catalogue.v1"
const CatalogueRecordVersion = "tracebolt.windows-managed-msi-catalogue-record.v1"
const CatalogueArtifactRecordVersion = "tracebolt.windows-managed-msi-artifact-record.v4"
const CatalogueManagerRecordVersion = "tracebolt.windows-managed-msi-manager-record.v5"
const ScheduledCatalogueManagerRecordVersion = "tracebolt.windows-managed-msi-manager-record.v6"
const CatalogueWorklistVersion = "tracebolt.windows-managed-msi-worklists.v2"
const MaxCatalogueEntries = 4

// Assignment is written atomically with the exact job. It never relies on the
// endpoint's bounded recent-history ring and outlives advancement to other jobs.
type CatalogueAssignment struct {
	Binding          Binding `json:"binding"`
	TransferID       string  `json:"transferId"`
	JobSequence      uint64  `json:"jobSequence,string"`
	ResultDigest     string  `json:"resultDigest"`
	RetirementDigest string  `json:"retirementDigest"`
}
type CatalogueRecord struct {
	Version      string           `json:"version"`
	Revision     uint64           `json:"revision,string"`
	Sequence     uint64           `json:"sequence,string"`
	RetiredChain string           `json:"retiredChain"`
	ClockFloor   int64            `json:"clockFloor"`
	Entries      []ArtifactRecord `json:"entries"`
}

func (r Record) Catalogue() bool {
	return r.Version == CatalogueManagerRecordVersion || r.Version == ScheduledCatalogueManagerRecordVersion
}
func (r ArtifactRecord) Catalogue() bool { return r.Version == CatalogueArtifactRecordVersion }
func (r ArtifactRecord) Reusable() bool {
	return r.Version == ReusableArtifactRecordVersion || r.Catalogue()
}
func (r CatalogueRecord) Find(id uint64) *ArtifactRecord {
	for i := range r.Entries {
		if r.Entries[i].RetiredCount == id {
			return &r.Entries[i]
		}
	}
	return nil
}
func (r CatalogueRecord) ReservedBytes() int64 {
	var n int64
	for _, a := range r.Entries {
		if !a.Retired {
			n += a.Artifact.Package.Size
		}
	}
	return n
}
func (r CatalogueRecord) Validate() error {
	if r.Version != CatalogueRecordVersion || r.Revision == 0 || !ValidTime(r.ClockFloor) || r.Entries == nil || (r.Sequence == 0) != (len(r.Entries) == 0) || len(r.Entries) > MaxCatalogueEntries || r.RetiredChain != "" && !ValidDigest(r.RetiredChain) {
		return ErrIntegrity
	}
	slots := map[uint32]bool{}
	var previous uint64
	for _, a := range r.Entries {
		if a.Validate() != nil || !a.Catalogue() || a.Artifact == nil || a.RetiredCount <= previous || a.RetiredCount > r.Sequence || a.ClockFloor > r.ClockFloor || slots[*a.CatalogueSlot] {
			return ErrIntegrity
		}
		slots[*a.CatalogueSlot] = true
		previous = a.RetiredCount
	}
	if r.ReservedBytes() > MaxRetainedPayloadBytes {
		return ErrIntegrity
	}
	return nil
}
func DecodeCatalogueRecord(raw []byte) (CatalogueRecord, error) {
	var r CatalogueRecord
	if Canonical(raw, &r, MaxRecordBytes) != nil || r.Validate() != nil {
		return r, ErrIntegrity
	}
	return r, nil
}
func (r ArtifactRecord) Assignment(b Binding) *CatalogueAssignment {
	for i := range r.Assignments {
		if r.Assignments[i].Binding == b {
			return &r.Assignments[i]
		}
	}
	return nil
}
func (r ArtifactRecord) CatalogueRetirementEvidence() (string, error) {
	if !r.Catalogue() {
		return "", ErrInvalid
	}
	evidence := []string{}
	for _, a := range r.Assignments {
		if !ValidDigest(a.RetirementDigest) {
			return "", ErrUncertain
		}
		evidence = append(evidence, BindingDigest(a.Binding)+":"+a.RetirementDigest)
	}
	sort.Strings(evidence)
	raw, _ := json.Marshal(evidence)
	return Digest(raw), nil
}
func (r ArtifactRecord) validateCatalogueArtifact() error {
	if !r.Catalogue() {
		if r.CatalogueSlot != nil || len(r.Assignments) != 0 {
			return ErrIntegrity
		}
		return nil
	}
	if r.CatalogueSlot == nil || *r.CatalogueSlot >= MaxCatalogueEntries || r.RetiredCount == 0 || r.RetiredChain != "" || len(r.Recent) != 0 || r.Artifact == nil || !ValidPublisherEvidence(r.Artifact.PublisherStatus, r.Artifact.PublisherEvidenceDigest) || len(r.Assignments) > MaxDevices || r.Retired && !r.RetirementStarted {
		return ErrIntegrity
	}
	previous := ""
	transfers := map[string]bool{}
	for _, a := range r.Assignments {
		if a.Binding.Validate() != nil || a.Binding.DeviceID <= previous || !ValidTransferID(a.TransferID) || a.JobSequence == 0 || transfers[a.TransferID] || (a.ResultDigest == "") != (a.RetirementDigest == "") || a.RetirementDigest != "" && (!ValidDigest(a.ResultDigest) || !ValidDigest(a.RetirementDigest)) {
			return ErrIntegrity
		}
		previous = a.Binding.DeviceID
		transfers[a.TransferID] = true
	}
	if r.RetirementStarted {
		proof, e := r.CatalogueRetirementEvidence()
		if e != nil || r.Artifact.CompletedAt == 0 || proof != r.RetirementEvidenceDigest || !enrollmentcrypto.ValidID(r.RetiredBy, "operator_") {
			return ErrIntegrity
		}
	} else if r.RetirementEvidenceDigest != "" || r.RetiredBy != "" {
		return ErrIntegrity
	}
	return nil
}
func catalogueArtifactTransition(a, b ArtifactRecord) error {
	if a.CatalogueSlot == nil || b.CatalogueSlot == nil || *a.CatalogueSlot != *b.CatalogueSlot || a.RetiredCount != b.RetiredCount || !sameJSON(a.Assignments, b.Assignments) || a.RetirementStarted && (!b.RetirementStarted || a.RetirementEvidenceDigest != b.RetirementEvidenceDigest || a.RetiredBy != b.RetiredBy) || a.Retired && !b.Retired {
		return ErrConsumed
	}
	return ArtifactTransition(a.Artifact, b.Artifact)
}

// Selection is private manager routing metadata, never endpoint authority.
type catalogueOccurrenceKey struct{}

func WithCatalogueOccurrence(ctx context.Context, n uint64) context.Context {
	return context.WithValue(ctx, catalogueOccurrenceKey{}, n)
}
func CatalogueOccurrence(ctx context.Context) (uint64, bool) {
	n, ok := ctx.Value(catalogueOccurrenceKey{}).(uint64)
	return n, ok
}
func ParseCatalogueOccurrence(s string) (uint64, error) {
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != s {
		return 0, ErrInvalid
	}
	return n, nil
}

type CatalogueStore interface {
	ReadWindowsMSICatalogue(context.Context, ed25519.PublicKey) (CatalogueRecord, error)
	ReserveWindowsMSICatalogue(context.Context, ed25519.PublicKey, time.Time, uint64, Artifact) (CatalogueRecord, error)
}
