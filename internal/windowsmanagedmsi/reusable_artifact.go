package windowsmanagedmsi

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
)

const ReusableArtifactRecordVersion = "tracebolt.windows-managed-msi-artifact-record.v3"

type RetiredArtifact struct {
	Sequence                uint64    `json:"sequence,string"`
	ArtifactID              string    `json:"artifactId"`
	Package                 Selection `json:"package"`
	PublisherStatus         string    `json:"publisherStatus"`
	PublisherEvidenceDigest string    `json:"publisherEvidenceDigest"`
	NativeAcceptanceDigest  string    `json:"nativeAcceptanceDigest"`
	EvidenceDigest          string    `json:"evidenceDigest"`
	ActorID                 string    `json:"actorId"`
}

func (r ArtifactRecord) validateReusableArtifact() error {
	if r.Version != ReusableArtifactRecordVersion {
		if r.RetiredCount != 0 || r.RetiredChain != "" || r.RetirementStarted || r.Retired || r.RetirementEvidenceDigest != "" || r.RetiredBy != "" || len(r.Recent) > 0 {
			return ErrIntegrity
		}
		if r.Artifact != nil && (r.Artifact.PublisherStatus != "" || r.Artifact.PublisherEvidenceDigest != "") {
			return ErrIntegrity
		}
		return nil
	}
	if r.RetiredCount == 0 && r.RetiredChain != "" || r.RetiredCount > 0 && !ValidDigest(r.RetiredChain) || len(r.Recent) != int(min(r.RetiredCount, uint64(MaxRecentJobs))) || r.Retired && !r.RetirementStarted {
		return ErrIntegrity
	}
	for i, v := range r.Recent {
		if v.Sequence != r.RetiredCount-uint64(len(r.Recent)-1-i) || !ValidDigest(v.ArtifactID) || !ValidSelection(v.Package) || !ValidPublisherEvidence(v.PublisherStatus, v.PublisherEvidenceDigest) || !ValidDigest(v.NativeAcceptanceDigest) || !ValidDigest(v.EvidenceDigest) || !enrollmentcrypto.ValidID(v.ActorID, "operator_") {
			return ErrIntegrity
		}
	}
	if r.Artifact != nil && !ValidPublisherEvidence(r.Artifact.PublisherStatus, r.Artifact.PublisherEvidenceDigest) {
		return ErrIntegrity
	}
	if r.RetirementStarted {
		if r.Artifact == nil || r.Artifact.CompletedAt == 0 || !ValidDigest(r.RetirementEvidenceDigest) || !enrollmentcrypto.ValidID(r.RetiredBy, "operator_") {
			return ErrIntegrity
		}
	} else if r.RetirementEvidenceDigest != "" || r.RetiredBy != "" {
		return ErrIntegrity
	}
	return nil
}
func NextArtifact(r ArtifactRecord) (ArtifactRecord, error) {
	if r.Version != ReusableArtifactRecordVersion || r.Validate() != nil || !r.Retired || r.RetiredCount == ^uint64(0) {
		return ArtifactRecord{}, ErrConsumed
	}
	a := r.Artifact
	v := RetiredArtifact{Sequence: r.RetiredCount + 1, ArtifactID: ArtifactIdentity(*a), Package: a.Package, NativeAcceptanceDigest: a.NativeAcceptanceDigest, PublisherStatus: a.PublisherStatus, PublisherEvidenceDigest: a.PublisherEvidenceDigest, EvidenceDigest: r.RetirementEvidenceDigest, ActorID: r.RetiredBy}
	raw, _ := json.Marshal(v)
	recent := append(append([]RetiredArtifact{}, r.Recent...), v)
	if len(recent) > MaxRecentJobs {
		recent = recent[len(recent)-MaxRecentJobs:]
	}
	return ArtifactRecord{Version: r.Version, ClockFloor: r.ClockFloor, RetiredCount: r.RetiredCount + 1, RetiredChain: Digest(append([]byte("Tracebolt retired MSI artifact v3\x00"+r.RetiredChain+"\x00"), raw...)), Recent: recent}, nil
}
func ArtifactRecordTransition(a, b ArtifactRecord) error {
	if a.Version != b.Version || b.ClockFloor < a.ClockFloor || b.Validate() != nil {
		return ErrIntegrity
	}
	if a.Version != ReusableArtifactRecordVersion {
		return ArtifactTransition(a.Artifact, b.Artifact)
	}
	if a.Retired && b.Artifact != nil && a.Artifact != nil && *b.Artifact != *a.Artifact {
		n, e := NextArtifact(a)
		if e != nil {
			return e
		}
		a = n
	}
	if a.RetiredCount != b.RetiredCount || a.RetiredChain != b.RetiredChain || !sameJSON(a.Recent, b.Recent) || a.RetirementStarted && (!b.RetirementStarted || a.RetirementEvidenceDigest != b.RetirementEvidenceDigest || a.RetiredBy != b.RetiredBy) || a.Retired && !b.Retired {
		return ErrConsumed
	}
	return ArtifactTransition(a.Artifact, b.Artifact)
}
