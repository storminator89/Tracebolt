package windowsmanagedmsi

// ReferencesArtifactOccurrence compares manager-owned custody occurrences, not
// content identity. A retired older assignment cannot stand in for a fresh copy
// of the same bytes. Unresolved or inconsistent older evidence always blocks.
func ReferencesArtifactOccurrence(r Record, a ArtifactRecord) (bool, error) {
	if r.Artifact == nil {
		return false, nil
	}
	if a.Catalogue() {
		if !r.Catalogue() {
			return false, ErrIntegrity
		}
		assignment := a.Assignment(r.Grant.Binding)
		if r.ArtifactRetiredCount != a.RetiredCount {
			if assignment != nil && assignment.RetirementDigest == "" {
				return false, ErrUncertain
			}
			return false, nil
		}
		if assignment == nil || a.Artifact == nil || *a.Artifact != *r.Artifact || r.TransferID != assignment.TransferID || r.Jobs == nil || r.Jobs.Sequence != assignment.JobSequence {
			return false, ErrIntegrity
		}
		if len(r.RetiredReport) > 0 && assignment.RetirementDigest != Digest(r.RetiredReport) || len(r.RetiredReport) == 0 && assignment.RetirementDigest != "" {
			return false, ErrIntegrity
		}
		return true, nil
	}
	if a.Version != ReusableArtifactRecordVersion {
		return a.Artifact != nil && ArtifactIdentity(*r.Artifact) == ArtifactIdentity(*a.Artifact), nil
	}
	if !r.Grant.Reusable() || r.ArtifactRetiredCount > a.RetiredCount {
		return false, ErrIntegrity
	}
	if r.ArtifactRetiredCount < a.RetiredCount {
		if len(r.RetiredReport) == 0 {
			return false, ErrUncertain
		}
		return false, nil
	}
	if a.Artifact == nil || *r.Artifact != *a.Artifact {
		return false, ErrIntegrity
	}
	return true, nil
}
