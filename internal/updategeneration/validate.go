package updategeneration

import (
	"encoding/json"
	"localrmm/internal/cachedupdates"
)

func ValidateManifest(m Manifest) error {
	if m.SchemaVersion != SchemaVersion || m.Scope != Scope || !validDigest(m.RowsSHA256) {
		return ErrInvalid
	}
	if m.CandidateCount > MaxGenerationRows || m.ChunkCount > MaxGenerationChunks || m.CanonicalRowBytes > MaxCanonicalRowBytes {
		return ErrLimit
	}
	if err := validateMetadata(m); err != nil {
		return err
	}
	if m.CandidateCount == 0 {
		if m.ChunkCount != 0 || m.CanonicalRowBytes != 0 || m.RowsSHA256 != hashHex(newRowsHash()) {
			return ErrInvalid
		}
	} else if m.ChunkCount == 0 || m.ChunkCount > m.CandidateCount || uint64(m.ChunkCount)*MaxChunkRows < uint64(m.CandidateCount) || m.CanonicalRowBytes < uint64(m.CandidateCount) || m.CanonicalRowBytes > uint64(m.CandidateCount)*MaxRowBytes || m.CanonicalRowBytes > uint64(m.ChunkCount)*MaxChunkBytes {
		return ErrInvalid
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return ErrInvalid
	}
	if len(raw) > MaxManifestBytes {
		return ErrLimit
	}
	return nil
}

// validateMetadata reuses the preview contract's release, time, cache-age and
// count semantics in an empty display preview. The artificial preview is not
// returned or used as completeness evidence, and no original age is replaced.
func validateMetadata(m Manifest) error {
	s := cachedupdates.Snapshot{SchemaVersion: cachedupdates.SchemaVersion, Scope: cachedupdates.Scope, GenerationID: m.GenerationID, CollectedAt: m.CollectedAt, DurationMS: m.DurationMS, Release: m.Release, Metadata: m.Metadata, InstalledCount: &m.InstalledCount, CheckedCount: &m.CheckedCount, CandidateCount: &m.CandidateCount, HeldCount: &m.HeldCount, UnknownCount: &m.UnknownCount, Coverage: "complete", Reason: cachedupdates.ReasonNone, Items: []cachedupdates.Candidate{}}
	if m.CandidateCount > 0 {
		s.Truncated = true
		s.Coverage = "partial"
		s.Reason = cachedupdates.ReasonItemLimit
	} else if m.UnknownCount > 0 {
		s.Coverage = "partial"
		s.Reason = cachedupdates.ReasonCandidateUnknown
	}
	if cachedupdates.Validate(s) != nil {
		return ErrInvalid
	}
	if m.UnknownCount == 0 {
		if m.ComparisonCoverage != "complete" || m.ComparisonReason != cachedupdates.ReasonNone {
			return ErrInvalid
		}
	} else if m.ComparisonCoverage != "partial" || m.ComparisonReason != cachedupdates.ReasonCandidateUnknown {
		return ErrInvalid
	}
	return nil
}

// ValidateRow preserves the existing candidate grammar and native-version
// comparison semantics. It is independent of preview row/count/byte limits.
func ValidateRow(row cachedupdates.Candidate) error {
	if len(row.Name) > 256 || len(row.Architecture) > 64 || len(row.InstalledVersion) > 512 || len(row.CandidateVersion) > 512 || cachedupdates.ValidateCandidate(row) != nil {
		return ErrInvalid
	}
	if len(canonicalRow(row)) > MaxRowBytes {
		return ErrLimit
	}
	return nil
}
func rowLess(a, b cachedupdates.Candidate) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.Architecture < b.Architecture
}
func validGeneration(s string) bool {
	const prefix = "sample_"
	if len(s) != len(prefix)+32 || s[:len(prefix)] != prefix {
		return false
	}
	for _, r := range s[len(prefix):] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// ValidateChunk checks independent typed shape, row ordering and self-digest.
// Incoming bytes must use DecodeChunk; cross-chunk linkage requires Validator.
func ValidateChunk(c Chunk) error {
	if c.SchemaVersion != SchemaVersion || !validGeneration(c.GenerationID) || !validDigest(c.ManifestSHA256) || !validDigest(c.SHA256) {
		return ErrInvalid
	}
	if len(c.Items) > MaxChunkRows || c.ChunkCount > MaxGenerationChunks || c.RowOffset > MaxGenerationRows {
		return ErrLimit
	}
	if c.ChunkCount == 0 || c.Ordinal >= c.ChunkCount || len(c.Items) == 0 || c.RowOffset+uint64(len(c.Items)) > MaxGenerationRows || c.Ordinal == 0 && (c.PreviousSHA256 != "" || c.RowOffset != 0) || c.Ordinal != 0 && (!validDigest(c.PreviousSHA256) || c.RowOffset == 0) {
		return ErrInvalid
	}
	for i, row := range c.Items {
		if err := ValidateRow(row); err != nil {
			return err
		}
		if i > 0 && !rowLess(c.Items[i-1], row) {
			return ErrInvalid
		}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return ErrInvalid
	}
	if len(raw) > MaxChunkBytes {
		return ErrLimit
	}
	if c.SHA256 != chunkDigest(c) {
		return ErrInvalid
	}
	return nil
}
