package overviewgeneration

import (
	"encoding/json"
	"localrmm/internal/completeoverview"
	"localrmm/internal/enrollmentcrypto"
	"strconv"
	"strings"
	"time"
)

// ValidateManifest validates claims, not completeness. DecodeManifest is required
// for untrusted JSON, including exact-shape and duplicate-member checks.
func ValidateManifest(m Manifest) error {
	if m.SchemaVersion != SchemaVersion || m.Scope != Scope || !validGeneration(m.GenerationID) || !validGeneration(m.CaptureGenerationID) || !validSection(m.Section) || !validDigest(m.RowsSHA256) ||
		!validTime(m.CaptureStartedAt) || !validTime(m.CaptureFinishedAt) || !validTime(m.CollectedAt) ||
		m.CaptureFinishedAt.Before(m.CaptureStartedAt) || !m.CollectedAt.Equal(m.CaptureStartedAt) {
		return ErrInvalid
	}
	if m.ObservedCount > MaxGenerationRows || m.ChunkCount > MaxGenerationChunks || m.CanonicalRowBytes > MaxCanonicalRowBytes || m.CanonicalSnapshotBytes > MaxSnapshotBytes || m.CanonicalSectionBytes > MaxSectionBytes {
		return ErrLimit
	}
	for i, meta := range []completeoverview.SectionMeta{m.Processes, m.Volumes} {
		var n uint64
		if meta.ObservedCount != nil {
			n = *meta.ObservedCount
		}
		limit := uint64(completeoverview.MaxProcessRows)
		if i == 1 {
			limit = completeoverview.MaxVolumeRows
		}
		if n > limit {
			return ErrLimit
		}
		if meta.GenerationID != m.CaptureGenerationID || completeoverview.ValidateSectionMeta(meta, int(n)) != nil {
			return ErrInvalid
		}
	}
	selected := m.SelectedMeta()
	if selected.Coverage != completeoverview.Complete || selected.ObservedCount == nil || m.ObservedCount != *selected.ObservedCount {
		return ErrInvalid
	}
	base, processBase, volumeBase := emptyBytes(m)
	sectionBase := processBase
	if m.Section == "volumes" {
		sectionBase = volumeBase
	}
	if m.CanonicalSnapshotBytes < base || m.CanonicalSectionBytes < sectionBase || m.CanonicalSectionBytes > m.CanonicalSnapshotBytes {
		return ErrInvalid
	}
	if m.CanonicalSectionBytes < sectionBase+commaBytes(m.ObservedCount) || m.CanonicalRowBytes != m.CanonicalSectionBytes-sectionBase-commaBytes(m.ObservedCount)+rowEnvelopeBytes*m.ObservedCount || m.CanonicalSnapshotBytes < base+m.CanonicalSectionBytes-sectionBase {
		return ErrInvalid
	}
	if m.ObservedCount == 0 {
		if m.ChunkCount != 0 || m.CanonicalRowBytes != 0 || m.CanonicalSectionBytes != sectionBase || m.RowsSHA256 != hashHex(newRowsHash()) {
			return ErrInvalid
		}
	} else if m.ChunkCount == 0 || uint64(m.ChunkCount) > m.ObservedCount || uint64(m.ChunkCount)*MaxChunkRows < m.ObservedCount || m.CanonicalRowBytes < m.ObservedCount || m.CanonicalRowBytes > uint64(m.ChunkCount)*MaxChunkBytes || m.CanonicalSectionBytes == sectionBase {
		return ErrInvalid
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ErrInvalid
	}
	if len(b) > MaxManifestBytes {
		return ErrLimit
	}
	return nil
}
func ValidateChunk(c Chunk) error {
	if c.SchemaVersion != SchemaVersion || !validSection(c.Section) || !validGeneration(c.GenerationID) || !validDigest(c.ManifestSHA256) || !validDigest(c.SHA256) {
		return ErrInvalid
	}
	if len(c.Items) > MaxChunkRows || c.ChunkCount > MaxGenerationChunks || c.RowOffset > MaxGenerationRows {
		return ErrLimit
	}
	if c.ChunkCount == 0 || c.Ordinal >= c.ChunkCount || len(c.Items) == 0 || c.RowOffset+uint64(len(c.Items)) > MaxGenerationRows ||
		c.Ordinal == 0 && (c.PreviousSHA256 != "" || c.RowOffset != 0) || c.Ordinal != 0 && (!validDigest(c.PreviousSHA256) || c.RowOffset == 0) {
		return ErrInvalid
	}
	for i, r := range c.Items {
		if err := ValidateRow(r); err != nil {
			return err
		}
		if i > 0 && !rowLess(c.Items[i-1], r) {
			return ErrInvalid
		}
		if (c.Section == "processes") != (r.Process != nil) {
			return ErrInvalid
		}
	}
	b, err := json.Marshal(c)
	if err != nil {
		return ErrInvalid
	}
	if len(b) > MaxChunkBytes {
		return ErrLimit
	}
	if c.SHA256 != chunkDigest(c) {
		return ErrInvalid
	}
	return nil
}
func ValidateRow(r Row) error {
	if (r.Process == nil) == (r.Volume == nil) {
		return ErrInvalid
	}
	if r.Process != nil && completeoverview.ValidateProcess(*r.Process) != nil || r.Volume != nil && completeoverview.ValidateVolume(*r.Volume) != nil {
		return ErrInvalid
	}
	b, err := json.Marshal(r)
	if err != nil {
		return ErrInvalid
	}
	if len(b) > MaxRowBytes {
		return ErrLimit
	}
	return nil
}
func validGeneration(id string) bool { return enrollmentcrypto.ValidID(id, "sample_") }
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Location() == time.UTC
}
func volumeID(id string) uint32 {
	n, _ := strconv.ParseUint(strings.TrimPrefix(id, "mount_"), 10, 32)
	return uint32(n)
}
func rowLess(a, b Row) bool {
	if a.Process != nil {
		return b.Volume != nil || b.Process != nil && a.Process.PID < b.Process.PID
	}
	return a.Volume != nil && b.Volume != nil && volumeID(a.Volume.ID) < volumeID(b.Volume.ID)
}
func validSection(section string) bool { return section == "processes" || section == "volumes" }
func rowIdentity(r Row) uint32 {
	if r.Process != nil {
		return r.Process.PID
	}
	if r.Volume != nil {
		return volumeID(r.Volume.ID)
	}
	return 0
}
func emptySnapshot(m Manifest) completeoverview.Snapshot {
	return completeoverview.Snapshot{SchemaVersion: completeoverview.SchemaVersion, GenerationID: m.CaptureGenerationID, CaptureStartedAt: m.CaptureStartedAt, CaptureFinishedAt: m.CaptureFinishedAt, Scope: m.Scope,
		Processes: completeoverview.ProcessSection{Meta: m.Processes, Items: []completeoverview.Process{}}, Volumes: completeoverview.VolumeSection{Meta: m.Volumes, Items: []completeoverview.Volume{}}}
}
func emptyBytes(m Manifest) (uint64, uint64, uint64) {
	s := emptySnapshot(m)
	b, _ := json.Marshal(s)
	p, _ := json.Marshal(s.Processes)
	v, _ := json.Marshal(s.Volumes)
	return uint64(len(b)), uint64(len(p)), uint64(len(v))
}
func commaBytes(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return n - 1
}

// CompareRows compares canonical ordering only. ValidateRow must precede use.
func CompareRows(a, b Row) int {
	if rowLess(a, b) {
		return -1
	}
	if rowLess(b, a) {
		return 1
	}
	return 0
}

// RowSearchText contains retained display labels only, for bounded operator search.
func RowSearchText(r Row) string {
	if r.Process != nil {
		s := strconv.FormatUint(uint64(r.Process.PID), 10)
		if r.Process.Name != nil {
			s += " " + *r.Process.Name
		}
		return s
	}
	if r.Volume != nil {
		return r.Volume.ID + " " + r.Volume.MountPoint + " " + r.Volume.Filesystem + " " + r.Volume.Kind
	}
	return ""
}
