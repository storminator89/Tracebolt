package fullinventory

import (
	"encoding/json"
	"localrmm/internal/linuxpackages"
	"time"
)

// ValidateManifest is a typed metadata check, not generation completion. Incoming
// JSON must use DecodeManifest for exact shape/duplicate/type/raw-byte checks.
func ValidateManifest(m Manifest) error {
	if m.SchemaVersion != SchemaVersion || m.Scope != Scope || !validDigest(m.RowsSHA256) {
		return ErrInvalid
	}
	if m.ObservedCount > MaxGenerationRows || m.ChunkCount > MaxGenerationChunks || m.CanonicalRowBytes > MaxCanonicalRowBytes {
		return ErrLimit
	}
	if m.InstalledCount > m.ObservedCount {
		return ErrInvalid
	}
	if err := validateMetadata(m.GenerationID, m.CollectedAt, m.DurationMS, m.Release); err != nil {
		return err
	}
	if m.ObservedCount == 0 {
		if m.ChunkCount != 0 || m.CanonicalRowBytes != 0 || m.RowsSHA256 != hashHex(newRowsHash()) {
			return ErrInvalid
		}
	} else if m.ChunkCount == 0 || uint64(m.ChunkCount) > m.ObservedCount ||
		uint64(m.ChunkCount)*MaxChunkRows < m.ObservedCount || m.CanonicalRowBytes < m.ObservedCount ||
		m.CanonicalRowBytes > uint64(m.ChunkCount)*MaxChunkBytes {
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

// ValidateChunk checks one typed chunk, its row ordering and its self-digest.
// Only Validator.Add can check linkage against its generation and other chunks.
func ValidateChunk(c Chunk) error {
	if c.SchemaVersion != SchemaVersion || !validGeneration(c.GenerationID) ||
		!validDigest(c.ManifestSHA256) || !validDigest(c.SHA256) {
		return ErrInvalid
	}
	if len(c.Items) > MaxChunkRows || c.ChunkCount > MaxGenerationChunks || c.RowOffset > MaxGenerationRows {
		return ErrLimit
	}
	if c.ChunkCount == 0 || c.Ordinal >= c.ChunkCount || len(c.Items) == 0 ||
		c.RowOffset+uint64(len(c.Items)) > MaxGenerationRows ||
		(c.Ordinal == 0 && (c.PreviousSHA256 != "" || c.RowOffset != 0)) ||
		(c.Ordinal != 0 && (!validDigest(c.PreviousSHA256) || c.RowOffset == 0)) {
		return ErrInvalid
	}
	for i, p := range c.Items {
		if err := ValidateRow(p); err != nil {
			return err
		}
		if i > 0 && !rowLess(c.Items[i-1], p) {
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

// Existing linuxpackages.Validate remains the sole row grammar/source-mapping/
// install-state authority. A bounded one-row complete snapshot avoids its legacy
// GLOBAL 128-row/16-KiB export cap without replacing any validation semantics.
func ValidateRow(p linuxpackages.PackageRow) error {
	if len(p.Name) > linuxpackages.MaxPackageName || len(p.SourcePackage) > linuxpackages.MaxPackageName ||
		len(p.Architecture) > linuxpackages.MaxArchitecture || len(p.Version) > linuxpackages.MaxVersion ||
		len(p.SourceVersion) > linuxpackages.MaxVersion {
		return ErrInvalid
	}
	observed, installed := uint64(1), uint64(0)
	if p.InstallState == "installed" {
		installed = 1
	}
	s := validationSnapshot()
	s.Inventory.ObservedCount, s.Inventory.InstalledCount = &observed, &installed
	s.Inventory.Items = []linuxpackages.PackageRow{p}
	if linuxpackages.Validate(s) != nil {
		return ErrInvalid
	}
	return nil
}
func validateMetadata(id string, at time.Time, duration int64, release linuxpackages.ReleaseObservation) error {
	s := validationSnapshot()
	s.GenerationID, s.CollectedAt, s.DurationMS, s.Release = id, at, duration, release
	if linuxpackages.Validate(s) != nil {
		return ErrInvalid
	}
	return nil
}
func validGeneration(id string) bool {
	if len(id) != len("sample_")+32 || id[:len("sample_")] != "sample_" {
		return false
	}
	for _, ch := range id[len("sample_"):] {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}
func validationSnapshot() linuxpackages.Snapshot {
	zero := uint64(0)
	return linuxpackages.Snapshot{SchemaVersion: linuxpackages.SchemaVersion, Scope: linuxpackages.SnapshotScope,
		GenerationID: "sample_00000000000000000000000000000000", CollectedAt: time.Unix(0, 0).UTC(),
		Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing},
		Inventory: linuxpackages.Inventory{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone,
			Complete: true, CountExact: true, ObservedCount: &zero, InstalledCount: &zero, Items: []linuxpackages.PackageRow{}}}
}

// This is exactly linuxpackages' name/architecture ordering, not a version
// comparator. Versions remain verbatim and are never compared here.
func rowLess(a, b linuxpackages.PackageRow) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.Architecture < b.Architecture
}
