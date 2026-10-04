// Package fullinventory defines a pure, isolated complete-package generation
// contract. It performs no source, filesystem, transport or assessment I/O.
package fullinventory

import (
	"errors"
	"localrmm/internal/linuxpackages"
	"time"
)

const (
	SchemaVersion        = "tracebolt.complete-linux-packages.v1"
	Scope                = linuxpackages.SnapshotScope
	MaxManifestBytes     = 4 << 10
	MaxChunkBytes        = 64 << 10
	MaxChunkRows         = 128
	MaxGenerationRows    = linuxpackages.MaxDpkgRecords
	MaxGenerationChunks  = 1024
	MaxCanonicalRowBytes = 32 << 20
	// MaxCanonicalWireBytes bounds canonical encodings, not whitespace-padded ingress.
	MaxCanonicalWireBytes = 48 << 20
	// Unique accepted raw objects have this upper bound; retries need an ingress quota.
	MaxGenerationRawBytes = MaxManifestBytes + MaxGenerationChunks*MaxChunkBytes
	// Reserve bounds every canonical chunk envelope independently of row lengths.
	chunkEnvelopeReserve = 2048
	rowDomain            = "tracebolt.complete-linux-packages.rows.v1\x00"
	manifestDomain       = "tracebolt.complete-linux-packages.manifest.v1\x00"
	chunkDomain          = "tracebolt.complete-linux-packages.chunk.v1\x00"
)

var (
	ErrInvalid    = errors.New("full_inventory_invalid")
	ErrLimit      = errors.New("full_inventory_limit_exceeded")
	ErrSource     = errors.New("full_inventory_source_failed")
	ErrCanceled   = errors.New("full_inventory_canceled")
	ErrIncomplete = errors.New("full_inventory_incomplete")
	ErrClosed     = errors.New("full_inventory_closed")
)

// SourceInventory is local full-source input, never an incoming wire DTO. Rows
// must be the entire successful ParseDpkgStatus result BEFORE any Trim/export.
// A nonnil empty Rows means a valid residual-only source; nil is unavailable.
// Build additionally requires the source operation's error and rejects failures.
// Neither this type nor the hashes authenticate the source or its claimed time.
type SourceInventory struct {
	GenerationID string
	CollectedAt  time.Time
	DurationMS   int64
	Release      linuxpackages.ReleaseObservation
	Rows         []linuxpackages.PackageRow
}

// Manifest declares the complete selected installed/incomplete dpkg dataset.
// Completeness is established only by Validator.Finish, never by this type alone.
// Counts are source-selected rows, not all source stanzas or vulnerability counts.
type Manifest struct {
	SchemaVersion     string                           `json:"schemaVersion"`
	Scope             string                           `json:"scope"`
	GenerationID      string                           `json:"generationId"`
	CollectedAt       time.Time                        `json:"collectedAt"`
	DurationMS        int64                            `json:"durationMs"`
	Release           linuxpackages.ReleaseObservation `json:"release"`
	ObservedCount     uint64                           `json:"observedCount"`
	InstalledCount    uint64                           `json:"installedCount"`
	ChunkCount        uint32                           `json:"chunkCount"`
	CanonicalRowBytes uint64                           `json:"canonicalRowBytes"`
	RowsSHA256        string                           `json:"rowsSha256"`
}

// Chunk is a nonempty contiguous part of one manifest. Ordinal is zero-based;
// PreviousSHA256 is empty only for ordinal zero. SHA256 hashes all other fields.
type Chunk struct {
	SchemaVersion  string                     `json:"schemaVersion"`
	GenerationID   string                     `json:"generationId"`
	ManifestSHA256 string                     `json:"manifestSha256"`
	Ordinal        uint32                     `json:"ordinal"`
	ChunkCount     uint32                     `json:"chunkCount"`
	RowOffset      uint64                     `json:"rowOffset"`
	PreviousSHA256 string                     `json:"previousSha256"`
	Items          []linuxpackages.PackageRow `json:"items"`
	SHA256         string                     `json:"sha256"`
}

// Complete is a nonforgeable-through-exported-fields consistency receipt. Its
// zero value is invalid. It is not authorization, freshness or provenance proof.
// The validator does not retain rows; a storage layer must stage validated rows
// and atomically promote only alongside a valid matching receipt.
type Complete struct {
	manifest       Manifest
	manifestSHA256 string
	lastSHA256     string
	wireBytes      uint64
	valid          bool
}

func (c Complete) Valid() bool                { return c.valid }
func (c Complete) Manifest() Manifest         { return cloneManifest(c.manifest) }
func (c Complete) ManifestSHA256() string     { return c.manifestSHA256 }
func (c Complete) LastChunkSHA256() string    { return c.lastSHA256 }
func (c Complete) CanonicalWireBytes() uint64 { return c.wireBytes }

func cloneManifest(m Manifest) Manifest {
	m.Release.Fields.ID = cloneString(m.Release.Fields.ID)
	m.Release.Fields.VersionID = cloneString(m.Release.Fields.VersionID)
	m.Release.Fields.VersionCodename = cloneString(m.Release.Fields.VersionCodename)
	return m
}
func cloneString(s *string) *string {
	if s == nil {
		return nil
	}
	v := *s
	return &v
}
