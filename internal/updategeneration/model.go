// Package updategeneration is a pure, unwired complete-known-candidate adapter.
// It performs no source, transport, filesystem, consent or assessment I/O.
// A complete receipt proves consistency of every declared known-candidate row;
// unknown comparisons remain unknown, never an all-up-to-date assertion.
package updategeneration

import (
	"errors"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/linuxpackages"
	"time"
)

const (
	SchemaVersion         = "tracebolt.complete-cached-apt-updates.v1"
	Scope                 = "agent-visible-complete-known-cached-apt-candidate-rows"
	MaxManifestBytes      = 4 << 10
	MaxChunkBytes         = 64 << 10
	MaxChunkRows          = 128
	MaxRowBytes           = 2 << 10
	MaxGenerationRows     = cachedupdates.MaxInstalledRows
	MaxGenerationChunks   = 1024
	MaxCanonicalRowBytes  = 32 << 20
	MaxCanonicalWireBytes = 48 << 20
	MaxGenerationRawBytes = MaxManifestBytes + MaxGenerationChunks*MaxChunkBytes
	chunkEnvelopeReserve  = 2048
	rowDomain             = "tracebolt.complete-cached-apt-updates.rows.v1\x00"
	manifestDomain        = "tracebolt.complete-cached-apt-updates.manifest.v1\x00"
	chunkDomain           = "tracebolt.complete-cached-apt-updates.chunk.v1\x00"
)

var (
	ErrInvalid    = errors.New("update_generation_invalid")
	ErrLimit      = errors.New("update_generation_limit_exceeded")
	ErrSource     = errors.New("update_generation_source_failed")
	ErrCanceled   = errors.New("update_generation_canceled")
	ErrIncomplete = errors.New("update_generation_incomplete")
	ErrClosed     = errors.New("update_generation_closed")
)

// SourceInventory is local full-source input, never a wire DTO. Rows must be the
// entire successful source operation's candidate set BEFORE preview trimming.
// Snapshot retains that operation's original bounded preview and metadata.
// Complete is a required caller assertion about the finished source operation,
// not evidence of provenance, freshness, consent or successful comparisons.
// Source errors must be passed to Build; nil Rows never means successful zero.
// Existing preview consent does not authorize any future full-row transmission.
type SourceInventory struct {
	Snapshot cachedupdates.Snapshot
	Rows     []cachedupdates.Candidate
	Complete bool
}

type Manifest struct {
	SchemaVersion      string                      `json:"schemaVersion"`
	Scope              string                      `json:"scope"`
	GenerationID       string                      `json:"generationId"`
	CollectedAt        time.Time                   `json:"collectedAt"`
	DurationMS         int64                       `json:"durationMs"`
	Release            linuxpackages.ReleaseFields `json:"release"`
	Metadata           cachedupdates.Metadata      `json:"metadata"`
	ComparisonCoverage string                      `json:"comparisonCoverage"`
	ComparisonReason   cachedupdates.Reason        `json:"comparisonReason"`
	InstalledCount     uint32                      `json:"installedCount"`
	CheckedCount       uint32                      `json:"checkedCount"`
	CandidateCount     uint32                      `json:"candidateCount"`
	HeldCount          uint32                      `json:"heldCount"`
	UnknownCount       uint32                      `json:"unknownCount"`
	ChunkCount         uint32                      `json:"chunkCount"`
	CanonicalRowBytes  uint64                      `json:"canonicalRowBytes"`
	RowsSHA256         string                      `json:"rowsSha256"`
}

type Chunk struct {
	SchemaVersion  string                    `json:"schemaVersion"`
	GenerationID   string                    `json:"generationId"`
	ManifestSHA256 string                    `json:"manifestSha256"`
	Ordinal        uint32                    `json:"ordinal"`
	ChunkCount     uint32                    `json:"chunkCount"`
	RowOffset      uint64                    `json:"rowOffset"`
	PreviousSHA256 string                    `json:"previousSha256"`
	Items          []cachedupdates.Candidate `json:"items"`
	SHA256         string                    `json:"sha256"`
}

// Complete cannot be constructed valid through exported fields. It is a
// consistency receipt only. Atomic persistence/promotion and authentication
// belong to a future caller; this package does not register an ingress route.
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
func clonePointer[T any](p *T) *T {
	if p == nil {
		return nil
	}
	value := *p
	return &value
}
func cloneManifest(m Manifest) Manifest {
	m.Release.ID = clonePointer(m.Release.ID)
	m.Release.VersionID = clonePointer(m.Release.VersionID)
	m.Release.VersionCodename = clonePointer(m.Release.VersionCodename)
	m.Metadata.OldestIndexModifiedAt = clonePointer(m.Metadata.OldestIndexModifiedAt)
	m.Metadata.AgeSeconds = clonePointer(m.Metadata.AgeSeconds)
	return m
}
