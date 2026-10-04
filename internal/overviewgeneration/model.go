// Package overviewgeneration defines the fixed process-and-volume generation
// contract. It performs no collection, transport, filesystem or assessment I/O.
package overviewgeneration

import (
	"errors"
	"localrmm/internal/completeoverview"
	"time"
)

const (
	rowEnvelopeBytes    = 27
	SchemaVersion       = "tracebolt.complete-overview-generation.v1"
	Scope               = completeoverview.SnapshotScope
	MaxManifestBytes    = 4 << 10
	MaxChunkBytes       = 64 << 10
	MaxChunkRows        = 128
	MaxRowBytes         = 32 << 10
	MaxGenerationRows   = completeoverview.MaxProcessRows
	MaxGenerationChunks = 1024
	MaxSnapshotBytes    = completeoverview.MaxSnapshotBytes
	MaxSectionBytes     = completeoverview.MaxSectionBytes
	// Fixed union envelopes add at most 32 bytes per row to the source snapshot.
	MaxCanonicalRowBytes  = MaxSectionBytes + 32*MaxGenerationRows
	MaxCanonicalWireBytes = 20 << 20
	MaxGenerationRawBytes = MaxManifestBytes + MaxGenerationChunks*MaxChunkBytes
	chunkEnvelopeReserve  = 2048
	rowDomain             = "tracebolt.complete-overview.rows.v1\x00"
	manifestDomain        = "tracebolt.complete-overview.manifest.v1\x00"
	chunkDomain           = "tracebolt.complete-overview.chunk.v1\x00"
)

var (
	ErrInvalid    = errors.New("overview_generation_invalid")
	ErrLimit      = errors.New("overview_generation_limit_exceeded")
	ErrSource     = errors.New("overview_generation_source_failed")
	ErrCanceled   = errors.New("overview_generation_canceled")
	ErrIncomplete = errors.New("overview_generation_incomplete")
	ErrClosed     = errors.New("overview_generation_closed")
)

// Row is a fixed union. Both JSON members are required; exactly one is nonnull.
// One generation contains one selected type, ordered by numeric PID or mount ID.
type Row struct {
	Process *completeoverview.Process `json:"process"`
	Volume  *completeoverview.Volume  `json:"volume"`
}
type Manifest struct {
	SchemaVersion       string                       `json:"schemaVersion"`
	Scope               string                       `json:"scope"`
	GenerationID        string                       `json:"generationId"`
	CaptureGenerationID string                       `json:"captureGenerationId"`
	Section             string                       `json:"section"`
	CaptureStartedAt    time.Time                    `json:"captureStartedAt"`
	CaptureFinishedAt   time.Time                    `json:"captureFinishedAt"`
	CollectedAt         time.Time                    `json:"collectedAt"`
	Processes           completeoverview.SectionMeta `json:"processes"`
	Volumes             completeoverview.SectionMeta `json:"volumes"`
	ObservedCount       uint64                       `json:"observedCount"`
	ChunkCount          uint32                       `json:"chunkCount"`
	CanonicalRowBytes   uint64                       `json:"canonicalRowBytes"`
	// Original whole-capture size is context only; omitted sibling rows are unverified.
	CanonicalSnapshotBytes uint64 `json:"canonicalSnapshotBytes"`
	CanonicalSectionBytes  uint64 `json:"canonicalSectionBytes"`
	RowsSHA256             string `json:"rowsSha256"`
}
type Chunk struct {
	SchemaVersion  string `json:"schemaVersion"`
	Section        string `json:"section"`
	GenerationID   string `json:"generationId"`
	ManifestSHA256 string `json:"manifestSha256"`
	Ordinal        uint32 `json:"ordinal"`
	ChunkCount     uint32 `json:"chunkCount"`
	RowOffset      uint64 `json:"rowOffset"`
	PreviousSHA256 string `json:"previousSha256"`
	Items          []Row  `json:"items"`
	SHA256         string `json:"sha256"`
}

// Complete is an unforgeable-through-exported-fields consistency receipt, not
// authorization, provenance or freshness. Rows must be promoted atomically with it.
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
	m.Processes.ObservedCount = clonePointer(m.Processes.ObservedCount)
	m.Volumes.ObservedCount = clonePointer(m.Volumes.ObservedCount)
	return m
}
func clonePointer[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
func cloneRow(r Row) Row {
	if r.Process != nil {
		p := *r.Process
		p.ParentPID = clonePointer(p.ParentPID)
		p.Name = clonePointer(p.Name)
		p.State = clonePointer(p.State)
		p.RSSBytes = clonePointer(p.RSSBytes)
		p.CPUTimeSeconds = clonePointer(p.CPUTimeSeconds)
		p.Threads = clonePointer(p.Threads)
		r.Process = &p
	}
	if r.Volume != nil {
		v := *r.Volume
		v.TotalBytes = clonePointer(v.TotalBytes)
		v.AvailableBytes = clonePointer(v.AvailableBytes)
		v.UsedPercent = clonePointer(v.UsedPercent)
		r.Volume = &v
	}
	return r
}

func (m Manifest) SelectedMeta() completeoverview.SectionMeta {
	if m.Section == "processes" {
		return cloneManifest(m).Processes
	}
	return cloneManifest(m).Volumes
}
