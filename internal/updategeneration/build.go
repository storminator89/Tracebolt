package updategeneration

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/bulkrows"
	"localrmm/internal/cachedupdates"
)

// Build takes a complete local operation plus its unmodified error. A validated
// preview alone, even with explicit preview consent, cannot authorize or provide
// a full generation. Counts and the original preview must match the full rows.
// Every failure returns zero outputs; Build performs no source or runtime I/O.
func Build(ctx context.Context, source SourceInventory, sourceErr error) (Manifest, []Chunk, error) {
	if sourceErr != nil || !source.Complete || source.Rows == nil || source.Snapshot.Coverage == "unavailable" {
		return Manifest{}, nil, ErrSource
	}
	if ctx == nil || ctx.Err() != nil {
		return Manifest{}, nil, ErrCanceled
	}
	if len(source.Rows) > MaxGenerationRows {
		return Manifest{}, nil, ErrLimit
	}
	s := source.Snapshot
	if cachedupdates.Validate(s) != nil {
		return Manifest{}, nil, ErrInvalid
	}
	if uint64(len(source.Rows)) != uint64(*s.CandidateCount) {
		return Manifest{}, nil, ErrSource
	}
	planned, err := bulkrows.Plan(ctx, source.Rows, bulkrows.Config[cachedupdates.Candidate]{MaxRows: MaxGenerationRows, MaxChunkRows: MaxChunkRows, MaxPayloadBytes: MaxChunkBytes - chunkEnvelopeReserve, MaxChunks: MaxGenerationChunks, MaxCanonicalBytes: MaxCanonicalRowBytes, Domain: rowDomain, Validate: ValidateRow, Less: rowLess, Canonical: canonicalRow})
	if err != nil {
		switch {
		case errors.Is(err, bulkrows.ErrCanceled):
			err = ErrCanceled
		case errors.Is(err, bulkrows.ErrLimit):
			err = ErrLimit
		case errors.Is(err, bulkrows.ErrInvalid):
			err = ErrInvalid
		}
		return Manifest{}, nil, err
	}
	held := uint32(0)
	for i, row := range planned.Rows {
		if ctx.Err() != nil {
			return Manifest{}, nil, ErrCanceled
		}
		if i < len(s.Items) && row != s.Items[i] {
			return Manifest{}, nil, ErrSource
		}
		if row.State == "held" {
			held++
		}
	}
	if held != *s.HeldCount {
		return Manifest{}, nil, ErrSource
	}
	count := len(planned.Boundaries) - 1
	coverage, reason := "complete", cachedupdates.ReasonNone
	if *s.UnknownCount > 0 {
		coverage, reason = "partial", cachedupdates.ReasonCandidateUnknown
	}
	m := cloneManifest(Manifest{SchemaVersion: SchemaVersion, Scope: Scope, GenerationID: s.GenerationID, CollectedAt: s.CollectedAt, DurationMS: s.DurationMS, Release: s.Release, Metadata: s.Metadata, ComparisonCoverage: coverage, ComparisonReason: reason, InstalledCount: *s.InstalledCount, CheckedCount: *s.CheckedCount, CandidateCount: *s.CandidateCount, HeldCount: *s.HeldCount, UnknownCount: *s.UnknownCount, ChunkCount: uint32(count), CanonicalRowBytes: planned.CanonicalBytes, RowsSHA256: planned.RowsSHA256})
	md, err := ManifestDigest(m)
	if err != nil {
		return Manifest{}, nil, err
	}
	mb, _ := json.Marshal(m)
	wireBytes := uint64(len(mb))
	chunks := make([]Chunk, 0, count)
	previous := ""
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			return Manifest{}, nil, ErrCanceled
		}
		a, b := planned.Boundaries[i], planned.Boundaries[i+1]
		c := Chunk{SchemaVersion: SchemaVersion, GenerationID: m.GenerationID, ManifestSHA256: md, Ordinal: uint32(i), ChunkCount: uint32(count), RowOffset: uint64(a), PreviousSHA256: previous, Items: planned.Rows[a:b:b]}
		c.SHA256 = chunkDigest(c)
		raw, _ := json.Marshal(c)
		if len(raw) > MaxChunkBytes || uint64(len(raw)) > MaxCanonicalWireBytes-wireBytes {
			return Manifest{}, nil, ErrLimit
		}
		if err := ValidateChunk(c); err != nil {
			return Manifest{}, nil, err
		}
		wireBytes += uint64(len(raw))
		previous = c.SHA256
		chunks = append(chunks, c)
	}
	if ctx.Err() != nil {
		return Manifest{}, nil, ErrCanceled
	}
	return m, chunks, nil
}
