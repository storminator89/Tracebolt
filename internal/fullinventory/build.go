package fullinventory

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/bulkrows"
	"localrmm/internal/linuxpackages"
)

// Build accepts only an entire completed local source operation. sourceErr must
// be passed through from that operation (including stat/read/change checks), not
// discarded after obtaining a prefix. On any failure all return values are zero.
// Build does not collect sources, accept incoming snapshots or call Trim.
func Build(ctx context.Context, source SourceInventory, sourceErr error) (Manifest, []Chunk, error) {
	if sourceErr != nil || source.Rows == nil {
		return Manifest{}, nil, ErrSource
	}
	if ctx == nil || ctx.Err() != nil {
		return Manifest{}, nil, ErrCanceled
	}
	if len(source.Rows) > MaxGenerationRows {
		return Manifest{}, nil, ErrLimit
	}
	if err := validateMetadata(source.GenerationID, source.CollectedAt, source.DurationMS, source.Release); err != nil {
		return Manifest{}, nil, err
	}
	plan, err := bulkrows.Plan(ctx, source.Rows, bulkrows.Config[linuxpackages.PackageRow]{
		MaxRows: MaxGenerationRows, MaxChunkRows: MaxChunkRows,
		MaxPayloadBytes: MaxChunkBytes - chunkEnvelopeReserve, MaxChunks: MaxGenerationChunks,
		MaxCanonicalBytes: MaxCanonicalRowBytes, Domain: rowDomain,
		Validate: ValidateRow, Less: rowLess, Canonical: canonicalRow,
	})
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
	rows, boundaries := plan.Rows, plan.Boundaries
	count := len(boundaries) - 1
	var installed uint64
	for _, row := range rows {
		if ctx.Err() != nil {
			return Manifest{}, nil, ErrCanceled
		}
		if row.InstallState == "installed" {
			installed++
		}
	}
	m := cloneManifest(Manifest{SchemaVersion: SchemaVersion, Scope: Scope, GenerationID: source.GenerationID,
		CollectedAt: source.CollectedAt, DurationMS: source.DurationMS, Release: source.Release,
		ObservedCount: uint64(len(rows)), InstalledCount: installed, ChunkCount: uint32(count),
		CanonicalRowBytes: plan.CanonicalBytes, RowsSHA256: plan.RowsSHA256})
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
		a, b := boundaries[i], boundaries[i+1]
		c := Chunk{SchemaVersion: SchemaVersion, GenerationID: m.GenerationID, ManifestSHA256: md,
			Ordinal: uint32(i), ChunkCount: uint32(count), RowOffset: uint64(a), PreviousSHA256: previous,
			Items: rows[a:b:b]}
		c.SHA256 = chunkDigest(c)
		raw, _ := json.Marshal(c)
		if len(raw) > MaxChunkBytes || uint64(len(raw)) > MaxCanonicalWireBytes-wireBytes {
			return Manifest{}, nil, ErrLimit
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
