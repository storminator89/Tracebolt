package fullinventory

import (
	"context"
	"encoding/json"
	"localrmm/internal/linuxpackages"
	"sort"
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
	var rowBytes, installed uint64
	// Validate and budget before sorting/allocating the detached row descriptors.
	for _, p := range source.Rows {
		if ctx.Err() != nil {
			return Manifest{}, nil, ErrCanceled
		}
		if err := ValidateRow(p); err != nil {
			return Manifest{}, nil, err
		}
		size := uint64(len(canonicalRow(p)))
		if size > MaxCanonicalRowBytes-rowBytes {
			return Manifest{}, nil, ErrLimit
		}
		rowBytes += size
		if p.InstallState == "installed" {
			installed++
		}
	}
	rows := append(make([]linuxpackages.PackageRow, 0, len(source.Rows)), source.Rows...)
	sort.Slice(rows, func(i, j int) bool { return rowLess(rows[i], rows[j]) })
	if ctx.Err() != nil {
		return Manifest{}, nil, ErrCanceled
	}
	h := newRowsHash()
	boundaries := []int{0}
	start, payloadBytes := 0, 0
	for i, p := range rows {
		if ctx.Err() != nil {
			return Manifest{}, nil, ErrCanceled
		}
		if i > 0 && !rowLess(rows[i-1], p) {
			return Manifest{}, nil, ErrInvalid
		}
		b := canonicalRow(p)
		if i-start == MaxChunkRows || payloadBytes+len(b) > MaxChunkBytes-chunkEnvelopeReserve {
			boundaries = append(boundaries, i)
			start, payloadBytes = i, 0
		}
		payloadBytes += len(b)
		_, _ = h.Write(b)
	}
	if len(rows) > 0 {
		boundaries = append(boundaries, len(rows))
	}
	count := len(boundaries) - 1
	if count > MaxGenerationChunks {
		return Manifest{}, nil, ErrLimit
	}
	m := cloneManifest(Manifest{SchemaVersion: SchemaVersion, Scope: Scope, GenerationID: source.GenerationID,
		CollectedAt: source.CollectedAt, DurationMS: source.DurationMS, Release: source.Release,
		ObservedCount: uint64(len(rows)), InstalledCount: installed, ChunkCount: uint32(count),
		CanonicalRowBytes: rowBytes, RowsSHA256: hashHex(h)})
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
