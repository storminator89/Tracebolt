package overviewgeneration

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/completeoverview"
	"sort"
)

// Build accepts an entire valid completed capture and the source operation's
// error. A failed selected section is a separate failure report, never an empty
// generation. A failed sibling does not block the completed selected section.
func Build(ctx context.Context, source completeoverview.Snapshot, section, transferGenerationID string, sourceErr error) (Manifest, []Chunk, error) {
	if !validSection(section) || !validGeneration(transferGenerationID) {
		return Manifest{}, nil, ErrInvalid
	}
	if sourceErr != nil {
		return Manifest{}, nil, ErrSource
	}
	if ctx == nil || ctx.Err() != nil {
		return Manifest{}, nil, ErrCanceled
	}
	if err := completeoverview.Validate(source); err != nil {
		if errors.Is(err, completeoverview.ErrSnapshotLimit) {
			return Manifest{}, nil, ErrLimit
		}
		return Manifest{}, nil, ErrInvalid
	}
	selected := source.Processes.Meta
	if section == "volumes" {
		selected = source.Volumes.Meta
	}
	if selected.Coverage != completeoverview.Complete {
		return Manifest{}, nil, ErrSource
	}
	raw, _ := json.Marshal(source)
	sectionValue := any(source.Processes)
	if section == "volumes" {
		sectionValue = source.Volumes
	}
	sectionRaw, _ := json.Marshal(sectionValue)
	rows := make([]Row, 0, int(*selected.ObservedCount))
	if section == "processes" {
		for i := range source.Processes.Items {
			if ctx.Err() != nil {
				return Manifest{}, nil, ErrCanceled
			}
			rows = append(rows, cloneRow(Row{Process: &source.Processes.Items[i]}))
		}
	} else {
		for i := range source.Volumes.Items {
			if ctx.Err() != nil {
				return Manifest{}, nil, ErrCanceled
			}
			rows = append(rows, cloneRow(Row{Volume: &source.Volumes.Items[i]}))
		}
		sort.Slice(rows, func(i, j int) bool { return rowLess(rows[i], rows[j]) })
	}
	h := newRowsHash()
	boundaries := []int{0}
	start, payloadBytes := 0, 0
	var rowBytes uint64
	for i, r := range rows {
		if ctx.Err() != nil {
			return Manifest{}, nil, ErrCanceled
		}
		if err := ValidateRow(r); err != nil {
			return Manifest{}, nil, err
		}
		b := canonicalRow(r)
		if uint64(len(b)) > MaxCanonicalRowBytes-rowBytes {
			return Manifest{}, nil, ErrLimit
		}
		rowBytes += uint64(len(b))
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
	m := cloneManifest(Manifest{SchemaVersion: SchemaVersion, Scope: source.Scope, GenerationID: transferGenerationID, CaptureGenerationID: source.GenerationID, Section: section, CaptureStartedAt: source.CaptureStartedAt, CaptureFinishedAt: source.CaptureFinishedAt, CollectedAt: source.CaptureStartedAt, Processes: source.Processes.Meta, Volumes: source.Volumes.Meta, ObservedCount: uint64(len(rows)), ChunkCount: uint32(count), CanonicalRowBytes: rowBytes, CanonicalSnapshotBytes: uint64(len(raw)), CanonicalSectionBytes: uint64(len(sectionRaw)), RowsSHA256: hashHex(h)})
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
		c := Chunk{SchemaVersion: SchemaVersion, Section: section, GenerationID: m.GenerationID, ManifestSHA256: md, Ordinal: uint32(i), ChunkCount: uint32(count), RowOffset: uint64(a), PreviousSHA256: previous, Items: rows[a:b:b]}
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
