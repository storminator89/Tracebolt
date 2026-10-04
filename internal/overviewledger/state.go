package overviewledger

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/overviewgeneration"
	"time"
)

type generation struct {
	device, id, state                                                          string
	manifestRaw, checkpoint                                                    []byte
	manifest                                                                   overviewgeneration.Manifest
	started, expires, completed, retired                                       time.Time
	nextChunk, nextRow, wireBytes, rowBytes, storedBytes, liveRows, liveChunks int64
}

func validDevice(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}
func validGeneration(s string) bool {
	if len(s) != 39 || s[:7] != "sample_" {
		return false
	}
	for _, c := range s[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1970 && t.Year() <= 9999
}
func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339Nano)
}
func parseStamp(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil || !validTime(t) || stamp(t) != s {
		return time.Time{}, ErrStorage
	}
	return t, nil
}
func loadGeneration(ctx context.Context, tx Transaction, device, id string) (generation, error) {
	var g generation
	var started, expires, completed, retired string
	var declaredRows, declaredChunks int64
	err := tx.QueryRowContext(ctx, `SELECT state,manifest,checkpoint,started_at,expires_at,completed_at,retired_at,next_chunk,next_row,wire_bytes,row_bytes,stored_bytes,live_rows,live_chunks,declared_rows,declared_chunks FROM co_generations WHERE device=? AND generation=?`, device, id).Scan(
		&g.state, &g.manifestRaw, &g.checkpoint, &started, &expires, &completed, &retired, &g.nextChunk, &g.nextRow, &g.wireBytes, &g.rowBytes, &g.storedBytes, &g.liveRows, &g.liveChunks, &declaredRows, &declaredChunks)
	if errors.Is(err, sql.ErrNoRows) {
		return generation{}, ErrNotFound
	}
	if err != nil {
		return generation{}, ErrStorage
	}
	g.device, g.id = device, id
	if len(g.manifestRaw) > overviewgeneration.MaxManifestBytes || len(g.checkpoint) > overviewgeneration.MaxCheckpointBytes {
		return generation{}, ErrStorage
	}
	m, e := overviewgeneration.DecodeManifest(g.manifestRaw)
	if e != nil || m.GenerationID != id || int64(m.ObservedCount) != declaredRows || int64(m.ChunkCount) != declaredChunks {
		return generation{}, ErrStorage
	}
	g.manifest = m
	canonical, _ := json.Marshal(m)
	if string(canonical) != string(g.manifestRaw) {
		return generation{}, ErrStorage
	}
	g.started, e = parseStamp(started)
	if e != nil || g.started.IsZero() {
		return generation{}, ErrStorage
	}
	g.expires, e = parseStamp(expires)
	if e != nil || !g.expires.Equal(g.started.Add(StagingTTL)) {
		return generation{}, ErrStorage
	}
	g.completed, e = parseStamp(completed)
	if e != nil {
		return generation{}, ErrStorage
	}
	g.retired, e = parseStamp(retired)
	if e != nil {
		return generation{}, ErrStorage
	}
	if g.manifest.CaptureFinishedAt.After(g.started) || !g.completed.IsZero() && g.completed.Before(g.started) || !g.retired.IsZero() && (g.completed.IsZero() || g.retired.Before(g.completed)) {
		return generation{}, ErrStorage
	}
	if g.nextChunk < 0 || g.nextChunk > int64(m.ChunkCount) || g.nextRow < 0 || g.nextRow > int64(m.ObservedCount) || g.wireBytes < 0 || g.wireBytes > overviewgeneration.MaxCanonicalWireBytes || g.rowBytes < 0 || g.rowBytes > int64(m.CanonicalRowBytes) || g.storedBytes < int64(len(g.manifestRaw)+len(g.checkpoint)) || g.liveRows < 0 || g.liveRows > g.nextRow || g.liveChunks < 0 || g.liveChunks > g.nextChunk {
		return generation{}, ErrStorage
	}
	switch g.state {
	case "staging":
		if !g.completed.IsZero() || !g.retired.IsZero() || g.liveRows != g.nextRow || g.liveChunks != g.nextChunk {
			return generation{}, ErrStorage
		}
	case "current":
		if g.completed.IsZero() || !g.retired.IsZero() {
			return generation{}, ErrStorage
		}
	case "retired":
		if g.completed.IsZero() || g.retired.IsZero() {
			return generation{}, ErrStorage
		}
	case "garbage":
	default:
		return generation{}, ErrStorage
	}
	if (g.state == "current" || g.state == "retired") && (g.nextRow != int64(m.ObservedCount) || g.nextChunk != int64(m.ChunkCount) || g.rowBytes != int64(m.CanonicalRowBytes)) {
		return generation{}, ErrStorage
	}
	return g, nil
}

type budget struct{ rows, chunks, bytes, generations int64 }

func readBudget(ctx context.Context, tx Transaction, scope string) (budget, error) {
	var b budget
	if tx.QueryRowContext(ctx, `SELECT held_rows,held_chunks,stored_bytes,generations FROM co_budget WHERE scope=?`, scope).Scan(&b.rows, &b.chunks, &b.bytes, &b.generations) != nil {
		return budget{}, ErrStorage
	}
	if b.rows < 0 || b.chunks < 0 || b.bytes < 0 || b.generations < 0 {
		return budget{}, ErrStorage
	}
	return b, nil
}
func (l *Ledger) adjust(ctx context.Context, tx Transaction, device string, delta budget) error {
	for _, scope := range []string{"", device} {
		b, e := readBudget(ctx, tx, scope)
		if e != nil {
			return e
		}
		b.rows += delta.rows
		b.chunks += delta.chunks
		b.bytes += delta.bytes
		b.generations += delta.generations
		if b.rows < 0 || b.chunks < 0 || b.bytes < 0 || b.generations < 0 {
			return ErrStorage
		}
		cap := budget{l.limits.DeviceRows, l.limits.DeviceChunks, l.limits.DeviceBytes, l.limits.DeviceGenerations}
		if scope == "" {
			cap = budget{l.limits.GlobalRows, l.limits.GlobalChunks, l.limits.GlobalBytes, l.limits.GlobalGenerations}
		}
		if b.rows > cap.rows || b.chunks > cap.chunks || b.bytes > cap.bytes || b.generations > cap.generations {
			return ErrQuota
		}
		if _, e = tx.ExecContext(ctx, `UPDATE co_budget SET held_rows=?,held_chunks=?,stored_bytes=?,generations=? WHERE scope=?`, b.rows, b.chunks, b.bytes, b.generations, scope); e != nil {
			return ErrStorage
		}
	}
	return nil
}

// checkReceiptClock rejects manager clock reversal relative to the latest accepted
// chunk without loading a generation or refreshing any persisted receipt.
func checkReceiptClock(ctx context.Context, tx Transaction, g generation, now time.Time) error {
	if g.nextChunk == 0 {
		return nil
	}
	var text string
	if tx.QueryRowContext(ctx, `SELECT received_at FROM co_chunks WHERE device=? AND generation=? AND ordinal=?`, g.device, g.id, g.nextChunk-1).Scan(&text) != nil {
		return ErrStorage
	}
	at, err := parseStamp(text)
	if err != nil || at.IsZero() || at.Before(g.started) {
		return ErrStorage
	}
	if now.Before(at) {
		return ErrExpired
	}
	if !g.completed.IsZero() && at.After(g.completed) {
		return ErrStorage
	}
	return nil
}
