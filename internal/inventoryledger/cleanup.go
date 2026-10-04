package inventoryledger

import (
	"context"
	"time"
)

type CleanupResult struct {
	RowsDeleted, ChunksDeleted int
	BytesReleased              int64
	Done                       bool
}

// Abandon marks only the matching staging generation. It releases no reservation
// or byte budget until Cleanup actually deletes the retained records. Current
// inventory is never abandoned here; lifecycle/revocation authorization belongs
// to the caller's authority transaction, not a flag supplied by a network client.
func (l *Ledger) Abandon(ctx context.Context, tx Transaction, device, id string, now time.Time) error {
	if e := l.check(ctx, tx); e != nil {
		return e
	}
	if !validDevice(device) || !validGeneration(id) || !validTime(now) {
		return ErrInvalid
	}
	g, e := loadGeneration(ctx, tx, device, id)
	if e != nil {
		return e
	}
	if now.Before(g.started) {
		return ErrInvalid
	}
	if g.state == "garbage" {
		return nil
	}
	if g.state != "staging" {
		return ErrConflict
	}
	return markGarbage(ctx, tx, g)
}
func markGarbage(ctx context.Context, tx Transaction, g generation) error {
	var current, staged string
	if tx.QueryRowContext(ctx, `SELECT current_generation,staging_generation FROM fi_devices WHERE device=?`, g.device).Scan(&current, &staged) != nil {
		return ErrStorage
	}
	if current == g.id || g.state == "current" {
		return ErrConflict
	}
	if g.state == "staging" && staged != g.id {
		return ErrStorage
	}
	if staged == g.id {
		if _, e := tx.ExecContext(ctx, `UPDATE fi_devices SET staging_generation='' WHERE device=?`, g.device); e != nil {
			return ErrStorage
		}
	}
	if _, e := tx.ExecContext(ctx, `UPDATE fi_generations SET state='garbage' WHERE device=? AND generation=?`, g.device, g.id); e != nil {
		return ErrStorage
	}
	return nil
}

// Cleanup deletes at most 256 indexed page rows and 16 chunk BLOBs. It may clean
// abandoned stages, expired stages, or retired generations past cursor retention.
// It NEVER deletes a current generation, even after observation expiry. A caller
// must continue until Done to release declared row/chunk reservations. No cascade,
// VACUUM, full table scan or whole-generation materialization occurs here.
func (l *Ledger) Cleanup(ctx context.Context, tx Transaction, device, id string, now time.Time) (CleanupResult, error) {
	zero := CleanupResult{}
	if e := l.check(ctx, tx); e != nil {
		return zero, e
	}
	if !validDevice(device) || !validGeneration(id) || !validTime(now) {
		return zero, ErrInvalid
	}
	g, e := loadGeneration(ctx, tx, device, id)
	if e != nil {
		return zero, e
	}
	if now.Before(g.started) {
		return zero, ErrInvalid
	}
	switch g.state {
	case "garbage":
	case "staging":
		if now.Before(g.expires) {
			return zero, ErrConflict
		}
	case "retired":
		if now.Before(g.retired.Add(CursorTTL)) {
			return zero, ErrConflict
		}
	default:
		return zero, ErrConflict
	}
	if e = markGarbage(ctx, tx, g); e != nil {
		return zero, e
	}
	rowCount, rowBytes, e := deleteBatch(ctx, tx, "fi_rows", device, id, MaxCleanupRows)
	if e != nil {
		return zero, e
	}
	chunkCount, chunkBytes, e := deleteBatch(ctx, tx, "fi_chunks", device, id, MaxCleanupChunks)
	if e != nil {
		return zero, e
	}
	released := rowBytes + chunkBytes
	if int64(rowCount) > g.liveRows || int64(chunkCount) > g.liveChunks || released > g.storedBytes {
		return zero, ErrStorage
	}
	remainRows, remainChunks := g.liveRows-int64(rowCount), g.liveChunks-int64(chunkCount)
	if remainRows == 0 && remainChunks == 0 {
		// Only metadata/checkpoint remains; all declared reservations are now safe to
		// release together with that exact retained metadata byte count.
		if g.storedBytes-released != int64(len(g.manifestRaw)+len(g.checkpoint)) {
			return zero, ErrStorage
		}
		if e = l.adjust(ctx, tx, device, budget{-int64(g.manifest.ObservedCount), -int64(g.manifest.ChunkCount), -g.storedBytes, -1}); e != nil {
			return zero, e
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM fi_generations WHERE device=? AND generation=?`, device, id); e != nil {
			return zero, ErrStorage
		}
		b, e := readBudget(ctx, tx, device)
		if e != nil {
			return zero, e
		}
		if b.generations == 0 {
			if b.rows != 0 || b.chunks != 0 || b.bytes != 0 {
				return zero, ErrStorage
			}
			var current, staged string
			if tx.QueryRowContext(ctx, `SELECT current_generation,staging_generation FROM fi_devices WHERE device=?`, device).Scan(&current, &staged) != nil || current != "" || staged != "" {
				return zero, ErrStorage
			}
			if _, e = tx.ExecContext(ctx, `DELETE FROM fi_devices WHERE device=?`, device); e != nil {
				return zero, ErrStorage
			}
			if _, e = tx.ExecContext(ctx, `DELETE FROM fi_budget WHERE scope=?`, device); e != nil {
				return zero, ErrStorage
			}
		}
		return CleanupResult{rowCount, chunkCount, g.storedBytes, true}, nil
	}
	if rowCount == 0 && remainRows > 0 || chunkCount == 0 && remainChunks > 0 {
		return zero, ErrStorage
	}
	if e = l.adjust(ctx, tx, device, budget{bytes: -released}); e != nil {
		return zero, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE fi_generations SET live_rows=?,live_chunks=?,stored_bytes=stored_bytes-? WHERE device=? AND generation=?`, remainRows, remainChunks, released, device, id); e != nil {
		return zero, ErrStorage
	}
	return CleanupResult{rowCount, chunkCount, released, false}, nil
}

func deleteBatch(ctx context.Context, tx Transaction, table, device, id string, limit int) (int, int64, error) {
	// table is an internal constant, never a caller-provided SQL identifier.
	rows, e := tx.QueryContext(ctx, `SELECT ordinal,length(body) FROM `+table+` WHERE device=? AND generation=? ORDER BY ordinal LIMIT ?`, device, id, limit)
	if e != nil {
		return 0, 0, ErrStorage
	}
	count := 0
	var total, last int64
	for rows.Next() {
		var ordinal, size int64
		if rows.Scan(&ordinal, &size) != nil || size < 1 || count > 0 && ordinal <= last {
			rows.Close()
			return 0, 0, ErrStorage
		}
		last = ordinal
		total += size
		count++
	}
	if rows.Err() != nil {
		rows.Close()
		return 0, 0, ErrStorage
	}
	if rows.Close() != nil {
		return 0, 0, ErrStorage
	}
	if count == 0 {
		return 0, 0, nil
	}
	result, e := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE device=? AND generation=? AND ordinal<=?`, device, id, last)
	if e != nil {
		return 0, 0, ErrStorage
	}
	n, e := result.RowsAffected()
	if e != nil || n != int64(count) {
		return 0, 0, ErrStorage
	}
	return count, total, nil
}
