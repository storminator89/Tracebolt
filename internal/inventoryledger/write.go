package inventoryledger

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/fullinventory"
	"time"
)

type BeginReceipt struct {
	GenerationID         string
	StartedAt, ExpiresAt time.Time
}
type ChunkReceipt struct {
	GenerationID string
	Ordinal      uint32
	Rows         int
	ReceivedAt   time.Time
}
type Completion struct {
	Manifest               fullinventory.Manifest
	StartedAt, CompletedAt time.Time
}

// Begin reserves all declared rows/chunks, but only bytes actually stored. An
// interrupted or quota-rejected stage cannot replace the old complete inventory.
// now is trusted manager time. Identical retries never refresh the stage TTL.
func (l *Ledger) Begin(ctx context.Context, tx Transaction, device string, m fullinventory.Manifest, now time.Time) (BeginReceipt, error) {
	zero := BeginReceipt{}
	if err := l.check(ctx, tx); err != nil {
		return zero, err
	}
	if !validDevice(device) || !validTime(now) || fullinventory.ValidateManifest(m) != nil || m.CollectedAt.After(now) {
		return zero, ErrInvalid
	}
	raw, _ := json.Marshal(m)
	g, e := loadGeneration(ctx, tx, device, m.GenerationID)
	if e == nil {
		if !bytes.Equal(g.manifestRaw, raw) {
			return zero, ErrConflict
		}
		if g.state == "garbage" || now.Before(g.started) || (g.state == "staging" && !now.Before(g.expires)) {
			return zero, ErrExpired
		}
		return BeginReceipt{g.id, g.started, g.expires}, nil
	}
	if !errors.Is(e, ErrNotFound) {
		return zero, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO fi_devices(device,current_generation,staging_generation) VALUES(?,'','') ON CONFLICT(device) DO NOTHING`, device); e != nil {
		return zero, ErrStorage
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO fi_budget VALUES(?,0,0,0,0) ON CONFLICT(scope) DO NOTHING`, device); e != nil {
		return zero, ErrStorage
	}
	var staged string
	if tx.QueryRowContext(ctx, `SELECT staging_generation FROM fi_devices WHERE device=?`, device).Scan(&staged) != nil {
		return zero, ErrStorage
	}
	if staged != "" {
		return zero, ErrConflict
	}
	validator, e := fullinventory.NewValidator(ctx, m)
	if e != nil {
		return zero, ErrInvalid
	}
	checkpoint, e := validator.Checkpoint()
	if e != nil || len(checkpoint) > fullinventory.MaxCheckpointBytes {
		return zero, ErrStorage
	}
	stored := int64(len(raw) + len(checkpoint))
	if stored > l.limits.GenerationBytes {
		return zero, ErrQuota
	}
	if e = l.adjust(ctx, tx, device, budget{int64(m.ObservedCount), int64(m.ChunkCount), stored, 1}); e != nil {
		return zero, e
	}
	expires := now.Add(StagingTTL)
	if !validTime(expires) {
		return zero, ErrInvalid
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO fi_generations VALUES(?,?, 'staging',?,?,?,?, '', '',0,0,?,0,?,0,0)`, device, m.GenerationID, raw, checkpoint, stamp(now), stamp(expires), len(raw), stored); e != nil {
		return zero, ErrStorage
	}
	if _, e = tx.ExecContext(ctx, `UPDATE fi_devices SET staging_generation=? WHERE device=?`, m.GenerationID, device); e != nil {
		return zero, ErrStorage
	}
	return BeginReceipt{m.GenerationID, now, expires}, nil
}

// Append admits only the next chunk or an exact canonical retry. A retry returns
// its original receipt, changes no counters, and cannot refresh any timestamp.
func (l *Ledger) Append(ctx context.Context, tx Transaction, device string, c fullinventory.Chunk, now time.Time) (ChunkReceipt, error) {
	zero := ChunkReceipt{}
	if e := l.check(ctx, tx); e != nil {
		return zero, e
	}
	if !validDevice(device) || !validTime(now) || fullinventory.ValidateChunk(c) != nil {
		return zero, ErrInvalid
	}
	g, e := loadGeneration(ctx, tx, device, c.GenerationID)
	if e != nil {
		return zero, e
	}
	if now.Before(g.started) || g.state == "garbage" || (g.state == "staging" && !now.Before(g.expires)) {
		return zero, ErrExpired
	}
	raw, _ := json.Marshal(c)
	var old []byte
	var received string
	e = tx.QueryRowContext(ctx, `SELECT body,received_at FROM fi_chunks WHERE device=? AND generation=? AND ordinal=?`, device, c.GenerationID, c.Ordinal).Scan(&old, &received)
	if e == nil {
		if !bytes.Equal(old, raw) {
			return zero, ErrConflict
		}
		at, e := parseStamp(received)
		if e != nil || at.IsZero() || at.Before(g.started) || at.After(now) {
			return zero, ErrStorage
		}
		return ChunkReceipt{c.GenerationID, c.Ordinal, len(c.Items), at}, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return zero, ErrStorage
	}
	if g.state != "staging" {
		return zero, ErrConflict
	}
	if int64(c.Ordinal) != g.nextChunk {
		return zero, ErrConflict
	}
	if e = checkReceiptClock(ctx, tx, g, now); e != nil {
		return zero, e
	}
	validator, e := restore(ctx, g)
	if e != nil {
		return zero, e
	}
	if e = validator.Add(c); e != nil {
		return zero, ErrInvalid
	}
	checkpoint, e := validator.Checkpoint()
	if e != nil || len(checkpoint) > fullinventory.MaxCheckpointBytes {
		return zero, ErrStorage
	}
	rowBodies := make([][]byte, len(c.Items))
	var rowBytes int64
	for i, p := range c.Items {
		rowBodies[i], _ = json.Marshal(p)
		rowBytes += int64(len(rowBodies[i]))
	}
	delta := int64(len(raw)+len(checkpoint)-len(g.checkpoint)) + rowBytes
	if delta < 0 || g.storedBytes+delta > l.limits.GenerationBytes {
		return zero, ErrQuota
	}
	if e = l.adjust(ctx, tx, device, budget{bytes: delta}); e != nil {
		return zero, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO fi_chunks VALUES(?,?,?,?,?)`, device, g.id, c.Ordinal, raw, stamp(now)); e != nil {
		return zero, ErrStorage
	}
	for i, body := range rowBodies {
		if _, e = tx.ExecContext(ctx, `INSERT INTO fi_rows VALUES(?,?,?,?)`, device, g.id, g.nextRow+int64(i), body); e != nil {
			return zero, ErrStorage
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE fi_generations SET checkpoint=?,next_chunk=next_chunk+1,next_row=next_row+?,wire_bytes=wire_bytes+?,row_bytes=row_bytes+?,stored_bytes=stored_bytes+?,live_rows=live_rows+?,live_chunks=live_chunks+1 WHERE device=? AND generation=?`, checkpoint, len(c.Items), len(raw), rowBytes+int64(len(c.Items)), delta, len(c.Items), device, g.id); e != nil {
		return zero, ErrStorage
	}
	return ChunkReceipt{g.id, c.Ordinal, len(c.Items), now}, nil
}

func restore(ctx context.Context, g generation) (*fullinventory.Validator, error) {
	validator, e := fullinventory.RestoreValidatorFromTrustedCheckpoint(ctx, g.manifest, g.checkpoint)
	if e != nil {
		return nil, ErrStorage
	}
	p, e := validator.Progress()
	if e != nil {
		return nil, ErrStorage
	}
	if int64(p.AcceptedChunks) != g.nextChunk || int64(p.ObservedCount) != g.nextRow || int64(p.CanonicalRowBytes) != g.rowBytes || int64(p.CanonicalWireBytes) != g.wireBytes {
		return nil, ErrStorage
	}
	return validator, nil
}

// Promote performs a bounded pointer transition only after streaming completion
// validation. It never deletes rows or frees retained-generation reservations.
// Existing complete inventory remains current if this call or COMMIT fails.
func (l *Ledger) Promote(ctx context.Context, tx Transaction, device, id string, now time.Time) (Completion, error) {
	zero := Completion{}
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
	if now.Before(g.started) || g.state == "garbage" || (g.state == "staging" && !now.Before(g.expires)) {
		return zero, ErrExpired
	}
	if g.state == "current" || g.state == "retired" {
		if now.Before(g.completed) {
			return zero, ErrExpired
		}
		return Completion{g.manifest, g.started, g.completed}, nil
	}
	if e = checkReceiptClock(ctx, tx, g, now); e != nil {
		return zero, e
	}
	validator, e := restore(ctx, g)
	if e != nil {
		return zero, e
	}
	complete, e := validator.Finish()
	if e != nil || !complete.Valid() {
		return zero, ErrIncomplete
	}
	var current, staged string
	if tx.QueryRowContext(ctx, `SELECT current_generation,staging_generation FROM fi_devices WHERE device=?`, device).Scan(&current, &staged) != nil || staged != id {
		return zero, ErrStorage
	}
	if current != "" {
		result, e := tx.ExecContext(ctx, `UPDATE fi_generations SET state='retired',retired_at=? WHERE device=? AND generation=? AND state='current'`, stamp(now), device, current)
		if e != nil {
			return zero, ErrStorage
		}
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			return zero, ErrStorage
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE fi_generations SET state='current',completed_at=? WHERE device=? AND generation=?`, stamp(now), device, id); e != nil {
		return zero, ErrStorage
	}
	if _, e = tx.ExecContext(ctx, `UPDATE fi_devices SET current_generation=?,staging_generation='' WHERE device=?`, id, device); e != nil {
		return zero, ErrStorage
	}
	return Completion{complete.Manifest(), g.started, now}, nil
}
