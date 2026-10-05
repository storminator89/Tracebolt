package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"time"
)

// Reclaim at most one bounded batch, preserving the independent authority floor
// and original complete metadata. Revocation never grants row access, and does
// not strand expired or abandoned reservations in the shared database budget.
func (s *Store) maintainCompleteUpdates(ctx context.Context, t *transaction, device string, now time.Time) (InventoryMaintenanceResult, error) {
	out := InventoryMaintenanceResult{DeviceID: device, Section: "cached_updates"}
	if !t.completeUpdatesEnabled {
		return out, nil
	}
	var snap enrollmentstate.Snapshot
	found := false
	for _, candidate := range t.engine.Snapshots() {
		if candidate.Approval.DeviceID == device {
			snap = candidate
			found = true
			break
		}
	}
	if !found {
		return out, enrollmentstate.ErrNotFound
	}
	if !completeProfile(snap.Binding.CollectionProfile) || snap.Platform != "linux" || snap.Activation.At == 0 || !enrollmentcrypto.ValidHash(snap.Issuance.CertificateHash) {
		return out, enrollmentstate.ErrProof
	}
	if _, ok := t.credentials[snap.InvitationID]; !ok {
		return out, ErrStorage
	}
	r, e := readCompleteUpdatesRecord(ctx, t, snap.InvitationID)
	if errors.Is(e, inventoryledger.ErrNotFound) {
		return out, nil
	}
	if e != nil {
		return out, e
	}
	if !validStoreTime(now) || now.Unix() < snap.UpdatedAt || now.Unix() < snap.Intent.NotBefore || now.Before(r.LastAt) || r.MaintenanceAt != nil && now.Before(*r.MaintenanceAt) {
		return out, enrollmentstate.ErrInvalid
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT `+completeUpdatesGenerationColumns+` FROM enrollment_complete_updates_generations WHERE device=? ORDER BY started_at,generation LIMIT ?`, device, inventoryLimits().DeviceGenerations)
	if e != nil {
		return out, ErrStorage
	}
	var selected *completeUpdatesGeneration
	for rows.Next() {
		g, e := scanCompleteUpdatesGeneration(rows)
		if e != nil {
			rows.Close()
			return out, e
		}
		eligible := g.State == "garbage" || !now.Before(g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)) || g.State == "staging" && !now.Before(g.Expires) || g.State == "retired" && !now.Before(g.Retired.Add(inventoryledger.CursorTTL))
		if eligible {
			selected = &g
			break
		}
	}
	if rows.Err() != nil {
		rows.Close()
		return out, ErrStorage
	}
	if rows.Close() != nil {
		return out, ErrStorage
	}
	if selected == nil {
		return out, nil
	}
	g := *selected
	if _, e = t.conn.ExecContext(ctx, `UPDATE enrollment_complete_updates_generations SET state='garbage' WHERE device=? AND generation=?`, device, g.Binding.GenerationID); e != nil {
		return out, ErrStorage
	}
	// Fixed identifiers only. Counts and byte sums cover just the indexed bounded
	// delete windows; no full row/chunk scan or materialization is needed.
	var freed int64
	for _, batch := range []struct {
		table string
		limit int
		rows  bool
	}{{"enrollment_complete_updates_rows", 256, true}, {"enrollment_complete_updates_chunks", 16, false}} {
		var n int
		var size int64
		if t.conn.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(length(body)),0) FROM (SELECT body FROM `+batch.table+` WHERE device=? AND generation=? ORDER BY ordinal LIMIT ?)`, device, g.Binding.GenerationID, batch.limit).Scan(&n, &size) != nil {
			return out, ErrStorage
		}
		if _, e = t.conn.ExecContext(ctx, `DELETE FROM `+batch.table+` WHERE device=? AND generation=? AND ordinal IN (SELECT ordinal FROM `+batch.table+` WHERE device=? AND generation=? ORDER BY ordinal LIMIT ?)`, device, g.Binding.GenerationID, device, g.Binding.GenerationID, batch.limit); e != nil {
			return out, ErrStorage
		}
		if batch.rows {
			out.RowsDeleted = n
		} else {
			out.ChunksDeleted = n
		}
		freed += size
	}
	if int64(out.RowsDeleted) > g.LiveRows || int64(out.ChunksDeleted) > g.LiveChunks || freed >= g.StoredBytes {
		return out, ErrStorage
	}
	remainingRows, remainingChunks := g.LiveRows-int64(out.RowsDeleted), g.LiveChunks-int64(out.ChunksDeleted)
	if remainingRows == 0 && remainingChunks == 0 {
		if _, e = t.conn.ExecContext(ctx, `DELETE FROM enrollment_complete_updates_generations WHERE device=? AND generation=?`, device, g.Binding.GenerationID); e != nil {
			return out, ErrStorage
		}
		out.GenerationRemoved = true
	} else {
		if _, e = t.conn.ExecContext(ctx, `UPDATE enrollment_complete_updates_generations SET live_rows=?,live_chunks=?,stored_bytes=stored_bytes-? WHERE device=? AND generation=?`, remainingRows, remainingChunks, freed, device, g.Binding.GenerationID); e != nil {
			return out, ErrStorage
		}
	}
	r.MaintenanceAt = &now
	if e = saveCompleteUpdatesRecord(ctx, t, snap.InvitationID, r); e != nil {
		return out, e
	}
	return out, nil
}
