package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/inventorywire"
	"localrmm/internal/updategeneration"
	"time"
)

func completeUpdatesBodyHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func completeUpdatesTouch(r *completeUpdatesRecord, now time.Time) {
	r.LastAt = now
}
func retirePendingCompleteUpdates(ctx context.Context, t *transaction, device string, r completeUpdatesRecord, now time.Time) error {
	if r.State != "pending" {
		return nil
	}
	if now.Before(r.StartedAt.Add(inventoryledger.StagingTTL)) {
		return inventoryledger.ErrConflict
	}
	if _, e := t.conn.ExecContext(ctx, `UPDATE enrollment_complete_updates_generations SET state='garbage' WHERE device=? AND generation=? AND state='staging'`, device, r.Binding.GenerationID); e != nil {
		return ErrStorage
	}
	return nil
}
func (s *Store) CompleteUpdatesBegin(ctx context.Context, id, hash string, b InventoryBinding, m updategeneration.Manifest, now time.Time) (inventoryledger.BeginReceipt, error) {
	zero := inventoryledger.BeginReceipt{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if !validCompleteUpdatesManifest(b, m) || !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	raw, _ := json.Marshal(m)
	m, e = updategeneration.DecodeManifest(raw)
	if e != nil {
		return zero, enrollmentstate.ErrInvalid
	}
	var out inventoryledger.BeginReceipt
	staleRejected := false
	e = s.transact(ctx, func(t *transaction) error {
		var e error
		now, e = overviewNow(ctx, now)
		if e != nil {
			return e
		}
		snap, r, e := s.completeUpdatesAuthority(ctx, t, id, hash, now)
		if e != nil {
			return e
		}
		want, e := inventorywire.CachedUpdatesGenerationID(snap.Approval.DeviceID, b.Sequence)
		if e != nil || want != b.GenerationID {
			return enrollmentstate.ErrProof
		}
		if r.Binding.Sequence != 0 && b.Sequence <= r.Binding.Sequence {
			if e = matchCompleteUpdates(r, b); e != nil {
				return e
			}
			g, e := loadCompleteUpdatesGeneration(ctx, t, snap.Approval.DeviceID, b.GenerationID)
			if e != nil {
				return e
			}
			if g.State == "garbage" || g.State == "staging" && !now.Before(g.Expires) || !now.Before(g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)) {
				return inventoryledger.ErrExpired
			}
			out = inventoryledger.BeginReceipt{GenerationID: b.GenerationID, StartedAt: g.Started, ExpiresAt: g.Expires}
			completeUpdatesTouch(&r, now)
			return saveCompleteUpdatesRecord(ctx, t, id, r)
		}
		if m.CollectedAt.After(now) {
			return enrollmentstate.ErrInvalid
		}
		if e = retirePendingCompleteUpdates(ctx, t, snap.Approval.DeviceID, r, now); e != nil {
			return e
		}
		expiry := now.Add(inventoryledger.StagingTTL)
		if !validStoreTime(expiry) {
			return enrollmentstate.ErrInvalid
		}
		if !now.Before(m.CollectedAt.Add(inventoryledger.ObservationTTL)) {
			// An immutable Begin may first arrive after a long offline period.
			// Persist only an authenticated terminal receipt so the existing
			// status/abort exchange can retire that local work without resetting
			// its floor or fabricating a new capture time. No payload generation
			// or resource reservation is admitted. The conflict is returned only
			// after COMMIT, so status can reliably resolve this rejected binding.
			r = completeUpdatesRecord{Binding: b, Manifest: &m, State: "aborted", StartedAt: now, LastAt: now, Complete: r.Complete}
			if e = saveCompleteUpdatesRecord(ctx, t, id, r); e != nil {
				return e
			}
			staleRejected = true
			return nil
		}
		if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_complete_updates_generations (`+completeUpdatesGenerationColumns+`) VALUES(?,?,?,?,?,'staging',?,?,'','',?,?,0,0,0,?,?,0,0,'','','')`, snap.Approval.DeviceID, b.GenerationID, b.Sequence, b.ManifestHash, raw, completeUpdatesStamp(now), completeUpdatesStamp(expiry), m.CandidateCount, m.ChunkCount, len(raw), len(raw)); e != nil {
			return ErrStorage
		}
		r = completeUpdatesRecord{Binding: b, Manifest: &m, State: "pending", StartedAt: now, LastAt: now, Complete: r.Complete}
		if e = saveCompleteUpdatesRecord(ctx, t, id, r); e != nil {
			return e
		}
		out = inventoryledger.BeginReceipt{GenerationID: b.GenerationID, StartedAt: now, ExpiresAt: expiry}
		return nil
	})
	if e != nil {
		return zero, e
	}
	if staleRejected {
		return zero, inventoryledger.ErrConflict
	}
	return out, nil
}
func (s *Store) CompleteUpdatesAppend(ctx context.Context, id, hash string, b InventoryBinding, c updategeneration.Chunk, now time.Time) (inventoryledger.ChunkReceipt, error) {
	zero := inventoryledger.ChunkReceipt{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if !b.valid() || c.GenerationID != b.GenerationID || c.ManifestSHA256 != b.ManifestHash || updategeneration.ValidateChunk(c) != nil || !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	raw, _ := json.Marshal(c)
	c, e = updategeneration.DecodeChunk(raw)
	if e != nil {
		return zero, enrollmentstate.ErrInvalid
	}
	var out inventoryledger.ChunkReceipt
	e = s.transact(ctx, func(t *transaction) error {
		var e error
		now, e = overviewNow(ctx, now)
		if e != nil {
			return e
		}
		snap, r, e := s.completeUpdatesAuthority(ctx, t, id, hash, now)
		if e != nil {
			return e
		}
		if e = matchCompleteUpdates(r, b); e != nil {
			return e
		}
		g, e := loadCompleteUpdatesGeneration(ctx, t, snap.Approval.DeviceID, b.GenerationID)
		if e != nil {
			return e
		}
		if g.State == "garbage" || g.State == "staging" && !now.Before(g.Expires) || !now.Before(g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)) {
			return inventoryledger.ErrExpired
		}
		var prior []byte
		var received string
		e = t.conn.QueryRowContext(ctx, `SELECT body,received_at FROM enrollment_complete_updates_chunks WHERE device=? AND generation=? AND ordinal=?`, g.Device, b.GenerationID, c.Ordinal).Scan(&prior, &received)
		if e == nil {
			if !bytes.Equal(prior, raw) {
				return inventoryledger.ErrConflict
			}
			at, e := completeUpdatesTime(received)
			if e != nil || at.Before(g.Started) || at.After(now) {
				return ErrStorage
			}
			out = inventoryledger.ChunkReceipt{GenerationID: b.GenerationID, Ordinal: c.Ordinal, Rows: len(c.Items), ReceivedAt: at}
			completeUpdatesTouch(&r, now)
			return saveCompleteUpdatesRecord(ctx, t, id, r)
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return ErrStorage
		}
		if g.State != "staging" || r.State != "pending" || int64(c.Ordinal) != g.NextChunk || int64(c.RowOffset) != g.NextRow || c.ChunkCount != g.Manifest.ChunkCount || c.PreviousSHA256 != g.LastHash || g.NextRow+int64(len(c.Items)) > int64(g.Manifest.CandidateCount) {
			return inventoryledger.ErrConflict
		}
		first := c.Items[0]
		if g.NextRow > 0 && (first.Name < g.LastName || first.Name == g.LastName && first.Architecture <= g.LastArch) {
			return inventoryledger.ErrConflict
		}
		rowBytes := int64(0)
		rowBodies := make([][]byte, len(c.Items))
		for i, row := range c.Items {
			rowBodies[i], _ = json.Marshal(row)
			rowBytes += int64(len(rowBodies[i]) + 1)
		}
		stored := int64(len(raw)) + rowBytes - int64(len(c.Items))
		if g.RowBytes+rowBytes > int64(g.Manifest.CanonicalRowBytes) || g.WireBytes+int64(len(raw)) > updategeneration.MaxCanonicalWireBytes {
			return inventoryledger.ErrConflict
		}
		if g.StoredBytes+stored > inventoryLimits().GenerationBytes {
			return inventoryledger.ErrQuota
		}
		if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_complete_updates_chunks VALUES(?,?,?,?,?)`, g.Device, b.GenerationID, c.Ordinal, raw, completeUpdatesStamp(now)); e != nil {
			return ErrStorage
		}
		stmt, e := t.conn.PrepareContext(ctx, `INSERT INTO enrollment_complete_updates_rows VALUES(?,?,?,?,?)`)
		if e != nil {
			return ErrStorage
		}
		for i, raw := range rowBodies {
			if _, e = stmt.ExecContext(ctx, g.Device, b.GenerationID, g.NextRow+int64(i), raw, completeUpdatesBodyHash(raw)); e != nil {
				stmt.Close()
				return ErrStorage
			}
		}
		if stmt.Close() != nil {
			return ErrStorage
		}
		last := c.Items[len(c.Items)-1]
		if _, e = t.conn.ExecContext(ctx, `UPDATE enrollment_complete_updates_generations SET next_row=next_row+?,next_chunk=next_chunk+1,row_bytes=row_bytes+?,wire_bytes=wire_bytes+?,stored_bytes=stored_bytes+?,live_rows=live_rows+?,live_chunks=live_chunks+1,last_hash=?,last_name=?,last_arch=? WHERE device=? AND generation=?`, len(c.Items), rowBytes, len(raw), stored, len(c.Items), c.SHA256, last.Name, last.Architecture, g.Device, b.GenerationID); e != nil {
			return ErrStorage
		}
		completeUpdatesTouch(&r, now)
		if e = saveCompleteUpdatesRecord(ctx, t, id, r); e != nil {
			return e
		}
		out = inventoryledger.ChunkReceipt{GenerationID: b.GenerationID, Ordinal: c.Ordinal, Rows: len(c.Items), ReceivedAt: now}
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
func (s *Store) CompleteUpdatesFinalize(ctx context.Context, id, hash string, b InventoryBinding, now time.Time) (CompleteUpdatesCompletion, error) {
	zero := CompleteUpdatesCompletion{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	var out CompleteUpdatesCompletion
	e = s.transact(ctx, func(t *transaction) error {
		var e error
		now, e = overviewNow(ctx, now)
		if e != nil {
			return e
		}
		snap, r, e := s.completeUpdatesAuthority(ctx, t, id, hash, now)
		if e != nil {
			return e
		}
		if e = matchCompleteUpdates(r, b); e != nil {
			return e
		}
		// A lost acknowledgement must remain recoverable after row retention or
		// physical cleanup. Only the exact latest, already-committed binding may
		// replay this authority-owned receipt. Authentication and revocation were
		// checked above; no expired rows are read or recreated here.
		if r.State == "complete" && r.Complete != nil && r.Complete.Binding == b {
			out = CompleteUpdatesCompletion{Manifest: r.Complete.Manifest, StartedAt: r.Complete.StartedAt, CompletedAt: r.Complete.CompletedAt}
			completeUpdatesTouch(&r, now)
			return saveCompleteUpdatesRecord(ctx, t, id, r)
		}
		g, e := loadCompleteUpdatesGeneration(ctx, t, snap.Approval.DeviceID, b.GenerationID)
		if e != nil {
			return e
		}
		if g.State == "garbage" || g.State == "staging" && !now.Before(g.Expires) || !now.Before(g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)) {
			return inventoryledger.ErrExpired
		}
		if g.State != "staging" || g.NextRow != int64(g.Manifest.CandidateCount) || g.NextChunk != int64(g.Manifest.ChunkCount) {
			return inventoryledger.ErrIncomplete
		}
		// Check exact retained payload accounting at completion, never during
		// routine authority restoration. Extra/missing normalized rows or chunks
		// cannot turn matching header counters into a complete receipt.
		var rowsCount, chunksCount, rowsBytes, chunksBytes int64
		if t.conn.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(length(body)),0) FROM enrollment_complete_updates_rows WHERE device=? AND generation=?`, g.Device, b.GenerationID).Scan(&rowsCount, &rowsBytes) != nil || t.conn.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(length(body)),0) FROM enrollment_complete_updates_chunks WHERE device=? AND generation=?`, g.Device, b.GenerationID).Scan(&chunksCount, &chunksBytes) != nil {
			return ErrStorage
		}
		manifestRaw, _ := json.Marshal(g.Manifest)
		if rowsCount != g.NextRow || chunksCount != g.NextChunk || rowsBytes+rowsCount != g.RowBytes || chunksBytes+int64(len(manifestRaw)) != g.WireBytes || rowsBytes+chunksBytes+int64(len(manifestRaw)) != g.StoredBytes {
			return ErrStorage
		}
		// Stream each bounded stored chunk through the strict adapter. A full exact
		// Finish receipt is mandatory; no completion is inferred from row counts.
		v, e := updategeneration.NewValidator(ctx, g.Manifest)
		if e != nil {
			return ErrStorage
		}
		lastReceived := g.Started
		for ordinal := int64(0); ordinal < g.NextChunk; ordinal++ {
			var raw []byte
			var received string
			if t.conn.QueryRowContext(ctx, `SELECT body,received_at FROM enrollment_complete_updates_chunks WHERE device=? AND generation=? AND ordinal=?`, g.Device, b.GenerationID, ordinal).Scan(&raw, &received) != nil {
				return ErrStorage
			}
			c, e := updategeneration.DecodeChunk(raw)
			canonical, _ := json.Marshal(c)
			if e != nil || !bytes.Equal(raw, canonical) || v.Add(c) != nil {
				return ErrStorage
			}
			at, e := completeUpdatesTime(received)
			if e != nil || at.Before(lastReceived) || at.After(now) || !at.Before(g.Expires) {
				return ErrStorage
			}
			lastReceived = at
			rows, e := t.conn.QueryContext(ctx, `SELECT ordinal,body,body_hash FROM enrollment_complete_updates_rows WHERE device=? AND generation=? AND ordinal>=? AND ordinal<? ORDER BY ordinal`, g.Device, b.GenerationID, c.RowOffset, c.RowOffset+uint64(len(c.Items)))
			if e != nil {
				return ErrStorage
			}
			count := 0
			for rows.Next() {
				var i uint64
				var rb []byte
				var digest string
				if rows.Scan(&i, &rb, &digest) != nil || count >= len(c.Items) || i != c.RowOffset+uint64(count) {
					rows.Close()
					return ErrStorage
				}
				want, _ := json.Marshal(c.Items[count])
				if !bytes.Equal(rb, want) || digest != completeUpdatesBodyHash(rb) {
					rows.Close()
					return ErrStorage
				}
				count++
			}
			if rows.Err() != nil {
				rows.Close()
				return ErrStorage
			}
			if rows.Close() != nil || count != len(c.Items) {
				return ErrStorage
			}
		}
		proof, e := v.Finish()
		if e != nil || !proof.Valid() || proof.ManifestSHA256() != b.ManifestHash || int64(proof.CanonicalWireBytes()) != g.WireBytes || proof.LastChunkSHA256() != g.LastHash {
			return inventoryledger.ErrIncomplete
		}
		// Validation can stream a large bounded generation. Sample trusted time
		// again before promotion so that work crossing a lease/retention boundary
		// cannot commit with an obsolete action timestamp.
		now, e = overviewNow(ctx, now)
		if e != nil {
			return e
		}
		if _, _, e = s.completeUpdatesAuthority(ctx, t, id, hash, now); e != nil {
			return e
		}
		if !now.Before(g.Expires) || !now.Before(g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)) {
			return inventoryledger.ErrExpired
		}
		if r.Complete != nil {
			if _, e = t.conn.ExecContext(ctx, `UPDATE enrollment_complete_updates_generations SET state='retired',retired_at=? WHERE device=? AND generation=? AND state='current'`, completeUpdatesStamp(now), g.Device, r.Complete.Binding.GenerationID); e != nil {
				return ErrStorage
			}
		}
		if _, e = t.conn.ExecContext(ctx, `UPDATE enrollment_complete_updates_generations SET state='current',completed_at=? WHERE device=? AND generation=? AND state='staging'`, completeUpdatesStamp(now), g.Device, b.GenerationID); e != nil {
			return ErrStorage
		}
		r.State = "complete"
		r.CompletedAt = now
		r.Complete = &completeUpdatesRetained{Binding: b, Manifest: g.Manifest, StartedAt: g.Started, CompletedAt: now}
		completeUpdatesTouch(&r, now)
		if e = saveCompleteUpdatesRecord(ctx, t, id, r); e != nil {
			return e
		}
		out = CompleteUpdatesCompletion{Manifest: g.Manifest, StartedAt: g.Started, CompletedAt: now}
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
func (s *Store) CompleteUpdatesAbort(ctx context.Context, id, hash string, b InventoryBinding, now time.Time) error {
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	return s.transact(ctx, func(t *transaction) error {
		var e error
		now, e = overviewNow(ctx, now)
		if e != nil {
			return e
		}
		snap, r, e := s.completeUpdatesAuthority(ctx, t, id, hash, now)
		if e != nil {
			return e
		}
		if !b.valid() {
			return enrollmentstate.ErrInvalid
		}
		if r.Binding.Sequence == 0 {
			return inventoryledger.ErrNotFound
		}
		if r.Binding != b || r.State != "pending" && r.State != "aborted" {
			return inventoryledger.ErrConflict
		}
		if _, e = t.conn.ExecContext(ctx, `UPDATE enrollment_complete_updates_generations SET state='garbage' WHERE device=? AND generation=? AND state='staging'`, snap.Approval.DeviceID, b.GenerationID); e != nil {
			return ErrStorage
		}
		r.State = "aborted"
		completeUpdatesTouch(&r, now)
		return saveCompleteUpdatesRecord(ctx, t, id, r)
	})
}
func (s *Store) CompleteUpdatesFailure(ctx context.Context, id, hash string, f InventoryFailureReport, now time.Time) (InventoryFailureReceipt, error) {
	zero := InventoryFailureReceipt{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if !validCompleteUpdatesFailure(f) || !validStoreTime(now) || f.AttemptedAt.After(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	var out InventoryFailureReceipt
	e = s.transact(ctx, func(t *transaction) error {
		var e error
		now, e = overviewNow(ctx, now)
		if e != nil {
			return e
		}
		snap, r, e := s.completeUpdatesAuthority(ctx, t, id, hash, now)
		if e != nil {
			return e
		}
		want, e := inventorywire.CachedUpdatesGenerationID(snap.Approval.DeviceID, f.Sequence)
		if e != nil || want != f.GenerationID {
			return enrollmentstate.ErrProof
		}
		if f.Sequence <= r.Binding.Sequence {
			if r.State != "source_failed" || r.Failure == nil || *r.Failure != f {
				return inventoryledger.ErrConflict
			}
			out = InventoryFailureReceipt{Failure: *r.Failure, ReceivedAt: r.StartedAt}
			completeUpdatesTouch(&r, now)
			return saveCompleteUpdatesRecord(ctx, t, id, r)
		}
		if e = retirePendingCompleteUpdates(ctx, t, snap.Approval.DeviceID, r, now); e != nil {
			return e
		}
		r = completeUpdatesRecord{Binding: InventoryBinding{Sequence: f.Sequence, GenerationID: f.GenerationID}, Failure: &f, State: "source_failed", StartedAt: now, LastAt: now, Complete: r.Complete}
		if e = saveCompleteUpdatesRecord(ctx, t, id, r); e != nil {
			return e
		}
		out = InventoryFailureReceipt{Failure: f, ReceivedAt: now}
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
