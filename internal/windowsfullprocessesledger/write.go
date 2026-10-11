package windowsfullprocessesledger

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/windowsfullprocesses"
	"strconv"
	"time"
)

type Generation struct {
	Manifest               windowsfullprocesses.Manifest
	Hash, State            string
	LastPID                uint32
	StartedAt, CompletedAt time.Time
	NextChunk, NextRow     int
	Reserved, Stored       int64
}

func LoadGeneration(ctx context.Context, tx Transaction, device, id string) (Generation, error) {
	var g Generation
	var raw []byte
	var started, completed string
	e := tx.QueryRowContext(ctx, `SELECT state,manifest,manifest_hash,started_at,completed_at,next_chunk,next_row,last_pid,reserved_bytes,stored_bytes FROM wfp_generations WHERE device=? AND generation=?`, device, id).Scan(&g.State, &raw, &g.Hash, &started, &completed, &g.NextChunk, &g.NextRow, &g.LastPID, &g.Reserved, &g.Stored)
	if errors.Is(e, sql.ErrNoRows) {
		return g, ErrNotFound
	}
	if e != nil {
		return g, ErrStorage
	}
	if json.Unmarshal(raw, &g.Manifest) != nil {
		return g, ErrStorage
	}
	canonical, _ := json.Marshal(g.Manifest)
	digest, e := windowsfullprocesses.ManifestDigest(g.Manifest)
	if e != nil || !bytes.Equal(raw, canonical) || digest != g.Hash || g.Manifest.DeviceID != device || g.Manifest.GenerationID != id {
		return g, ErrStorage
	}
	g.StartedAt, e = time.Parse(time.RFC3339Nano, started)
	if e != nil {
		return g, ErrStorage
	}
	if completed != "" {
		g.CompletedAt, e = time.Parse(time.RFC3339Nano, completed)
		if e != nil {
			return g, ErrStorage
		}
	}
	if g.NextChunk > g.Manifest.ChunkCount || g.NextRow > g.Manifest.RowCount || g.Stored > g.Reserved {
		return g, ErrStorage
	}
	return g, nil
}
func Receipt(m windowsfullprocesses.Message, raw []byte, now time.Time) windowsfullprocesses.Receipt {
	status := "accepted"
	if m.Operation == "chunk" && m.Index == m.Manifest.ChunkCount-1 {
		status = "complete"
	}
	return windowsfullprocesses.Receipt{SchemaVersion: windowsfullprocesses.ReceiptVersion, Operation: m.Operation, DeviceID: m.DeviceID, GrantID: m.Consent.GrantID, GrantRevision: m.Consent.Revision, Sequence: m.Sequence, RequestSHA256: windowsfullprocesses.Hash(raw), Index: m.Index, Status: status, ReceivedAt: now}
}
func MarkGarbage(ctx context.Context, tx Transaction, device, id string) error {
	if id == "" {
		return nil
	}
	if _, e := tx.ExecContext(ctx, `UPDATE wfp_generations SET state='garbage' WHERE device=? AND generation=?`, device, id); e != nil {
		return ErrStorage
	}
	return nil
}

// Apply receives previously authenticated, canonical messages. Reservations,
// receipts and normalized rows remain provisional until the caller commits.
func Apply(ctx context.Context, tx Transaction, m windowsfullprocesses.Message, raw []byte, r *Record, now time.Time, extraBytes int64) (windowsfullprocesses.Receipt, error) {
	zero := windowsfullprocesses.Receipt{}
	if m.Operation == "scope" {
		if r.Consent.Revision != 0 {
			if m.Consent.Revision < r.Consent.Revision {
				return zero, windowsfullprocesses.ErrConflict
			}
			if m.Consent.Revision == r.Consent.Revision {
				if !bytes.Equal(raw, r.ScopeRaw) {
					return zero, windowsfullprocesses.ErrConflict
				}
				return r.ScopeReceipt, nil
			}
			if m.Consent.SenderBinding != r.Consent.SenderBinding || m.Consent.ChangedAt.Before(r.Consent.ChangedAt) || m.Consent.Enabled && m.Consent.GrantID == r.Consent.GrantID {
				return zero, windowsfullprocesses.ErrConflict
			}
		}
		if e := MarkGarbage(ctx, tx, m.DeviceID, r.Current); e != nil {
			return zero, e
		}
		if e := MarkGarbage(ctx, tx, m.DeviceID, r.Pending); e != nil {
			return zero, e
		}
		r.Consent = m.Consent
		r.ScopeRaw = bytes.Clone(raw)
		r.ScopeReceipt = Receipt(m, raw, now)
		r.Current = ""
		r.Pending = ""
		r.Latest = nil
		r.FailureRaw = nil
		r.FailureReceipt = nil
		r.LastAt = now
		return r.ScopeReceipt, nil
	}
	if m.Consent != r.Consent || !r.Consent.Enabled {
		return zero, windowsfullprocesses.ErrConflict
	}
	if m.Operation == "failure" {
		if m.AttemptedAt.After(now) || !now.Before(m.AttemptedAt.Add(windowsfullprocesses.Retention)) {
			return zero, windowsfullprocesses.ErrExpired
		}
		if m.Sequence <= r.Floor {
			if m.Sequence == r.Floor && r.FailureReceipt != nil && bytes.Equal(raw, r.FailureRaw) {
				return *r.FailureReceipt, nil
			}
			return zero, windowsfullprocesses.ErrConflict
		}
		if r.Pending != "" {
			if e := MarkGarbage(ctx, tx, m.DeviceID, r.Pending); e != nil {
				return zero, e
			}
		}
		receipt := Receipt(m, raw, now)
		r.Floor = m.Sequence
		r.Pending = ""
		r.Latest = &windowsfullprocesses.Attempt{Sequence: m.Sequence, AttemptedAt: *m.AttemptedAt, Status: "source_failed", Reason: m.Reason}
		r.FailureRaw = bytes.Clone(raw)
		r.FailureReceipt = &receipt
		r.LastAt = now
		return receipt, nil
	}
	manifest := m.Manifest
	if manifest.CaptureFinishedAt.After(now) || !now.Before(manifest.ExpiresAt) {
		return zero, windowsfullprocesses.ErrExpired
	}
	g, e := LoadGeneration(ctx, tx, m.DeviceID, manifest.GenerationID)
	if errors.Is(e, ErrNotFound) {
		if m.Sequence <= r.Floor || m.Index != 0 {
			return zero, windowsfullprocesses.ErrConflict
		}
		if r.Pending != "" {
			old, er := LoadGeneration(ctx, tx, m.DeviceID, r.Pending)
			if er != nil {
				return zero, er
			}
			if now.Before(old.StartedAt.Add(StagingTTL)) {
				return zero, windowsfullprocesses.ErrConflict
			}
			if er = MarkGarbage(ctx, tx, m.DeviceID, r.Pending); er != nil {
				return zero, er
			}
		}
		body, _ := json.Marshal(manifest)
		// Four canonical row copies cover chunk bodies, normalized row bodies and
		// search and optional text columns; envelope/receipt overhead is independently reserved.
		reserved := int64(manifest.RowsBytes)*4 + int64(manifest.ChunkCount)*(int64(len(body))+4096) + 16384
		if reserved > MaxDeviceBytes {
			return zero, windowsfullprocesses.ErrBudget
		}
		if e = Reserve(ctx, tx, m.DeviceID, reserved, manifest.RowCount, manifest.ChunkCount, extraBytes); e != nil {
			return zero, e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO wfp_generations VALUES(?,?,'staging',?,?,?,'',0,0,0,?,?,?,?)`, m.DeviceID, manifest.GenerationID, body, m.ManifestSHA256, now.Format(time.RFC3339Nano), reserved, len(body), manifest.RowCount, manifest.ChunkCount); e != nil {
			return zero, ErrStorage
		}
		if e = Budgets(ctx, tx, 0); e != nil {
			return zero, e
		}
		g = Generation{Manifest: *manifest, Hash: m.ManifestSHA256, State: "staging", StartedAt: now, Reserved: reserved, Stored: int64(len(body))}
		r.Floor = m.Sequence
		r.Pending = manifest.GenerationID
		r.Latest = &windowsfullprocesses.Attempt{Sequence: m.Sequence, AttemptedAt: manifest.CaptureStartedAt, Status: "pending"}
		r.FailureRaw = nil
		r.FailureReceipt = nil
	} else if e != nil {
		return zero, e
	}
	if g.Hash != m.ManifestSHA256 || g.Manifest.Sequence != m.Sequence || g.Manifest.GrantID != r.Consent.GrantID || g.Manifest.GrantRevision != r.Consent.Revision {
		return zero, windowsfullprocesses.ErrConflict
	}
	if g.State == "garbage" {
		return zero, windowsfullprocesses.ErrConflict
	}
	if g.State == "staging" && !now.Before(g.StartedAt.Add(StagingTTL)) {
		return zero, windowsfullprocesses.ErrExpired
	}
	if m.Index < g.NextChunk {
		var old, receiptRaw []byte
		if tx.QueryRowContext(ctx, `SELECT body,receipt FROM wfp_chunks WHERE device=? AND generation=? AND ordinal=?`, m.DeviceID, manifest.GenerationID, m.Index).Scan(&old, &receiptRaw) != nil {
			return zero, ErrStorage
		}
		if !bytes.Equal(raw, old) {
			return zero, windowsfullprocesses.ErrConflict
		}
		receipt, e := windowsfullprocesses.DecodeReceipt(receiptRaw, old)
		if e != nil {
			return zero, ErrStorage
		}
		return receipt, nil
	}
	if g.State != "staging" || r.Pending != manifest.GenerationID || m.Sequence != r.Floor || m.Index != g.NextChunk || m.Offset != g.NextRow {
		return zero, windowsfullprocesses.ErrConflict
	}
	if len(m.Rows) > 0 && g.NextRow > 0 && m.Rows[0].PID <= g.LastPID {
		return zero, windowsfullprocesses.ErrConflict
	}
	receipt := Receipt(m, raw, now)
	receiptRaw, _ := json.Marshal(receipt)
	stored := g.Stored + int64(len(raw)+len(receiptRaw))
	for i, row := range m.Rows {
		body, _ := json.Marshal(row)
		search := SearchText(row)
		stored += int64(len(body) + 12 + len(search))
		if row.Name != nil {
			stored += int64(len(*row.Name))
		}
		if stored > g.Reserved {
			return zero, windowsfullprocesses.ErrBudget
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO wfp_rows VALUES(?,?,?,?,?,?,?,?,?)`, m.DeviceID, manifest.GenerationID, m.Offset+i, body, row.PID, row.ParentPID, row.Name, row.Threads, search); e != nil {
			return zero, ErrStorage
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO wfp_chunks VALUES(?,?,?,?,?)`, m.DeviceID, manifest.GenerationID, m.Index, raw, receiptRaw); e != nil {
		return zero, ErrStorage
	}
	g.NextChunk++
	g.NextRow += len(m.Rows)
	if len(m.Rows) > 0 {
		g.LastPID = m.Rows[len(m.Rows)-1].PID
	}
	if _, e = tx.ExecContext(ctx, `UPDATE wfp_generations SET next_chunk=?,next_row=?,last_pid=?,stored_bytes=? WHERE device=? AND generation=?`, g.NextChunk, g.NextRow, g.LastPID, stored, m.DeviceID, manifest.GenerationID); e != nil {
		return zero, ErrStorage
	}
	if g.NextChunk == manifest.ChunkCount {
		if g.NextRow != manifest.RowCount {
			return zero, windowsfullprocesses.ErrConflict
		}
		all, e := ReadRows(ctx, tx, m.DeviceID, manifest.GenerationID)
		if e != nil {
			return zero, e
		}
		digest, size, e := windowsfullprocesses.RowsDigest(all)
		if e != nil || digest != manifest.RowsSHA256 || size != manifest.RowsBytes || len(all) != manifest.RowCount {
			return zero, windowsfullprocesses.ErrConflict
		}
		if e = MarkGarbage(ctx, tx, m.DeviceID, r.Current); e != nil {
			return zero, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE wfp_generations SET state='current',completed_at=? WHERE device=? AND generation=?`, now.Format(time.RFC3339Nano), m.DeviceID, manifest.GenerationID); e != nil {
			return zero, ErrStorage
		}
		r.Current = manifest.GenerationID
		r.Pending = ""
		r.Latest = &windowsfullprocesses.Attempt{Sequence: m.Sequence, AttemptedAt: manifest.CaptureStartedAt, Status: "complete"}
	}
	r.LastAt = now
	return receipt, nil
}
func SearchText(r windowsfullprocesses.Row) string {
	text := ""
	if r.Name != nil {
		text = *r.Name
	}
	return windowsfullprocesses.IdentityKey(text + "\n" + strconv.FormatUint(uint64(r.PID), 10) + "\n" + strconv.FormatUint(uint64(r.ParentPID), 10) + "\n" + strconv.FormatUint(uint64(r.Threads), 10))
}
func sameText(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func ReadRows(ctx context.Context, tx Transaction, device, generation string) ([]windowsfullprocesses.Row, error) {
	rr, e := tx.QueryContext(ctx, `SELECT ordinal,body FROM wfp_rows WHERE device=? AND generation=? ORDER BY ordinal LIMIT 32769`, device, generation)
	if e != nil {
		return nil, ErrStorage
	}
	defer rr.Close()
	out := make([]windowsfullprocesses.Row, 0)
	total := 2
	for rr.Next() {
		var ordinal int
		var raw []byte
		var row windowsfullprocesses.Row
		if rr.Scan(&ordinal, &raw) != nil || ordinal != len(out) || len(out) >= windowsfullprocesses.MaxRows || json.Unmarshal(raw, &row) != nil || windowsfullprocesses.ValidateRow(row) != nil {
			return nil, ErrStorage
		}
		canonical, _ := json.Marshal(row)
		if !bytes.Equal(canonical, raw) {
			return nil, ErrStorage
		}
		total += len(raw) + 1
		if total > windowsfullprocesses.MaxSourceBytes+1 {
			return nil, ErrStorage
		}
		out = append(out, row)
	}
	if rr.Err() != nil {
		return nil, ErrStorage
	}
	return out, nil
}
