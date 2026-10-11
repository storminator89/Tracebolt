package windowsusersoftwareledger

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/windowsusersoftware"
	"time"
)

type Generation struct {
	Manifest                      windowsusersoftware.Manifest
	Hash, State, LastRegistration string
	StartedAt, CompletedAt        time.Time
	NextChunk, NextRow            int
	Reserved, Stored              int64
}

func LoadGeneration(ctx context.Context, tx Transaction, device, id string) (Generation, error) {
	var g Generation
	var raw []byte
	var started, completed string
	e := tx.QueryRowContext(ctx, `SELECT state,manifest,manifest_hash,started_at,completed_at,next_chunk,next_row,last_registration,reserved_bytes,stored_bytes FROM wus_generations WHERE device=? AND generation=?`, device, id).Scan(&g.State, &raw, &g.Hash, &started, &completed, &g.NextChunk, &g.NextRow, &g.LastRegistration, &g.Reserved, &g.Stored)
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
	digest, e := windowsusersoftware.ManifestDigest(g.Manifest)
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
func Receipt(m windowsusersoftware.Message, raw []byte, now time.Time) windowsusersoftware.Receipt {
	status := "accepted"
	if m.Operation == "chunk" && m.Index == m.Manifest.ChunkCount-1 {
		status = "complete"
	}
	return windowsusersoftware.Receipt{SchemaVersion: windowsusersoftware.ReceiptVersion, Operation: m.Operation, DeviceID: m.DeviceID, GrantID: m.Consent.GrantID, GrantRevision: m.Consent.Revision, Sequence: m.Sequence, RequestSHA256: windowsusersoftware.Hash(raw), Index: m.Index, Status: status, ReceivedAt: now}
}
func MarkGarbage(ctx context.Context, tx Transaction, device, id string) error {
	if id == "" {
		return nil
	}
	if _, e := tx.ExecContext(ctx, `UPDATE wus_generations SET state='garbage' WHERE device=? AND generation=?`, device, id); e != nil {
		return ErrStorage
	}
	return nil
}

// Apply receives previously authenticated, canonical messages. Reservations,
// receipts and normalized rows remain provisional until the caller commits.
func Apply(ctx context.Context, tx Transaction, m windowsusersoftware.Message, raw []byte, r *Record, now time.Time, extraBytes int64) (windowsusersoftware.Receipt, error) {
	zero := windowsusersoftware.Receipt{}
	if m.Operation == "scope" {
		if r.Consent.Revision != 0 {
			if m.Consent.Revision < r.Consent.Revision {
				return zero, windowsusersoftware.ErrConflict
			}
			if m.Consent.Revision == r.Consent.Revision {
				if !bytes.Equal(raw, r.ScopeRaw) {
					return zero, windowsusersoftware.ErrConflict
				}
				return r.ScopeReceipt, nil
			}
			if m.Consent.SenderBinding != r.Consent.SenderBinding || m.Consent.ChangedAt.Before(r.Consent.ChangedAt) || m.Consent.Enabled && m.Consent.GrantID == r.Consent.GrantID {
				return zero, windowsusersoftware.ErrConflict
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
		return zero, windowsusersoftware.ErrConflict
	}
	if m.Operation == "failure" {
		if m.AttemptedAt.After(now) || !now.Before(m.AttemptedAt.Add(windowsusersoftware.Retention)) {
			return zero, windowsusersoftware.ErrExpired
		}
		if m.Sequence <= r.Floor {
			if m.Sequence == r.Floor && r.FailureReceipt != nil && bytes.Equal(raw, r.FailureRaw) {
				return *r.FailureReceipt, nil
			}
			return zero, windowsusersoftware.ErrConflict
		}
		if r.Pending != "" {
			if e := MarkGarbage(ctx, tx, m.DeviceID, r.Pending); e != nil {
				return zero, e
			}
		}
		receipt := Receipt(m, raw, now)
		r.Floor = m.Sequence
		r.Pending = ""
		r.Latest = &windowsusersoftware.Attempt{AccountContextID: m.AccountContextID, AccountLabel: m.AccountLabel, CaptureNonce: m.CaptureNonce, Sequence: m.Sequence, AttemptedAt: *m.AttemptedAt, Status: "source_failed", Reason: m.Reason}
		r.FailureRaw = bytes.Clone(raw)
		r.FailureReceipt = &receipt
		r.LastAt = now
		return receipt, nil
	}
	manifest := m.Manifest
	if manifest.CaptureFinishedAt.After(now) || !now.Before(manifest.ExpiresAt) {
		return zero, windowsusersoftware.ErrExpired
	}
	g, e := LoadGeneration(ctx, tx, m.DeviceID, manifest.GenerationID)
	if errors.Is(e, ErrNotFound) {
		if m.Sequence <= r.Floor || m.Index != 0 {
			return zero, windowsusersoftware.ErrConflict
		}
		if r.Pending != "" {
			old, er := LoadGeneration(ctx, tx, m.DeviceID, r.Pending)
			if er != nil {
				return zero, er
			}
			if now.Before(old.StartedAt.Add(StagingTTL)) {
				return zero, windowsusersoftware.ErrConflict
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
			return zero, windowsusersoftware.ErrBudget
		}
		if e = Reserve(ctx, tx, m.DeviceID, reserved, manifest.RowCount, manifest.ChunkCount, extraBytes); e != nil {
			return zero, e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO wus_generations VALUES(?,?,'staging',?,?,?,'',0,0,'',?,?,?,?)`, m.DeviceID, manifest.GenerationID, body, m.ManifestSHA256, now.Format(time.RFC3339Nano), reserved, len(body), manifest.RowCount, manifest.ChunkCount); e != nil {
			return zero, ErrStorage
		}
		if e = Budgets(ctx, tx, 0); e != nil {
			return zero, e
		}
		g = Generation{Manifest: *manifest, Hash: m.ManifestSHA256, State: "staging", StartedAt: now, Reserved: reserved, Stored: int64(len(body))}
		r.Floor = m.Sequence
		r.Pending = manifest.GenerationID
		r.Latest = &windowsusersoftware.Attempt{AccountContextID: manifest.AccountContextID, AccountLabel: manifest.AccountLabel, CaptureNonce: manifest.CaptureNonce, Sequence: m.Sequence, AttemptedAt: manifest.CaptureStartedAt, Status: "pending"}
		r.FailureRaw = nil
		r.FailureReceipt = nil
	} else if e != nil {
		return zero, e
	}
	if g.Hash != m.ManifestSHA256 || g.Manifest.Sequence != m.Sequence || g.Manifest.GrantID != r.Consent.GrantID || g.Manifest.GrantRevision != r.Consent.Revision {
		return zero, windowsusersoftware.ErrConflict
	}
	if g.State == "garbage" {
		return zero, windowsusersoftware.ErrConflict
	}
	if g.State == "staging" && !now.Before(g.StartedAt.Add(StagingTTL)) {
		return zero, windowsusersoftware.ErrExpired
	}
	if m.Index < g.NextChunk {
		var old, receiptRaw []byte
		if tx.QueryRowContext(ctx, `SELECT body,receipt FROM wus_chunks WHERE device=? AND generation=? AND ordinal=?`, m.DeviceID, manifest.GenerationID, m.Index).Scan(&old, &receiptRaw) != nil {
			return zero, ErrStorage
		}
		if !bytes.Equal(raw, old) {
			return zero, windowsusersoftware.ErrConflict
		}
		receipt, e := windowsusersoftware.DecodeReceipt(receiptRaw, old)
		if e != nil {
			return zero, ErrStorage
		}
		return receipt, nil
	}
	if g.State != "staging" || r.Pending != manifest.GenerationID || m.Sequence != r.Floor || m.Index != g.NextChunk || m.Offset != g.NextRow {
		return zero, windowsusersoftware.ErrConflict
	}
	if len(m.Rows) > 0 && g.LastRegistration != "" && m.Rows[0].RegistrationID <= g.LastRegistration {
		return zero, windowsusersoftware.ErrConflict
	}
	receipt := Receipt(m, raw, now)
	receiptRaw, _ := json.Marshal(receipt)
	stored := g.Stored + int64(len(raw)+len(receiptRaw))
	for i, row := range m.Rows {
		body, _ := json.Marshal(row)
		search := SearchText(row)
		stored += int64(len(body) + len(row.RegistrationID) + len(row.Source) + len(search))
		for _, value := range []*string{row.Name, row.Version, row.Publisher} {
			if value != nil {
				stored += int64(len(*value))
			}
		}
		if stored > g.Reserved {
			return zero, windowsusersoftware.ErrBudget
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO wus_rows VALUES(?,?,?,?,?,?,?,?,?,?)`, m.DeviceID, manifest.GenerationID, m.Offset+i, body, row.RegistrationID, row.Source, row.Name, row.Version, row.Publisher, search); e != nil {
			return zero, ErrStorage
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO wus_chunks VALUES(?,?,?,?,?)`, m.DeviceID, manifest.GenerationID, m.Index, raw, receiptRaw); e != nil {
		return zero, ErrStorage
	}
	g.NextChunk++
	g.NextRow += len(m.Rows)
	if len(m.Rows) > 0 {
		g.LastRegistration = m.Rows[len(m.Rows)-1].RegistrationID
	}
	if _, e = tx.ExecContext(ctx, `UPDATE wus_generations SET next_chunk=?,next_row=?,last_registration=?,stored_bytes=? WHERE device=? AND generation=?`, g.NextChunk, g.NextRow, g.LastRegistration, stored, m.DeviceID, manifest.GenerationID); e != nil {
		return zero, ErrStorage
	}
	if g.NextChunk == manifest.ChunkCount {
		if g.NextRow != manifest.RowCount {
			return zero, windowsusersoftware.ErrConflict
		}
		all, e := ReadRows(ctx, tx, m.DeviceID, manifest.GenerationID)
		if e != nil {
			return zero, e
		}
		digest, size, e := windowsusersoftware.RowsDigest(all)
		if e != nil || digest != manifest.RowsSHA256 || size != manifest.RowsBytes || len(all) != manifest.RowCount {
			return zero, windowsusersoftware.ErrConflict
		}
		if e = MarkGarbage(ctx, tx, m.DeviceID, r.Current); e != nil {
			return zero, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE wus_generations SET state='current',completed_at=? WHERE device=? AND generation=?`, now.Format(time.RFC3339Nano), m.DeviceID, manifest.GenerationID); e != nil {
			return zero, ErrStorage
		}
		r.Current = manifest.GenerationID
		r.Pending = ""
		r.Latest = &windowsusersoftware.Attempt{AccountContextID: manifest.AccountContextID, AccountLabel: manifest.AccountLabel, CaptureNonce: manifest.CaptureNonce, Sequence: m.Sequence, AttemptedAt: manifest.CaptureStartedAt, Status: "complete"}
	}
	r.LastAt = now
	return receipt, nil
}
func SearchText(r windowsusersoftware.Row) string {
	text := ""
	for _, value := range []*string{r.Name, r.Version, r.Publisher} {
		if value != nil {
			text += *value
		}
		text += "\n"
	}
	return windowsusersoftware.IdentityKey(text + r.Source)
}
func sameText(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func ReadRows(ctx context.Context, tx Transaction, device, generation string) ([]windowsusersoftware.Row, error) {
	rr, e := tx.QueryContext(ctx, `SELECT ordinal,body FROM wus_rows WHERE device=? AND generation=? ORDER BY ordinal LIMIT 4097`, device, generation)
	if e != nil {
		return nil, ErrStorage
	}
	defer rr.Close()
	out := make([]windowsusersoftware.Row, 0)
	total := 2
	for rr.Next() {
		var ordinal int
		var raw []byte
		var row windowsusersoftware.Row
		if rr.Scan(&ordinal, &raw) != nil || ordinal != len(out) || len(out) >= windowsusersoftware.MaxRows || json.Unmarshal(raw, &row) != nil || windowsusersoftware.ValidateRow(row) != nil {
			return nil, ErrStorage
		}
		canonical, _ := json.Marshal(row)
		if !bytes.Equal(canonical, raw) {
			return nil, ErrStorage
		}
		total += len(raw) + 1
		if total > windowsusersoftware.MaxSourceBytes+1 {
			return nil, ErrStorage
		}
		out = append(out, row)
	}
	if rr.Err() != nil {
		return nil, ErrStorage
	}
	return out, nil
}
