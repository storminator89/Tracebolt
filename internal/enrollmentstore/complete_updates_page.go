package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/updategeneration"
	"strings"
	"time"
)

func completeUpdatesGenerationStatus(g completeUpdatesGeneration, now time.Time) CompleteUpdatesGenerationStatus {
	state, expiry := g.State, g.Expires
	switch state {
	case "staging":
		state = "pending"
		// The original 15-minute transport lease stays unchanged. A capture
		// whose shorter remaining retention has elapsed is failed and abortable.
		if now.Before(g.Expires) && !now.Before(g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)) {
			state = "failed"
		}
	case "current":
		state = "complete"
		expiry = g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)
	case "retired":
		expiry = g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)
	case "garbage":
		state = "failed"
		if !g.Completed.IsZero() && !now.Before(g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)) {
			state = "expired"
			expiry = g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)
		}
	}
	if state != "failed" && !now.Before(expiry) {
		state = "expired"
	}
	return CompleteUpdatesGenerationStatus{Manifest: g.Manifest, State: state, StartedAt: g.Started, ExpiresAt: expiry, CompletedAt: g.Completed, AcceptedChunks: uint32(g.NextChunk), AcceptedRows: uint64(g.NextRow)}
}
func completeUpdatesStatus(ctx context.Context, t *transaction, snap enrollmentstate.Snapshot, r completeUpdatesRecord, now time.Time) (CompleteUpdatesStatus, error) {
	out := CompleteUpdatesStatus{DeviceID: snap.Approval.DeviceID, ServerNow: now, Sequence: r.Binding.Sequence, Status: "awaiting", boundary: overviewBoundary(now, snap.Intent.NotAfter)}
	if c := r.Complete; c != nil {
		expiry := c.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)
		state := "complete"
		out.Status = "available"
		if !now.Before(expiry) {
			state = "expired"
			out.Status = "unavailable"
		} else {
			out.boundary.limit(expiry, inventoryledger.ErrExpired)
		}
		out.CompleteBinding = c.Binding
		out.Complete = &CompleteUpdatesGenerationStatus{Manifest: c.Manifest, State: state, StartedAt: c.StartedAt, ExpiresAt: expiry, CompletedAt: c.CompletedAt, AcceptedChunks: c.Manifest.ChunkCount, AcceptedRows: uint64(c.Manifest.CandidateCount)}
	}
	if r.Failure != nil {
		out.Failure = &InventoryFailureReceipt{Failure: *r.Failure, ReceivedAt: r.StartedAt}
		if out.Complete == nil {
			out.Status = "unavailable"
		}
	}
	if r.Manifest != nil {
		g, e := loadCompleteUpdatesGeneration(ctx, t, snap.Approval.DeviceID, r.Binding.GenerationID)
		retentionExpired := !now.Before(r.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL))
		missingExpiredComplete := r.State == "complete" && retentionExpired
		missingExpiredPending := r.State == "pending" && (retentionExpired || !now.Before(r.StartedAt.Add(inventoryledger.StagingTTL)))
		if errors.Is(e, inventoryledger.ErrNotFound) && (r.State == "aborted" || missingExpiredComplete || missingExpiredPending) {
			state := "expired"
			expiry := r.StartedAt.Add(inventoryledger.StagingTTL)
			if r.State == "aborted" || r.State == "pending" && now.Before(expiry) {
				state = "failed"
			}
			if r.State == "complete" {
				expiry = r.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)
			}
			out.Transfer = &CompleteUpdatesGenerationStatus{Manifest: *r.Manifest, State: state, StartedAt: r.StartedAt, ExpiresAt: expiry, CompletedAt: r.CompletedAt}
			if r.State == "complete" {
				out.Transfer.AcceptedChunks = r.Manifest.ChunkCount
				out.Transfer.AcceptedRows = uint64(r.Manifest.CandidateCount)
			}
		} else if e != nil {
			return CompleteUpdatesStatus{}, e
		} else {
			status := completeUpdatesGenerationStatus(g, now)
			out.Transfer = &status
		}
	}
	if out.Transfer != nil && (out.Transfer.State == "pending" || out.Transfer.State == "complete") {
		out.boundary.limit(out.Transfer.ExpiresAt, inventoryledger.ErrExpired)
		if out.Transfer.State == "pending" {
			out.boundary.limit(out.Transfer.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL), inventoryledger.ErrExpired)
		}
	}
	return out, nil
}
func (s *Store) CompleteUpdatesStatus(ctx context.Context, id, hash string, b InventoryBinding, now time.Time) (CompleteUpdatesStatus, error) {
	zero := CompleteUpdatesStatus{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	var out CompleteUpdatesStatus
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
		if !b.valid() {
			return enrollmentstate.ErrInvalid
		}
		if r.Binding.Sequence == 0 {
			return inventoryledger.ErrNotFound
		}
		if r.Binding != b {
			return inventoryledger.ErrConflict
		}
		out, e = completeUpdatesStatus(ctx, t, snap, r, now)
		if e != nil {
			return e
		}
		completeUpdatesTouch(&r, now)
		return saveCompleteUpdatesRecord(ctx, t, id, r)
	})
	if e != nil {
		return zero, e
	}
	now, e = overviewNow(ctx, now)
	if e != nil {
		return zero, e
	}
	if e = out.ValidateAt(now); e != nil {
		return zero, e
	}
	out.ServerNow = now
	out.boundary.checkedAt = now
	return out, nil
}
func (s *Store) CompleteUpdatesView(ctx context.Context, device string, now time.Time) (CompleteUpdatesStatus, error) {
	zero := CompleteUpdatesStatus{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	var out CompleteUpdatesStatus
	e = s.transact(ctx, func(t *transaction) error {
		var e error
		now, e = overviewNow(ctx, now)
		if e != nil {
			return e
		}
		snap, r, e := s.completeUpdatesOperator(ctx, t, device, now)
		if e != nil {
			return e
		}
		out, e = completeUpdatesStatus(ctx, t, snap, r, now)
		if e != nil {
			return e
		}
		if r.Binding.Sequence != 0 {
			completeUpdatesTouch(&r, now)
			return saveCompleteUpdatesRecord(ctx, t, snap.InvitationID, r)
		}
		return nil
	})
	if e != nil {
		return zero, e
	}
	now, e = overviewNow(ctx, now)
	if e != nil {
		return zero, e
	}
	if e = out.ValidateAt(now); e != nil {
		return zero, e
	}
	out.ServerNow = now
	out.boundary.checkedAt = now
	return out, nil
}

type completeUpdatesCursor struct {
	Version      int    `json:"v"`
	Device       string `json:"device"`
	Generation   string `json:"generation"`
	ManifestHash string `json:"manifestHash"`
	Search       string `json:"search"`
	Next         int64  `json:"next"`
	Limit        int    `json:"limit"`
	Expires      string `json:"expires"`
}

type completeUpdatesCursorKey [32]byte

func (completeUpdatesCursorKey) String() string               { return "completeUpdatesCursorKey{redacted}" }
func (k completeUpdatesCursorKey) GoString() string           { return k.String() }
func (k completeUpdatesCursorKey) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }
func (completeUpdatesCursorKey) MarshalJSON() ([]byte, error) { return []byte(`"redacted"`), nil }

const completeUpdatesCursorDomain = "tracebolt.complete-cached-apt-updates.cursor.v1\x00"

func signCompleteUpdatesCursor(c completeUpdatesCursor, key completeUpdatesCursorKey) string {
	raw, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(completeUpdatesCursorDomain))
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func readCompleteUpdatesCursor(token string, key completeUpdatesCursorKey, device, search string, limit int, now time.Time) (completeUpdatesCursor, error) {
	zero := completeUpdatesCursor{}
	if len(token) > inventoryledger.MaxCursorBytes {
		return zero, inventoryledger.ErrCursor
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return zero, inventoryledger.ErrCursor
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if e != nil {
		return zero, inventoryledger.ErrCursor
	}
	sig, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil || len(sig) != 32 {
		return zero, inventoryledger.ErrCursor
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(completeUpdatesCursorDomain))
	mac.Write(raw)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return zero, inventoryledger.ErrCursor
	}
	var c completeUpdatesCursor
	if json.Unmarshal(raw, &c) != nil {
		return zero, inventoryledger.ErrCursor
	}
	canonical, _ := json.Marshal(c)
	if !bytes.Equal(raw, canonical) || c.Version != 1 || c.Device != device || c.Search != search || c.Limit != limit || c.Next < 0 || c.Next > updategeneration.MaxGenerationRows || !enrollmentcrypto.ValidID(c.Generation, "sample_") || !enrollmentcrypto.ValidHash(c.ManifestHash) {
		return zero, inventoryledger.ErrCursor
	}
	at, e := completeUpdatesTime(c.Expires)
	if e != nil || at.IsZero() || at.After(now.Add(inventoryledger.CursorTTL)) {
		return zero, inventoryledger.ErrCursor
	}
	if !now.Before(at) {
		return zero, inventoryledger.ErrCursorExpired
	}
	return c, nil
}
func completeUpdatesSearch(s string) (string, error) {
	if len(s) > inventoryledger.MaxSearchBytes {
		return "", inventoryledger.ErrInvalid
	}
	for _, ch := range s {
		if ch < 0x20 || ch > 0x7e {
			return "", inventoryledger.ErrInvalid
		}
	}
	return strings.ToLower(strings.TrimSpace(s)), nil
}
func (s *Store) CompleteUpdatesPage(ctx context.Context, device string, req inventoryledger.PageRequest, now time.Time) (CompleteUpdatesPageResult, error) {
	zero := CompleteUpdatesPageResult{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if req.Limit < 1 || req.Limit > inventoryledger.MaxPageRows || req.GenerationID != "" && !enrollmentcrypto.ValidID(req.GenerationID, "sample_") {
		return zero, inventoryledger.ErrInvalid
	}
	query, e := completeUpdatesSearch(req.Search)
	if e != nil {
		return zero, e
	}
	var out CompleteUpdatesPageResult
	e = s.transact(ctx, func(t *transaction) error {
		var e error
		now, e = overviewNow(ctx, now)
		if e != nil {
			return e
		}
		snap, r, e := s.completeUpdatesOperator(ctx, t, device, now)
		if e != nil {
			return e
		}
		var cursor completeUpdatesCursor
		if req.Cursor != "" {
			cursor, e = readCompleteUpdatesCursor(req.Cursor, t.completeUpdatesKey, device, query, req.Limit, now)
			if e != nil {
				return e
			}
			if req.GenerationID != "" && req.GenerationID != cursor.Generation {
				return inventoryledger.ErrCursor
			}
		} else {
			if r.Complete == nil {
				return inventoryledger.ErrNotFound
			}
			if req.GenerationID != "" && req.GenerationID != r.Complete.Binding.GenerationID {
				return inventoryledger.ErrCursorExpired
			}
			cursor = completeUpdatesCursor{Version: 1, Device: device, Generation: r.Complete.Binding.GenerationID, ManifestHash: r.Complete.Binding.ManifestHash, Search: query, Limit: req.Limit, Expires: completeUpdatesStamp(now.Add(inventoryledger.CursorTTL))}
		}
		g, e := loadCompleteUpdatesGeneration(ctx, t, device, cursor.Generation)
		if errors.Is(e, inventoryledger.ErrNotFound) && req.Cursor != "" {
			return inventoryledger.ErrCursorExpired
		}
		if e != nil {
			return e
		}
		if g.State != "current" && g.State != "retired" || cursor.ManifestHash != g.Binding.ManifestHash {
			return inventoryledger.ErrCursorExpired
		}
		if g.Started.After(now) || g.Completed.After(now) || !now.Before(g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)) {
			return inventoryledger.ErrExpired
		}
		if g.State == "retired" && (now.Before(g.Retired) || !now.Before(g.Retired.Add(inventoryledger.CursorTTL))) {
			return inventoryledger.ErrCursorExpired
		}
		if cursor.Next > g.NextRow {
			return inventoryledger.ErrCursor
		}
		expires, e := completeUpdatesTime(cursor.Expires)
		if e != nil {
			return e
		}
		retention := g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)
		if expires.After(retention) {
			expires = retention
		}
		if g.State == "retired" && expires.After(g.Retired.Add(inventoryledger.CursorTTL)) {
			expires = g.Retired.Add(inventoryledger.CursorTTL)
		}
		cursor.Expires = completeUpdatesStamp(expires)
		out = CompleteUpdatesPageResult{Binding: g.Binding, Manifest: g.Manifest, StartedAt: g.Started, CompletedAt: g.Completed, ServerNow: now, Items: make([]cachedupdates.Candidate, 0, req.Limit), TotalRows: uint64(g.Manifest.CandidateCount), CursorExpiresAt: expires, boundary: overviewBoundary(now, snap.Intent.NotAfter)}
		out.boundary.limit(expires, inventoryledger.ErrCursorExpired)
		rows, e := t.conn.QueryContext(ctx, `SELECT ordinal,body,body_hash FROM enrollment_complete_updates_rows WHERE device=? AND generation=? AND ordinal>=? AND ordinal<? ORDER BY ordinal LIMIT ?`, device, cursor.Generation, cursor.Next, g.NextRow, inventoryledger.MaxScanRows)
		if e != nil {
			return ErrStorage
		}
		var previous *cachedupdates.Candidate
		for rows.Next() {
			var ordinal int64
			var raw []byte
			var digest string
			if rows.Scan(&ordinal, &raw, &digest) != nil || ordinal != cursor.Next || len(raw) == 0 || len(raw) > updategeneration.MaxRowBytes || digest != completeUpdatesBodyHash(raw) {
				rows.Close()
				return ErrStorage
			}
			var row cachedupdates.Candidate
			if json.Unmarshal(raw, &row) != nil || updategeneration.ValidateRow(row) != nil {
				rows.Close()
				return ErrStorage
			}
			canonical, _ := json.Marshal(row)
			if !bytes.Equal(raw, canonical) || previous != nil && (row.Name < previous.Name || row.Name == previous.Name && row.Architecture <= previous.Architecture) {
				rows.Close()
				return ErrStorage
			}
			copy := row
			previous = &copy
			cursor.Next++
			out.ScannedRows++
			if query == "" || strings.Contains(strings.ToLower(strings.Join([]string{row.Name, row.Architecture, row.InstalledVersion, row.CandidateVersion, row.State, row.Installability}, " ")), query) {
				out.Items = append(out.Items, row)
			}
			if len(out.Items) == req.Limit {
				break
			}
		}
		if rows.Err() != nil {
			rows.Close()
			return ErrStorage
		}
		if rows.Close() != nil {
			return ErrStorage
		}
		if cursor.Next < g.NextRow && out.ScannedRows < inventoryledger.MaxScanRows && len(out.Items) < req.Limit {
			return ErrStorage
		}
		out.Exhausted = cursor.Next == g.NextRow
		out.SearchIncomplete = query != "" && !out.Exhausted
		if !out.Exhausted {
			out.NextCursor = signCompleteUpdatesCursor(cursor, t.completeUpdatesKey)
		}
		completeUpdatesTouch(&r, now)
		return saveCompleteUpdatesRecord(ctx, t, snap.InvitationID, r)
	})
	if e != nil {
		return zero, e
	}
	now, e = overviewNow(ctx, now)
	if e != nil {
		return zero, e
	}
	if e = out.ValidateAt(now); e != nil {
		return zero, e
	}
	out.ServerNow = now
	out.boundary.checkedAt = now
	return out, nil
}
