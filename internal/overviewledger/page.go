package overviewledger

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/overviewgeneration"
	"strings"
	"time"
)

type PageRequest struct {
	Section string
	Limit   int
	Search  string
	Cursor  string
	// Optional generation assertion, required to match a supplied cursor. Without
	// a cursor only the current generation may be selected.
	GenerationID string
}

// PageResult is provisional until the authority transaction commits. TotalRows
// is the full immutable inventory size, NOT the count of search matches. An empty
// Items with !Exhausted is a scan continuation, never proof of no search matches.
type PageResult struct {
	Section                string
	Manifest               overviewgeneration.Manifest
	StartedAt, CompletedAt time.Time
	Items                  []overviewgeneration.Row
	TotalRows              uint64
	ScannedRows            int
	Exhausted              bool
	SearchIncomplete       bool
	NextCursor             string
	CursorExpiresAt        time.Time
}

// Page reads at most MaxScanRows indexed rows, returns at most Limit matches,
// and advances its generation-pinned cursor past every scanned row. There is no
// total-prefix cap: callers can scan the entire complete generation. It performs
// no total-match COUNT or unbounded LIKE query and does not materialize chunks.
func (l *Ledger) Page(ctx context.Context, tx Transaction, device string, req PageRequest, now time.Time, key CursorKey) (PageResult, error) {
	zero := PageResult{}
	if e := l.check(ctx, tx); e != nil {
		return zero, e
	}
	if (req.Section != "processes" && req.Section != "volumes") || !validDevice(device) || !validTime(now) || req.Limit < 1 || req.Limit > MaxPageRows || key.state == nil || key.state.value == [32]byte{} || req.GenerationID != "" && !validGeneration(req.GenerationID) {
		return zero, ErrInvalid
	}
	query, e := normalizeSearch(req.Search)
	if e != nil {
		return zero, e
	}
	var c cursor
	if req.Cursor != "" {
		c, e = readCursor(req.Cursor, key, device, req.Section, query, req.Limit, now)
		if e != nil {
			return zero, e
		}
		if req.GenerationID != "" && req.GenerationID != c.Generation {
			return zero, ErrCursor
		}
	} else {
		var id string
		e = tx.QueryRowContext(ctx, `SELECT current_generation FROM co_devices WHERE device=?`, device).Scan(&id)
		if errors.Is(e, sql.ErrNoRows) || e == nil && id == "" {
			return zero, ErrNotFound
		}
		if e != nil {
			return zero, ErrStorage
		}
		if req.GenerationID != "" && req.GenerationID != id {
			return zero, ErrCursorExpired
		}
		c = cursor{Version: 1, Device: device, Generation: id, Section: req.Section, Search: query, Limit: req.Limit, After: -1, Expires: stamp(now.Add(CursorTTL))}
	}
	g, e := loadGeneration(ctx, tx, device, c.Generation)
	if errors.Is(e, ErrNotFound) && req.Cursor != "" {
		return zero, ErrCursorExpired
	}
	if e != nil {
		return zero, e
	}
	if g.state != "current" && g.state != "retired" {
		return zero, ErrCursorExpired
	}
	if now.Before(g.started) || now.Before(g.completed) || g.manifest.CollectedAt.After(now) {
		return zero, ErrExpired
	}
	if !now.Before(g.manifest.CollectedAt.Add(ObservationTTL)) {
		return zero, ErrExpired
	}
	if g.state == "retired" && (now.Before(g.retired) || !now.Before(g.retired.Add(CursorTTL))) {
		return zero, ErrCursorExpired
	}
	if g.liveRows != g.nextRow || g.liveChunks != g.nextChunk {
		return zero, ErrStorage
	}
	if req.Section != g.manifest.Section {
		return zero, ErrCursor
	}
	start, end := int64(0), int64(g.manifest.ObservedCount)
	if req.Cursor == "" {
		c.Next = start
	}
	if c.Next < start || c.Next > end {
		return zero, ErrCursor
	}
	expires, e := parseStamp(c.Expires)
	if e != nil {
		return zero, e
	}
	if expires.After(g.manifest.CollectedAt.Add(ObservationTTL)) {
		expires = g.manifest.CollectedAt.Add(ObservationTTL)
		c.Expires = stamp(expires)
	}
	if g.state == "retired" && expires.After(g.retired.Add(CursorTTL)) {
		expires = g.retired.Add(CursorTTL)
		c.Expires = stamp(expires)
	}
	// Validating a bounded trusted checkpoint detects inconsistent counters/state;
	// it does not purport to authenticate an arbitrarily rewritten local database.
	if e = checkReceiptClock(ctx, tx, g, now); e != nil {
		return zero, e
	}
	v, e := restore(ctx, g)
	if e != nil {
		return zero, e
	}
	proof, e := v.Finish()
	if e != nil || !proof.Valid() {
		return zero, ErrStorage
	}
	out := PageResult{Section: req.Section, Manifest: g.manifest, StartedAt: g.started, CompletedAt: g.completed, Items: make([]overviewgeneration.Row, 0, req.Limit), TotalRows: uint64(end - start), CursorExpiresAt: expires}
	var afterKey string
	if c.After >= 0 {
		if tx.QueryRowContext(ctx, `SELECT display_key FROM co_rows WHERE device=? AND generation=? AND ordinal=?`, device, g.id, c.After).Scan(&afterKey) != nil {
			return zero, ErrCursor
		}
	}
	if (c.Next == 0) != (c.After == -1) {
		return zero, ErrCursor
	}
	rows, e := tx.QueryContext(ctx, `SELECT ordinal,body,display_key FROM co_rows WHERE device=? AND generation=? AND (display_key,ordinal)>(?,?) ORDER BY display_key,ordinal LIMIT ?`, device, g.id, afterKey, c.After, MaxScanRows)
	if e != nil {
		return zero, ErrStorage
	}
	previousKey := afterKey
	previousOrdinal := c.After
	responseBytes := 16 << 10
	byteBound := false
	for rows.Next() {
		var ordinal int64
		var raw []byte
		var key string
		if rows.Scan(&ordinal, &raw, &key) != nil || ordinal < 0 || ordinal >= end || len(raw) == 0 || len(raw) > overviewgeneration.MaxRowBytes {
			rows.Close()
			return zero, ErrStorage
		}
		var p overviewgeneration.Row
		if json.Unmarshal(raw, &p) != nil || overviewgeneration.ValidateRow(p) != nil {
			rows.Close()
			return zero, ErrStorage
		}
		canonical, _ := json.Marshal(p)
		if !bytes.Equal(canonical, raw) {
			rows.Close()
			return zero, ErrStorage
		}
		if key != displayKey(p) || key < previousKey || key == previousKey && ordinal <= previousOrdinal {
			rows.Close()
			return zero, ErrStorage
		}
		if (req.Section == "processes") != (p.Process != nil) {
			rows.Close()
			return zero, ErrStorage
		}
		matches := query == "" || strings.Contains(strings.ToLower(overviewgeneration.RowSearchText(p)), query)
		if matches && responseBytes+len(raw)+1 > MaxPageBytes {
			byteBound = true
			break
		}
		previousKey, previousOrdinal = key, ordinal
		c.After = ordinal
		c.Next++
		out.ScannedRows++
		if matches {
			out.Items = append(out.Items, p)
			responseBytes += len(raw) + 1
		}
		if len(out.Items) == req.Limit {
			break
		}
	}
	if rows.Err() != nil {
		rows.Close()
		return zero, ErrStorage
	}
	if rows.Close() != nil {
		return zero, ErrStorage
	}
	if c.Next < end && out.ScannedRows < MaxScanRows && len(out.Items) < req.Limit && !byteBound {
		return zero, ErrStorage
	}
	out.Exhausted = c.Next == end
	if !out.Exhausted {
		out.NextCursor = signCursor(c, key)
	}
	out.SearchIncomplete = query != "" && !out.Exhausted
	return out, nil
}
