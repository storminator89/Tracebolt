package inventoryledger

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	"strings"
	"time"
)

type PageRequest struct {
	Limit  int
	Search string
	Cursor string
	// Optional generation assertion, required to match a supplied cursor. Without
	// a cursor only the current generation may be selected.
	GenerationID string
}

// PageResult is provisional until the authority transaction commits. TotalRows
// is the full immutable inventory size, NOT the count of search matches. An empty
// Items with !Exhausted is a scan continuation, never proof of no search matches.
type PageResult struct {
	Manifest               fullinventory.Manifest
	StartedAt, CompletedAt time.Time
	Items                  []linuxpackages.PackageRow
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
	if !validDevice(device) || !validTime(now) || req.Limit < 1 || req.Limit > MaxPageRows || key.state == nil || key.state.value == [32]byte{} || req.GenerationID != "" && !validGeneration(req.GenerationID) {
		return zero, ErrInvalid
	}
	query, e := normalizeSearch(req.Search)
	if e != nil {
		return zero, e
	}
	var c cursor
	if req.Cursor != "" {
		c, e = readCursor(req.Cursor, key, device, query, req.Limit, now)
		if e != nil {
			return zero, e
		}
		if req.GenerationID != "" && req.GenerationID != c.Generation {
			return zero, ErrCursor
		}
	} else {
		var id string
		e = tx.QueryRowContext(ctx, `SELECT current_generation FROM fi_devices WHERE device=?`, device).Scan(&id)
		if errors.Is(e, sql.ErrNoRows) || e == nil && id == "" {
			return zero, ErrNotFound
		}
		if e != nil {
			return zero, ErrStorage
		}
		if req.GenerationID != "" && req.GenerationID != id {
			return zero, ErrCursorExpired
		}
		c = cursor{1, device, id, query, 0, req.Limit, stamp(now.Add(CursorTTL))}
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
	if c.Next > g.nextRow {
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
	out := PageResult{Manifest: g.manifest, StartedAt: g.started, CompletedAt: g.completed, Items: make([]linuxpackages.PackageRow, 0, req.Limit), TotalRows: g.manifest.ObservedCount, CursorExpiresAt: expires}
	rows, e := tx.QueryContext(ctx, `SELECT ordinal,body FROM fi_rows WHERE device=? AND generation=? AND ordinal>=? ORDER BY ordinal LIMIT ?`, device, g.id, c.Next, MaxScanRows)
	if e != nil {
		return zero, ErrStorage
	}
	var previous *linuxpackages.PackageRow
	for rows.Next() {
		var ordinal int64
		var raw []byte
		if rows.Scan(&ordinal, &raw) != nil || ordinal != c.Next || len(raw) == 0 || len(raw) > 4096 {
			rows.Close()
			return zero, ErrStorage
		}
		var p linuxpackages.PackageRow
		if json.Unmarshal(raw, &p) != nil || fullinventory.ValidateRow(p) != nil {
			rows.Close()
			return zero, ErrStorage
		}
		canonical, _ := json.Marshal(p)
		if !bytes.Equal(canonical, raw) {
			rows.Close()
			return zero, ErrStorage
		}
		if previous != nil && (p.Name < previous.Name || p.Name == previous.Name && p.Architecture <= previous.Architecture) {
			rows.Close()
			return zero, ErrStorage
		}
		copy := p
		previous = &copy
		c.Next++
		out.ScannedRows++
		if query == "" || strings.Contains(strings.ToLower(strings.Join([]string{p.Name, p.Version, p.Architecture, p.SourcePackage, p.SourceVersion, p.SourceMapping, p.InstallState}, " ")), query) {
			out.Items = append(out.Items, p)
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
	if c.Next < g.nextRow && out.ScannedRows < MaxScanRows && len(out.Items) < req.Limit {
		return zero, ErrStorage
	}
	out.Exhausted = c.Next == g.nextRow
	if !out.Exhausted {
		out.NextCursor = signCursor(c, key)
	}
	out.SearchIncomplete = query != "" && !out.Exhausted
	return out, nil
}
