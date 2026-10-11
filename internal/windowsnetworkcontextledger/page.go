package windowsnetworkcontextledger

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"localrmm/internal/windowsnetworkcontext"
	"strings"
	"time"
)

type cursor struct {
	Kind       string    `json:"kind"`
	Version    int       `json:"v"`
	Device     string    `json:"device"`
	Grant      string    `json:"grant"`
	Revision   uint64    `json:"revision"`
	Generation string    `json:"generation"`
	Manifest   string    `json:"manifest"`
	Search     string    `json:"search"`
	Sort       string    `json:"sort"`
	Limit      int       `json:"limit"`
	Offset     int       `json:"offset"`
	Session    string    `json:"session"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

const cursorDomain = "tracebolt.windows-network-context.cursor.v1\x00"

func cursorKey(ctx context.Context, tx Transaction) ([]byte, error) {
	var raw []byte
	if tx.QueryRowContext(ctx, `SELECT cursor_key FROM wnc_meta WHERE id=1`).Scan(&raw) != nil || len(raw) != 32 || bytes.Equal(raw, make([]byte, 32)) {
		return nil, ErrStorage
	}
	return raw, nil
}
func signCursor(c cursor, key []byte) string {
	raw, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cursorDomain))
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func decodeCursor(token string, key []byte) (cursor, error) {
	zero := cursor{}
	if len(token) > windowsnetworkcontext.MaxCursorBytes {
		return zero, windowsnetworkcontext.ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return zero, windowsnetworkcontext.ErrInvalid
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if e != nil {
		return zero, windowsnetworkcontext.ErrInvalid
	}
	sig, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil || len(sig) != 32 {
		return zero, windowsnetworkcontext.ErrInvalid
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cursorDomain))
	mac.Write(raw)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return zero, windowsnetworkcontext.ErrInvalid
	}
	var c cursor
	if json.Unmarshal(raw, &c) != nil {
		return zero, windowsnetworkcontext.ErrInvalid
	}
	canonical, _ := json.Marshal(c)
	if !bytes.Equal(raw, canonical) || c.Version != 1 || c.Offset < 0 || c.Offset > windowsnetworkcontext.MaxRows || !windowsnetworkcontext.ValidTime(c.ExpiresAt) {
		return zero, windowsnetworkcontext.ErrInvalid
	}
	return c, nil
}

// Page has bounded complete-generation count/search work (4352 rows maximum).
// Sort expressions are fixed SQL constants; private text is always a parameter.
func Page(ctx context.Context, tx Transaction, device string, r Record, q windowsnetworkcontext.Query, now, authorityUntil time.Time, session string, sessionUntil time.Time) (windowsnetworkcontext.Page, error) {
	zero := windowsnetworkcontext.Page{}
	out := windowsnetworkcontext.Page{SchemaVersion: windowsnetworkcontext.PageVersion, DeviceID: device, ServerNow: now, Status: "not_configured", AuthorityUntil: &authorityUntil, Kind: q.Kind, Search: q.Search, Sort: q.Sort, Limit: q.Limit, Rows: []windowsnetworkcontext.Row{}}
	if r.Consent.Revision == 0 {
		out.AuthorityUntil = nil
		if q.Cursor != "" {
			return zero, windowsnetworkcontext.ErrConflict
		}
		return out, nil
	}
	grant, revision := r.Consent.GrantID, r.Consent.Revision
	out.GrantID = &grant
	out.GrantRevision = &revision
	if !r.Consent.Enabled {
		if q.Cursor != "" {
			return zero, windowsnetworkcontext.ErrConflict
		}
		out.Status = "disabled"
		return out, nil
	}
	out.Status = "awaiting"
	out.LatestAttempt = r.Latest
	if r.Latest != nil {
		copy := *r.Latest
		out.LatestAttempt = &copy
		if copy.Status == "pending" && r.Pending != "" {
			pending, e := LoadGeneration(ctx, tx, device, r.Pending)
			if e != nil {
				return zero, e
			}
			if !now.Before(pending.StartedAt.Add(StagingTTL)) || !now.Before(pending.Manifest.ExpiresAt) {
				copy.Status = "expired"
			}
		}
	}
	if r.Current == "" {
		if q.Cursor != "" {
			return zero, windowsnetworkcontext.ErrConflict
		}
		if out.LatestAttempt != nil && (out.LatestAttempt.Status == "source_failed" || out.LatestAttempt.Status == "expired") {
			out.Status = "unavailable"
		}
		return out, nil
	}
	g, e := LoadGeneration(ctx, tx, device, r.Current)
	if e != nil {
		return zero, e
	}
	if g.State != "current" || g.Manifest.GrantID != grant || g.Manifest.GrantRevision != revision || g.NextRow != g.Manifest.RowCount || g.NextChunk != g.Manifest.ChunkCount || g.CompletedAt.IsZero() {
		return zero, ErrStorage
	}
	if !now.Before(g.Manifest.ExpiresAt) {
		if q.Cursor != "" {
			return zero, windowsnetworkcontext.ErrConflict
		}
		out.Status = "unavailable"
		return out, nil
	}
	if now.Before(g.StartedAt) || now.Before(g.CompletedAt) || now.Before(g.Manifest.CaptureFinishedAt) {
		return zero, windowsnetworkcontext.ErrInvalid
	}
	key, e := cursorKey(ctx, tx)
	if e != nil {
		return zero, e
	}
	c := cursor{Version: 1, Device: device, Grant: grant, Revision: revision, Generation: r.Current, Manifest: g.Hash, Kind: q.Kind, Search: q.Search, Sort: q.Sort, Limit: q.Limit, Session: session, ExpiresAt: now.Add(windowsnetworkcontext.CursorLifetime)}
	if authorityUntil.Before(c.ExpiresAt) {
		c.ExpiresAt = authorityUntil
	}
	if g.Manifest.ExpiresAt.Before(c.ExpiresAt) {
		c.ExpiresAt = g.Manifest.ExpiresAt
	}
	if !sessionUntil.IsZero() && sessionUntil.Before(c.ExpiresAt) {
		c.ExpiresAt = sessionUntil.UTC() // Preserve the deadline, canonicalize normal local-time sessions.
	}
	if q.Cursor != "" {
		old, e := decodeCursor(q.Cursor, key)
		if e != nil {
			return zero, e
		}
		if old.Device != c.Device || old.Grant != c.Grant || old.Revision != c.Revision || old.Generation != c.Generation || old.Manifest != c.Manifest || old.Kind != c.Kind || old.Search != c.Search || old.Sort != c.Sort || old.Limit != c.Limit || old.Session != c.Session || !now.Before(old.ExpiresAt) || old.ExpiresAt.After(c.ExpiresAt) {
			return zero, windowsnetworkcontext.ErrConflict
		}
		c = old
	}
	if !now.Before(c.ExpiresAt) {
		return zero, windowsnetworkcontext.ErrConflict
	}
	if e = verifyCompleteRows(ctx, tx, device, g); e != nil {
		return zero, e
	}
	query := windowsnetworkcontext.IdentityKey(q.Search)
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM wnc_rows WHERE device=? AND generation=? AND (?='all' OR kind=?) AND (?='' OR instr(search,?)>0)`, device, r.Current, q.Kind, q.Kind, query, query).Scan(&out.MatchingCount) != nil || out.MatchingCount > g.Manifest.RowCount {
		return zero, ErrStorage
	}
	if c.Offset > out.MatchingCount {
		return zero, windowsnetworkcontext.ErrConflict
	}
	order := map[string]string{
		"source-asc": "kind ASC,id ASC", "source-desc": "kind DESC,id ASC",
		"interface-asc": "interface_index ASC,kind ASC,id ASC", "interface-desc": "interface_index DESC,kind ASC,id ASC",
	}[q.Sort]
	if order == "" {
		return zero, windowsnetworkcontext.ErrInvalid
	}
	rr, e := tx.QueryContext(ctx, `SELECT body,id,interface_index,kind,search FROM wnc_rows WHERE device=? AND generation=? AND (?='all' OR kind=?) AND (?='' OR instr(search,?)>0) ORDER BY `+order+` LIMIT ? OFFSET ?`, device, r.Current, q.Kind, q.Kind, query, query, q.Limit, c.Offset)
	if e != nil {
		return zero, ErrStorage
	}
	used := 16 << 10
	for rr.Next() {
		var raw []byte
		var id, index uint32
		var search, kind string
		var row windowsnetworkcontext.Row
		if rr.Scan(&raw, &id, &index, &kind, &search) != nil || json.Unmarshal(raw, &row) != nil || windowsnetworkcontext.ValidateRow(row) != nil {
			rr.Close()
			return zero, ErrStorage
		}
		canonical, _ := json.Marshal(row)
		if !bytes.Equal(raw, canonical) || row.ID != id || row.InterfaceIndex != index || row.Kind != kind || SearchText(row) != search {
			rr.Close()
			return zero, ErrStorage
		}
		if used+len(raw)+1 > windowsnetworkcontext.MaxPageBytes {
			break
		}
		used += len(raw) + 1
		out.Rows = append(out.Rows, row)
	}
	if rr.Err() != nil {
		rr.Close()
		return zero, ErrStorage
	}
	if rr.Close() != nil {
		return zero, ErrStorage
	}
	if len(out.Rows) == 0 && c.Offset < out.MatchingCount {
		return zero, ErrStorage
	}
	out.Status = "ready"
	out.Complete = &windowsnetworkcontext.Complete{Manifest: g.Manifest, ManifestSHA256: g.Hash, ReceivedAt: g.CompletedAt}
	out.Offset = c.Offset
	out.CursorExpiresAt = &c.ExpiresAt
	c.Offset += len(out.Rows)
	if c.Offset < out.MatchingCount {
		out.NextCursor = signCursor(c, key)
	}
	raw, _ := json.Marshal(out)
	if len(raw) > windowsnetworkcontext.MaxPageBytes {
		return zero, windowsnetworkcontext.ErrBudget
	}
	return out, nil
}
