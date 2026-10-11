package windowsfullsoftwareledger

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"localrmm/internal/windowsfullsoftware"
	"strings"
	"time"
)

type cursor struct {
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

const cursorDomain = "tracebolt.windows-complete-machine-software.cursor.v1\x00"

func cursorKey(ctx context.Context, tx Transaction) ([]byte, error) {
	var raw []byte
	if tx.QueryRowContext(ctx, `SELECT cursor_key FROM wfw_meta WHERE id=1`).Scan(&raw) != nil || len(raw) != 32 || bytes.Equal(raw, make([]byte, 32)) {
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
	if len(token) > windowsfullsoftware.MaxCursorBytes {
		return zero, windowsfullsoftware.ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return zero, windowsfullsoftware.ErrInvalid
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if e != nil {
		return zero, windowsfullsoftware.ErrInvalid
	}
	sig, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil || len(sig) != 32 {
		return zero, windowsfullsoftware.ErrInvalid
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cursorDomain))
	mac.Write(raw)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return zero, windowsfullsoftware.ErrInvalid
	}
	var c cursor
	if json.Unmarshal(raw, &c) != nil {
		return zero, windowsfullsoftware.ErrInvalid
	}
	canonical, _ := json.Marshal(c)
	if !bytes.Equal(raw, canonical) || c.Version != 1 || c.Offset < 0 || c.Offset > windowsfullsoftware.MaxRows || !windowsfullsoftware.ValidTime(c.ExpiresAt) {
		return zero, windowsfullsoftware.ErrInvalid
	}
	return c, nil
}

// Page has bounded complete-generation count/search work (32768 rows maximum).
// Sort expressions are fixed SQL constants; private text is always a parameter.
func Page(ctx context.Context, tx Transaction, device string, r Record, q windowsfullsoftware.Query, now, authorityUntil time.Time, session string, sessionUntil time.Time) (windowsfullsoftware.Page, error) {
	zero := windowsfullsoftware.Page{}
	out := windowsfullsoftware.Page{SchemaVersion: windowsfullsoftware.PageVersion, DeviceID: device, ServerNow: now, Status: "not_configured", AuthorityUntil: &authorityUntil, Search: q.Search, Sort: q.Sort, Limit: q.Limit, Rows: []windowsfullsoftware.Row{}}
	if r.Consent.Revision == 0 {
		out.AuthorityUntil = nil
		if q.Cursor != "" {
			return zero, windowsfullsoftware.ErrConflict
		}
		return out, nil
	}
	grant, revision := r.Consent.GrantID, r.Consent.Revision
	out.GrantID = &grant
	out.GrantRevision = &revision
	if !r.Consent.Enabled {
		if q.Cursor != "" {
			return zero, windowsfullsoftware.ErrConflict
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
			return zero, windowsfullsoftware.ErrConflict
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
			return zero, windowsfullsoftware.ErrConflict
		}
		out.Status = "unavailable"
		return out, nil
	}
	if now.Before(g.StartedAt) || now.Before(g.CompletedAt) || now.Before(g.Manifest.CaptureFinishedAt) {
		return zero, windowsfullsoftware.ErrInvalid
	}
	key, e := cursorKey(ctx, tx)
	if e != nil {
		return zero, e
	}
	c := cursor{Version: 1, Device: device, Grant: grant, Revision: revision, Generation: r.Current, Manifest: g.Hash, Search: q.Search, Sort: q.Sort, Limit: q.Limit, Session: session, ExpiresAt: now.Add(windowsfullsoftware.CursorLifetime)}
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
		if old.Device != c.Device || old.Grant != c.Grant || old.Revision != c.Revision || old.Generation != c.Generation || old.Manifest != c.Manifest || old.Search != c.Search || old.Sort != c.Sort || old.Limit != c.Limit || old.Session != c.Session || !now.Before(old.ExpiresAt) || old.ExpiresAt.After(c.ExpiresAt) {
			return zero, windowsfullsoftware.ErrConflict
		}
		c = old
	}
	if !now.Before(c.ExpiresAt) {
		return zero, windowsfullsoftware.ErrConflict
	}
	if e = verifyCompleteRows(ctx, tx, device, g); e != nil {
		return zero, e
	}
	query := windowsfullsoftware.IdentityKey(q.Search)
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM wfw_rows WHERE device=? AND generation=? AND (?='' OR instr(search,?)>0)`, device, r.Current, query, query).Scan(&out.MatchingCount) != nil || out.MatchingCount > g.Manifest.RowCount {
		return zero, ErrStorage
	}
	if c.Offset > out.MatchingCount {
		return zero, windowsfullsoftware.ErrConflict
	}
	order := map[string]string{
		"name-asc": "name IS NULL ASC,name ASC,registration_id ASC", "name-desc": "name IS NULL ASC,name DESC,registration_id ASC",
		"version-asc": "version IS NULL ASC,version ASC,registration_id ASC", "version-desc": "version IS NULL ASC,version DESC,registration_id ASC",
		"publisher-asc": "publisher IS NULL ASC,publisher ASC,registration_id ASC", "publisher-desc": "publisher IS NULL ASC,publisher DESC,registration_id ASC",
		"view-asc": "registry_view ASC,registration_id ASC", "view-desc": "registry_view DESC,registration_id ASC",
	}[q.Sort]
	if order == "" {
		return zero, windowsfullsoftware.ErrInvalid
	}
	rr, e := tx.QueryContext(ctx, `SELECT body,registration_id,registry_view,name,version,publisher,search FROM wfw_rows WHERE device=? AND generation=? AND (?='' OR instr(search,?)>0) ORDER BY `+order+` LIMIT ? OFFSET ?`, device, r.Current, query, query, q.Limit, c.Offset)
	if e != nil {
		return zero, ErrStorage
	}
	used := 16 << 10
	for rr.Next() {
		var raw []byte
		var registration, view, search string
		var name, version, publisher *string
		var row windowsfullsoftware.Row
		if rr.Scan(&raw, &registration, &view, &name, &version, &publisher, &search) != nil || json.Unmarshal(raw, &row) != nil || windowsfullsoftware.ValidateRow(row) != nil {
			rr.Close()
			return zero, ErrStorage
		}
		canonical, _ := json.Marshal(row)
		if !bytes.Equal(raw, canonical) || row.RegistrationID != registration || row.RegistryView != view || !sameText(row.Name, name) || !sameText(row.Version, version) || !sameText(row.Publisher, publisher) || SearchText(row) != search {
			rr.Close()
			return zero, ErrStorage
		}
		if used+len(raw)+1 > windowsfullsoftware.MaxPageBytes {
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
	out.Complete = &windowsfullsoftware.Complete{Manifest: g.Manifest, ManifestSHA256: g.Hash, ReceivedAt: g.CompletedAt}
	out.Offset = c.Offset
	out.CursorExpiresAt = &c.ExpiresAt
	c.Offset += len(out.Rows)
	if c.Offset < out.MatchingCount {
		out.NextCursor = signCursor(c, key)
	}
	raw, _ := json.Marshal(out)
	if len(raw) > windowsfullsoftware.MaxPageBytes {
		return zero, windowsfullsoftware.ErrBudget
	}
	return out, nil
}
