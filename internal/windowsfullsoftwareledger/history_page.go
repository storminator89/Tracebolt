package windowsfullsoftwareledger

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"localrmm/internal/windowsfullsoftware"
	"sort"
	"strings"
	"time"
)

const historyCursorDomain = "tracebolt.windows-software-history.cursor.v1\x00"

func signHistoryCursor(c cursor, key []byte) string {
	raw, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(historyCursorDomain))
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func decodeHistoryCursor(token string, key []byte) (cursor, error) {
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
	mac.Write([]byte(historyCursorDomain))
	mac.Write(raw)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return zero, windowsfullsoftware.ErrInvalid
	}
	var c cursor
	if json.Unmarshal(raw, &c) != nil {
		return zero, windowsfullsoftware.ErrInvalid
	}
	canonical, _ := json.Marshal(c)
	if !bytes.Equal(raw, canonical) || c.Version != 1 || c.Offset < 0 || c.Offset > windowsfullsoftware.MaxHistoryRows || !windowsfullsoftware.ValidTime(c.ExpiresAt) {
		return zero, windowsfullsoftware.ErrInvalid
	}
	return c, nil
}
func QueryHistory(ctx context.Context, tx Transaction, device string, r Record, q windowsfullsoftware.Query, now, authorityUntil time.Time, session string, sessionUntil time.Time) (windowsfullsoftware.HistoryPage, error) {
	zero := windowsfullsoftware.HistoryPage{}
	out := windowsfullsoftware.HistoryPage{SchemaVersion: windowsfullsoftware.HistoryPageVersion, DeviceID: device, ServerNow: now, Status: "not_configured", AuthorityUntil: &authorityUntil, Search: q.Search, Limit: q.Limit, Rows: []windowsfullsoftware.HistoryChange{}}
	if r.Consent.Revision == 0 || r.Consent.HistoryScope == "" {
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
		out.Status = "disabled"
		if q.Cursor != "" {
			return zero, windowsfullsoftware.ErrConflict
		}
		return out, nil
	}
	h, e := LoadHistory(ctx, tx, device, r.Consent)
	if e != nil {
		return zero, e
	}
	if PruneHistory(&h, now) {
		if e = SaveHistory(ctx, tx, device, h); e != nil {
			return zero, e
		}
	}
	out.HistoryDigest = HistoryDigest(h)
	out.Comparison = h.Comparison
	out.GapCount = h.GapCount
	out.OmittedChanges = h.OmittedChanges
	out.ExpiredChanges = h.ExpiredChanges
	out.RetainedCount = len(h.Changes)
	out.LatestAttempt = r.Latest
	out.Status = "awaiting"
	if h.Comparison != nil || len(h.Changes) > 0 || h.ExpiredChanges > 0 || h.GapCount > 0 || h.OmittedChanges > 0 {
		out.Status = "ready"
	}
	if out.Status == "awaiting" {
		out.HistoryDigest = ""
		if q.Cursor != "" {
			return zero, windowsfullsoftware.ErrConflict
		}
		return out, nil
	}
	if out.Comparison != nil && now.Before(out.Comparison.AfterObservedAt) {
		return zero, windowsfullsoftware.ErrInvalid
	}
	key, e := cursorKey(ctx, tx)
	if e != nil {
		return zero, e
	}
	c := cursor{Version: 1, Device: device, Grant: grant, Revision: revision, Generation: out.HistoryDigest, Manifest: windowsfullsoftware.HistoryScope, Search: q.Search, Sort: "observed-desc", Limit: q.Limit, Session: session, ExpiresAt: now.Add(windowsfullsoftware.CursorLifetime)}
	bound := func(t time.Time) {
		if !t.IsZero() && t.Before(c.ExpiresAt) {
			c.ExpiresAt = t.UTC()
		}
	}
	bound(authorityUntil)
	bound(sessionUntil)
	if h.Comparison != nil {
		bound(h.Comparison.ExpiresAt)
	}
	for _, row := range h.Changes {
		if now.Before(row.AfterObservedAt) {
			return zero, windowsfullsoftware.ErrInvalid
		}
		bound(row.ExpiresAt)
	}
	if q.Cursor != "" {
		old, e := decodeHistoryCursor(q.Cursor, key)
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
	matches := []windowsfullsoftware.HistoryChange{}
	search := windowsfullsoftware.IdentityKey(q.Search)
	for _, row := range h.Changes {
		if search == "" || strings.Contains(windowsfullsoftware.HistorySearchText(row), search) {
			matches = append(matches, row)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if !matches[i].AfterObservedAt.Equal(matches[j].AfterObservedAt) {
			return matches[i].AfterObservedAt.After(matches[j].AfterObservedAt)
		}
		return matches[i].ID < matches[j].ID
	})
	out.MatchingCount = len(matches)
	if c.Offset > len(matches) {
		return zero, windowsfullsoftware.ErrConflict
	}
	out.Offset = c.Offset
	out.CursorExpiresAt = &c.ExpiresAt
	used := 16384
	for _, row := range matches[c.Offset:] {
		if len(out.Rows) >= q.Limit {
			break
		}
		raw, _ := json.Marshal(row)
		if used+len(raw)+1 > windowsfullsoftware.MaxPageBytes {
			break
		}
		used += len(raw) + 1
		out.Rows = append(out.Rows, row)
	}
	if len(out.Rows) == 0 && c.Offset < len(matches) {
		return zero, ErrStorage
	}
	c.Offset += len(out.Rows)
	if c.Offset < len(matches) {
		out.NextCursor = signHistoryCursor(c, key)
	}
	raw, _ := json.Marshal(out)
	if len(raw) > windowsfullsoftware.MaxPageBytes {
		return zero, windowsfullsoftware.ErrBudget
	}
	return out, nil
}
