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

// Fleet cursors reuse the existing software key with a separate purpose domain.
// They do not create a secret, grant, retained snapshot or action authority.
type FleetCursor struct {
	Version     int       `json:"v"`
	Roster      string    `json:"roster"`
	QueryDigest string    `json:"queryDigest"`
	Session     string    `json:"session"`
	Mode        string    `json:"mode"`
	Device      string    `json:"device"`
	Offset      int       `json:"offset"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

const fleetCursorDomain = "tracebolt.windows-complete-machine-software.fleet-cursor.v1\x00"

func SealFleetCursor(ctx context.Context, tx Transaction, c FleetCursor) (string, error) {
	key, e := cursorKey(ctx, tx)
	if e != nil {
		return "", e
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return "", ErrStorage
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(fleetCursorDomain))
	mac.Write(raw)
	token := base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if len(token) > windowsfullsoftware.MaxCursorBytes {
		return "", ErrStorage
	}
	return token, nil
}

func OpenFleetCursor(ctx context.Context, tx Transaction, token string) (FleetCursor, error) {
	zero := FleetCursor{}
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
	key, e := cursorKey(ctx, tx)
	if e != nil {
		return zero, e
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(fleetCursorDomain))
	mac.Write(raw)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return zero, windowsfullsoftware.ErrInvalid
	}
	var c FleetCursor
	if json.Unmarshal(raw, &c) != nil {
		return zero, windowsfullsoftware.ErrInvalid
	}
	canonical, _ := json.Marshal(c)
	if !bytes.Equal(raw, canonical) || c.Version != 1 || c.Offset < 0 || c.Offset > windowsfullsoftware.MaxRows || !windowsfullsoftware.ValidTime(c.ExpiresAt) || (c.Mode != "fleet" && c.Mode != "device") || c.Mode == "fleet" && c.Device != "" || c.Mode == "device" && c.Device == "" {
		return zero, windowsfullsoftware.ErrInvalid
	}
	return c, nil
}

// FleetMatches is called only after Page has verified this exact complete
// generation in the same transaction. The existing (device,generation,ordinal)
// primary index visits its bounded canonical registration order. Filtering uses
// the contract's Unicode identity fold, not SQLite's ASCII-only lower().
func FleetMatches(ctx context.Context, tx Transaction, p windowsfullsoftware.Page, q windowsfullsoftware.FleetQuery, offset, limit int) ([]windowsfullsoftware.Row, int, int, error) {
	rows := []windowsfullsoftware.Row{}
	if p.Complete == nil || p.Status != "ready" || offset < 0 || limit < 1 || limit > windowsfullsoftware.FleetDetailRows {
		return nil, 0, 0, windowsfullsoftware.ErrInvalid
	}
	rr, e := tx.QueryContext(ctx, `SELECT body FROM wfw_rows WHERE device=? AND generation=? ORDER BY ordinal LIMIT 32769`, p.DeviceID, p.Complete.Manifest.GenerationID)
	if e != nil {
		return nil, 0, 0, ErrStorage
	}
	defer rr.Close()
	name, version := windowsfullsoftware.IdentityKey(q.Name), windowsfullsoftware.IdentityKey(q.Version)
	count, unknown, seen := 0, 0, 0
	for rr.Next() {
		if e := ctx.Err(); e != nil {
			return nil, 0, 0, e
		}
		var raw []byte
		var row windowsfullsoftware.Row
		if rr.Scan(&raw) != nil || len(raw) > 16384 || json.Unmarshal(raw, &row) != nil || windowsfullsoftware.ValidateRow(row) != nil {
			return nil, 0, 0, ErrStorage
		}
		seen++
		if seen > p.Complete.Manifest.RowCount {
			return nil, 0, 0, ErrStorage
		}
		if name != "" && row.Name == nil || version != "" && row.Version == nil {
			unknown++
			continue
		}
		if name != "" && !strings.Contains(windowsfullsoftware.IdentityKey(*row.Name), name) || version != "" && !strings.Contains(windowsfullsoftware.IdentityKey(*row.Version), version) {
			continue
		}
		if count >= offset && len(rows) < limit {
			rows = append(rows, row)
		}
		count++
	}
	if rr.Err() != nil || rr.Close() != nil || seen != p.Complete.Manifest.RowCount {
		return nil, 0, 0, ErrStorage
	}
	if offset > count || offset == count && offset != 0 {
		return nil, 0, 0, windowsfullsoftware.ErrConflict
	}
	return rows, count, unknown, nil
}
