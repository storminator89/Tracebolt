package overviewledger

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const cursorDomain = "tracebolt.overview-ledger.cursor.v1\x00"

// CursorKey is a caller-owned durable MAC key, independent of client input. Key
// rotation intentionally invalidates existing cursors. Do not place it in logs,
// client JSON, request telemetry or a second authority cache.
type CursorKey struct{ state *cursorKeyState }
type cursorKeyState struct{ value [32]byte }

func NewCursorKey(raw [32]byte) (CursorKey, error) {
	if raw == [32]byte{} {
		return CursorKey{}, ErrInvalid
	}
	return CursorKey{state: &cursorKeyState{value: raw}}, nil
}
func (CursorKey) String() string               { return "overviewledger.CursorKey{redacted}" }
func (k CursorKey) GoString() string           { return k.String() }
func (k CursorKey) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }
func (CursorKey) MarshalJSON() ([]byte, error) { return []byte(`"redacted"`), nil }

type cursor struct {
	Version    int    `json:"v"`
	Device     string `json:"device"`
	Generation string `json:"generation"`
	Section    string `json:"section"`
	Search     string `json:"search"`
	Next       int64  `json:"next"`
	After      int64  `json:"after"`
	Limit      int    `json:"limit"`
	Expires    string `json:"expires"`
}

func signCursor(c cursor, key CursorKey) string {
	raw, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, key.state.value[:])
	_, _ = mac.Write([]byte(cursorDomain))
	_, _ = mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func readCursor(token string, key CursorKey, device, section, query string, limit int, now time.Time) (cursor, error) {
	var zero cursor
	if len(token) > MaxCursorBytes {
		return zero, ErrCursor
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return zero, ErrCursor
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if e != nil {
		return zero, ErrCursor
	}
	signature, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil || len(signature) != sha256.Size {
		return zero, ErrCursor
	}
	mac := hmac.New(sha256.New, key.state.value[:])
	_, _ = mac.Write([]byte(cursorDomain))
	_, _ = mac.Write(raw)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return zero, ErrCursor
	}
	var c cursor
	if json.Unmarshal(raw, &c) != nil {
		return zero, ErrCursor
	}
	canonical, _ := json.Marshal(c)
	if !bytes.Equal(raw, canonical) {
		return zero, ErrCursor
	}
	if c.Version != 1 || c.Device != device || c.Section != section || c.Search != query || c.Limit != limit || !validGeneration(c.Generation) || c.Next < 0 || c.Next > 32768 || c.After < -1 || c.After >= 32768 {
		return zero, ErrCursor
	}
	at, e := parseStamp(c.Expires)
	if e != nil || at.IsZero() {
		return zero, ErrCursor
	}
	if !now.Before(at) {
		return zero, ErrCursorExpired
	}
	if at.After(now.Add(CursorTTL)) {
		return zero, ErrCursor
	}
	return c, nil
}
func normalizeSearch(s string) (string, error) {
	if len(s) > MaxSearchBytes {
		return "", ErrInvalid
	}
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return "", ErrInvalid
		}
	}
	return strings.ToLower(strings.TrimSpace(s)), nil
}
