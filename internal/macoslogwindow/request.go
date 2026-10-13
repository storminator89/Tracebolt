// Package macoslogwindow is an inactive, pure contract for one explicitly
// requested macOS log window. It contains no native reader, authority, transport,
// storage or provider callbacks. A valid value never grants permission to read.
package macoslogwindow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"
)

const (
	Scope           = "macos-unified-log-window-v1"
	RequestSchema   = "tracebolt.macos-log-window-request.v1"
	DefaultWindow   = 5 * time.Minute
	MaxWindow       = 15 * time.Minute
	MaxLookback     = 24 * time.Hour
	Lifetime        = 15 * time.Minute
	MaxRequestBytes = 2048
)

var (
	ErrInvalid = errors.New("macos_log_window_invalid")
	ErrExpired = errors.New("macos_log_window_expired")
	ErrClock   = errors.New("macos_log_window_clock_invalid")
	ErrBounds  = errors.New("macos_log_window_bounds")
)

// Request is only the query contract. Transport must be "tls", but this field
// is not transport authentication. Future trusted admission must independently
// bind original identity, fresh local content consent, request ID/sequence,
// operator session and actual TLS. No native predicate or service selector exists.
// The interval is [Start, End); all times are UTC. CreatedAt and ExpiresAt are
// immutable across retries, receipt publication, renewal, filtering and paging.
type Request struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	Transport     string    `json:"transport"`
	CreatedAt     time.Time `json:"createdAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
}

func (Request) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("<macos-log-window request redacted>"))
}

func validTime(t time.Time) bool {
	return t.Location() == time.UTC && t.Unix() > 0 && t.Year() <= 9999
}

// DefaultRequest constructs a fixed last-five-minute window, never a moving
// "last" argument to a native utility. It performs no collection or activation.
func DefaultRequest(created time.Time) (Request, error) {
	r := Request{RequestSchema, Scope, "tls", created, created.Add(Lifetime), created.Add(-DefaultWindow), created}
	if err := ValidateRequest(r); err != nil {
		return Request{}, err
	}
	return r, nil
}

func ValidateRequest(r Request) error {
	if r.SchemaVersion != RequestSchema || r.Scope != Scope || r.Transport != "tls" ||
		!validTime(r.CreatedAt) || !validTime(r.ExpiresAt) || !validTime(r.Start) || !validTime(r.End) ||
		!r.ExpiresAt.Equal(r.CreatedAt.Add(Lifetime)) || !r.Start.Before(r.End) ||
		r.End.Sub(r.Start) > MaxWindow || r.End.After(r.CreatedAt) || r.Start.Before(r.CreatedAt.Add(-MaxLookback)) {
		return ErrInvalid
	}
	return nil
}

// ValidateLive rejects expired or pre-creation clocks; it cannot detect a
// backwards clock that remains after CreatedAt. A future owner must also track
// its last trusted clock and discard memory on any regression.
func ValidateLive(r Request, now time.Time) error {
	if err := ValidateRequest(r); err != nil {
		return err
	}
	if !validTime(now) || now.Before(r.CreatedAt) {
		return ErrClock
	}
	if !now.Before(r.ExpiresAt) {
		return ErrExpired
	}
	return nil
}

func EncodeRequest(r Request) ([]byte, error) {
	if err := ValidateRequest(r); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

func DecodeRequest(raw []byte) (Request, error) {
	var r Request
	if err := decodeCanonical(raw, &r, MaxRequestBytes); err != nil {
		return Request{}, err
	}
	if err := ValidateRequest(r); err != nil {
		return Request{}, err
	}
	return r, nil
}

// Exact re-encoding also rejects duplicate keys, alternate field casing, null
// scalar values, replacement of invalid UTF-8/surrogates, and trailing documents.
// This is Tracebolt's internal format, not a permissive native JSON parser.
func decodeCanonical(raw []byte, value any, limit int) error {
	if len(raw) > limit {
		return ErrBounds
	}
	if len(raw) == 0 || !utf8.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		if errors.Is(err, ErrBounds) {
			return ErrBounds
		}
		return ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	encoded, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, encoded) {
		return ErrInvalid
	}
	return nil
}
