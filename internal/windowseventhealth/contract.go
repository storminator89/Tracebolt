// Package windowseventhealth is the separately consented, bounded event-header
// extension. It contains no event content or provider-export integration.
package windowseventhealth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/windowsevents"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const SchemaVersion = "tracebolt.windows-event-metadata.v1"
const ConsentVersion = "tracebolt.windows-event-metadata-consent.v1"
const Scope = "windows-application-system-event-headers-v1"
const MaxBytes = 6 << 10
const MaxRows = 16
const HTTPPrivacy = "WARNING: HTTP-test also sends Application/System event headers, including provider names, IDs, levels and timestamps, in plaintext. Network observers can read them; signatures do not encrypt headers or authenticate manager responses. Use only a disposable test network; production requires HTTPS."
const Privacy = "Read and send bounded Application and System event headers: provider, event ID, level, record ID, timestamp and channel. No messages, XML, EventData, Security log or identities. Headers remain private manager data and are excluded from AI/provider export. This does not establish overall device health."

var ErrInvalid = errors.New("windows_event_metadata_invalid")

type Consent struct {
	SchemaVersion string `json:"schemaVersion"`
	Scope         string `json:"scope"`
	SenderBinding string `json:"senderBinding"`
	GrantID       string `json:"grantId"`
	Enabled       bool   `json:"enabled"`
}
type Event struct {
	RecordID  string    `json:"recordId"`
	EventID   uint16    `json:"eventId"`
	Level     uint8     `json:"level"`
	Provider  string    `json:"provider"`
	Timestamp time.Time `json:"timestamp"`
}
type Channel struct {
	Channel       string  `json:"channel"`
	Quality       string  `json:"quality"`
	Reason        string  `json:"reason"`
	Complete      bool    `json:"complete"`
	Truncated     bool    `json:"truncated"`
	ObservedCount uint32  `json:"observedCount"`
	Rows          []Event `json:"rows"`
}
type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	GrantID       string    `json:"grantId"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
	Channels      []Channel `json:"channels"`
}

func hex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func canonical(raw []byte, v any, max int) error {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	b, e := json.Marshal(v)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrInvalid
	}
	return nil
}
func DecodeConsent(raw []byte, binding string) (Consent, error) {
	var c Consent
	if canonical(raw, &c, 1024) != nil || c.SchemaVersion != ConsentVersion || c.Scope != Scope || !hex(binding, 64) || c.SenderBinding != binding || !hex(c.GrantID, 32) {
		return Consent{}, ErrInvalid
	}
	return c, nil
}
func EncodeConsent(c Consent, binding string) ([]byte, error) {
	b, e := json.Marshal(c)
	if e != nil {
		return nil, ErrInvalid
	}
	if _, e = DecodeConsent(b, binding); e != nil {
		return nil, e
	}
	return b, nil
}
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1601 && t.Year() <= 9999
}
func validText(s string) bool {
	units := 0
	for _, r := range s {
		units++
		if r > 0xffff {
			units++
		}
	}
	return units <= 256 && s != "" && strings.TrimSpace(s) == s && len(s) <= 1024 && utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError || r == '\u2028' || r == '\u2029'
	}) < 0
}
func Validate(s Snapshot) error { return validateSnapshot(s, true) }
func validateSnapshot(s Snapshot, budget bool) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != Scope || !hex(s.GrantID, 32) || !strings.HasPrefix(s.GenerationID, "sample_") || !hex(strings.TrimPrefix(s.GenerationID, "sample_"), 32) || !validTime(s.CollectedAt) || s.CollectedAt.Year() < 1970 || len(s.Channels) != 2 {
		return ErrInvalid
	}
	for i, c := range s.Channels {
		if c.Channel != []string{"Application", "System"}[i] || c.Rows == nil || len(c.Rows) > MaxRows || c.ObservedCount > MaxRows || int(c.ObservedCount) < len(c.Rows) || int(c.ObservedCount) > len(c.Rows) && !c.Truncated {
			return ErrInvalid
		}
		switch c.Quality {
		case "observed":
			if !c.Complete || c.Truncated || c.Reason != "" || int(c.ObservedCount) != len(c.Rows) {
				return ErrInvalid
			}
		case "bounded":
			if c.Complete || !c.Truncated || c.Reason != "" {
				return ErrInvalid
			}
		case "partial":
			if c.Complete || c.Reason == "" {
				return ErrInvalid
			}
		case "denied", "unavailable":
			if c.Complete || c.Truncated || len(c.Rows) != 0 || c.ObservedCount != 0 || c.Reason == "" {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		if c.Reason != "" {
			switch c.Reason {
			case "windows_events_access_denied", "windows_events_unsupported_platform", "windows_events_source_unavailable", "windows_events_invalid_metadata", "windows_events_metadata_buffer_limit", "windows_events_read_failed", "context canceled", "context deadline exceeded":
			default:
				return ErrInvalid
			}
		}
		if (c.Quality == "denied") != (c.Reason == "windows_events_access_denied" && len(c.Rows) == 0) {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for _, e := range c.Rows {
			n, err := strconv.ParseUint(e.RecordID, 10, 64)
			if err != nil || n == 0 || strconv.FormatUint(n, 10) != e.RecordID || seen[e.RecordID] || !validText(e.Provider) || !validTime(e.Timestamp) {
				return ErrInvalid
			}
			seen[e.RecordID] = true
		}
	}
	b, e := json.Marshal(s)
	if e != nil || budget && len(b) > MaxBytes {
		return ErrInvalid
	}
	return nil
}
func Decode(raw []byte) (Snapshot, error) {
	var s Snapshot
	if canonical(raw, &s, MaxBytes) != nil || Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	return s, nil
}

// FromReport copies the native report and never consults or changes the clock.
// Transport omission preserves observed counts and marks bounded/partial data.
func FromReport(r windowsevents.Report, generation, grant string) (Snapshot, error) {
	s := Snapshot{SchemaVersion, Scope, grant, generation, r.CollectedAt, []Channel{}}
	if r.Source != windowsevents.Source || r.LimitPerChannel != MaxRows || len(r.Channels) != 2 {
		return Snapshot{}, ErrInvalid
	}
	complete, truncated := true, false
	failures, observed := false, false
	for i, p := range r.Channels {
		if p.Channel != []string{"Application", "System"}[i] || p.Source != windowsevents.Source || len(p.Events) > MaxRows {
			return Snapshot{}, ErrInvalid
		}
		c := Channel{p.Channel, p.Quality, p.Reason, p.Complete, p.Truncated, uint32(len(p.Events)), []Event{}}
		if c.Reason == windowsevents.ErrAccessDenied.Error() && len(p.Events) == 0 {
			c.Quality = "denied"
		}
		for _, e := range p.Events {
			if e.Channel != p.Channel {
				return Snapshot{}, ErrInvalid
			}
			c.Rows = append(c.Rows, Event{strconv.FormatUint(e.RecordID, 10), e.EventID, e.Level, e.Provider, e.Timestamp})
		}
		s.Channels = append(s.Channels, c)
		failures = failures || p.Reason != ""
		observed = observed || p.Reason == "" || len(p.Events) > 0
		complete = complete && p.Complete
		truncated = truncated || p.Truncated
	}
	if r.Complete != complete || r.Truncated != truncated {
		return Snapshot{}, ErrInvalid
	}
	quality := "observed"
	if failures {
		quality = "partial"
		if !observed {
			quality = "unavailable"
		}
	} else if truncated {
		quality = "bounded"
	}
	if r.Quality != quality || validateSnapshot(s, false) != nil {
		return Snapshot{}, ErrInvalid
	}
	// Each iteration removes exactly one row. No unbounded rendering or retries.
	for {
		b, _ := json.Marshal(s)
		if len(b) <= MaxBytes {
			break
		}
		n := 0
		if len(s.Channels[1].Rows) > len(s.Channels[0].Rows) {
			n = 1
		}
		c := &s.Channels[n]
		if len(c.Rows) == 0 {
			return Snapshot{}, ErrInvalid
		}
		c.Rows = c.Rows[:len(c.Rows)-1]
		c.Complete = false
		c.Truncated = true
		if c.Reason == "" {
			c.Quality = "bounded"
		}
	}
	if Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	return s, nil
}
func Collect(ctx context.Context, generation string, c Consent, binding string) (Snapshot, error) {
	return collectUsing(ctx, generation, c, binding, windowsevents.Collect)
}
func collectUsing(ctx context.Context, generation string, c Consent, binding string, read func(context.Context, []string, int) (windowsevents.Report, error)) (Snapshot, error) {
	b, e := EncodeConsent(c, binding)
	if e != nil || !c.Enabled || len(b) == 0 || ctx == nil || read == nil || !strings.HasPrefix(generation, "sample_") || !hex(strings.TrimPrefix(generation, "sample_"), 32) {
		return Snapshot{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return Snapshot{}, ctx.Err()
	}
	r, _ := read(ctx, []string{"Application", "System"}, MaxRows)
	if ctx.Err() != nil {
		return Snapshot{}, ctx.Err()
	}
	return FromReport(r, generation, c.GrantID)
}
