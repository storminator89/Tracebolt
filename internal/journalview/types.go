// Package journalview defines a bounded, opt-in system journal content snapshot.
// It does not grant journal access, consent, transport or retention authority.
package journalview

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	SchemaVersion    = "tracebolt.journal-content.v1"
	Scope            = "agent-visible-system-journal-service-and-manager"
	RedactionWarning = "Best-effort masking only. Messages may still contain credentials, personal data or other secrets; this output is not safe or anonymous."
	MaxRows          = 500
	MaxSnapshotBytes = 512 << 10
	MaxMessageBytes  = 4 << 10
	MaxRawBytes      = 8 << 20
	MaxLineBytes     = 64 << 10
	MaxScannedRows   = 4096
	MaxUnitBytes     = 255
	MaxLookback      = 24 * time.Hour
	MaxSpan          = time.Hour
	CommandTimeout   = 4 * time.Second
	metadataReserve  = 2048
)

var (
	ErrInvalidInput    = errors.New("journal_view_invalid_input")
	ErrInvalidSnapshot = errors.New("journal_view_invalid_snapshot")
	ErrSourceLimit     = errors.New("journal_view_source_limit")
)

type Coverage string

const (
	Complete Coverage = "complete"
	Partial  Coverage = "partial"
	Failed   Coverage = "failed"
)

type Reason string

const (
	ReasonNone                 Reason = "none"
	ReasonPermissionDenied     Reason = "permission_denied"
	ReasonSourceMissing        Reason = "source_missing"
	ReasonInvalidSource        Reason = "invalid_source"
	ReasonReadFailed           Reason = "read_failed"
	ReasonTimeout              Reason = "timeout"
	ReasonItemLimit            Reason = "item_limit"
	ReasonByteLimit            Reason = "byte_limit"
	ReasonVisibilityRestricted Reason = "visibility_restricted"
	ReasonNotSupported         Reason = "not_supported"
	ReasonCollectorBusy        Reason = "collector_busy"
)

type Query struct {
	Unit        string    `json:"unit"`
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	MaxPriority int       `json:"maxPriority"`
	BrowseMode  string    `json:"browseMode,omitempty"`
	Search      string    `json:"search,omitempty"`
	Cursor      string    `json:"cursor,omitempty"`
}
type Row struct {
	Timestamp time.Time `json:"timestamp"`
	Unit      string    `json:"unit"`
	Priority  int       `json:"priority"`
	Message   string    `json:"message"`
}
type Snapshot struct {
	SchemaVersion    string    `json:"schemaVersion"`
	Scope            string    `json:"scope"`
	Query            Query     `json:"query"`
	ObservedAt       time.Time `json:"observedAt"`
	Coverage         Coverage  `json:"coverage"`
	Reason           Reason    `json:"reason"`
	Rows             []Row     `json:"rows"`
	ObservedCount    uint64    `json:"observedCount"`
	CountExact       bool      `json:"countExact"`
	RedactionApplied bool      `json:"redactionApplied"`
	RedactionWarning string    `json:"redactionWarning"`
	NextCursor       string    `json:"nextCursor,omitempty"`
	Exhausted        bool      `json:"exhausted,omitempty"`
}

// ValidateQuery accepts an intentionally small canonical service-name subset.
// Escaped names, paths, template patterns and arbitrary match syntax are not
// supported. Names are matched literally against _SYSTEMD_UNIT; aliases are not
// resolved. A second fixed branch permits UNIT only with trusted PID 1/UID 0.
// Start/end are inclusive, UTC, and microsecond-aligned.
func ValidateQuery(q Query, now time.Time) error {
	if !validUnit(q.Unit) || !validUTC(now) || !validUTC(q.Start) || !validUTC(q.End) ||
		q.Start.Nanosecond()%1000 != 0 || q.End.Nanosecond()%1000 != 0 || q.Start.After(q.End) ||
		q.Start.Equal(q.End) || q.End.After(now) || q.MaxPriority < 0 || q.MaxPriority > 7 {
		return ErrInvalidInput
	}
	if q.BrowseMode == "" {
		if q.Search != "" || q.Cursor != "" || now.Sub(q.Start) > MaxLookback || q.End.Sub(q.Start) > MaxSpan {
			return ErrInvalidInput
		}
	} else if q.BrowseMode != BrowseMode || !validSearch(q.Search) || q.Cursor != "" && !ValidCursor(q.Cursor) {
		return ErrInvalidInput
	}
	return nil
}
func validUTC(t time.Time) bool {
	return t.Location() == time.UTC && t.Year() >= 1970 && t.Year() <= 9999
}
func validUnit(s string) bool {
	if len(s) > MaxUnitBytes || !strings.HasSuffix(s, ".service") {
		return false
	}
	stem := strings.TrimSuffix(s, ".service")
	if len(stem) == 0 || stem[0] == '.' || stem[0] == '-' || stem[0] == '@' || strings.Contains(stem, "..") || strings.HasSuffix(stem, "@") || strings.Count(stem, "@") > 1 {
		return false
	}
	for _, c := range stem {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '@') {
			return false
		}
	}
	return true
}
func validReason(r Reason) bool {
	switch r {
	case ReasonCursorUnavailable, ReasonNone, ReasonPermissionDenied, ReasonSourceMissing, ReasonInvalidSource, ReasonReadFailed, ReasonTimeout, ReasonItemLimit, ReasonByteLimit, ReasonVisibilityRestricted, ReasonNotSupported, ReasonCollectorBusy:
		return true
	}
	return false
}
func empty(q Query, now time.Time) Snapshot {
	version := SchemaVersion
	if q.BrowseMode == BrowseMode {
		version = SchemaVersionV2
	}
	return Snapshot{SchemaVersion: version, Scope: Scope, Query: q, ObservedAt: now, Coverage: Complete, Reason: ReasonNone, Rows: make([]Row, 0, MaxRows), CountExact: true, RedactionWarning: RedactionWarning}
}
func mark(s Snapshot, reason Reason) Snapshot {
	// A cleanup, timeout or source failure cannot retain an exhaustion claim.
	s.Exhausted = false
	s.Reason = reason
	s.CountExact = false
	// A validated cursor records source progress even if a sparse search or
	// projection gap retained no rows. Cleanup failure must keep that partial
	// continuation instead of producing a contradictory failed-with-cursor page.
	continuable := s.Query.BrowseMode == BrowseMode && ValidCursor(s.NextCursor) && s.NextCursor != s.Query.Cursor
	if reason == ReasonItemLimit || reason == ReasonByteLimit || reason == ReasonVisibilityRestricted || len(s.Rows) > 0 || s.ObservedCount > 0 || continuable {
		s.Coverage = Partial
	} else {
		s.Coverage = Failed
	}
	return s
}

// Provider is synchronous: it must honor cancellation cooperatively, bound work
// and release resources before returning. Its only input is a validated query.
// Open may return a bounded readable prefix with byte_limit/visibility_restricted.
// No test invokes the real provider or a subprocess.
type Provider interface {
	Open(context.Context, Query) (io.ReadCloser, Reason, error)
}
type SourceError struct{ Reason Reason }

func (e SourceError) Error() string {
	if !validReason(e.Reason) || e.Reason == ReasonNone {
		return "journal_view_source_read_failed"
	}
	return "journal_view_source_" + string(e.Reason)
}
func failureReason(err error) Reason {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ReasonTimeout
	}
	if errors.Is(err, ErrSourceLimit) {
		return ReasonByteLimit
	}
	var e SourceError
	if errors.As(err, &e) && validReason(e.Reason) && e.Reason != ReasonNone {
		return e.Reason
	}
	return ReasonReadFailed
}

func (Query) String() string               { return "journalview.Query{content redacted}" }
func (q Query) GoString() string           { return q.String() }
func (q Query) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, q.String()) }

// Formatting is content-redacted to keep accidental diagnostic formatting from
// dumping journal messages. Encode is the deliberate validated wire serializer.
func (Row) String() string                    { return "journalview.Row{content redacted}" }
func (r Row) GoString() string                { return r.String() }
func (r Row) Format(f fmt.State, _ rune)      { _, _ = io.WriteString(f, r.String()) }
func (Snapshot) String() string               { return "journalview.Snapshot{content redacted}" }
func (s Snapshot) GoString() string           { return s.String() }
func (s Snapshot) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
