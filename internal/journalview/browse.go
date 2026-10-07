package journalview

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// Browse is a distinct contract. Existing v1 queries retain their original
// range limits. Every page is bounded, newest first, and carries a source
// locator only to continue the same exact scope. It is not a retention claim.
const BrowseMode = "retained-v1"
const BrowseContract = "tracebolt.journal-browse.v1"
const SchemaVersionV2 = "tracebolt.journal-content.v2"
const MaxCursorBytes = 1024
const MaxSearchBytes = 200
const ReasonCursorUnavailable Reason = "cursor_unavailable"

func validSearch(s string) bool {
	return len(s) <= MaxSearchBytes && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func ValidCursor(s string) bool {
	if len(s) == 0 || len(s) > MaxCursorBytes {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '=' || c == ';' || c == '_' || c == '-') {
			return false
		}
	}
	return strings.Contains(s, "=")
}
func validSnapshotMode(s Snapshot) bool {
	if s.Query.BrowseMode == "" {
		return s.SchemaVersion == SchemaVersion && s.NextCursor == "" && !s.Exhausted
	}
	if s.Query.BrowseMode != BrowseMode || s.SchemaVersion != SchemaVersionV2 || s.NextCursor != "" && !ValidCursor(s.NextCursor) {
		return false
	}
	if s.Coverage == Failed && s.NextCursor != "" {
		return false
	}
	if s.Exhausted {
		return s.NextCursor == "" && s.Coverage == Complete
	}
	return s.Coverage != Complete && (s.NextCursor == "" || s.NextCursor != s.Query.Cursor)
}

// decodeCursor rejects duplicate or nonstring locators before they can be
// reused. A journal locator is bounded public navigation metadata, never a
// command, path, authentication token, or evidence of past retention.
func decodeCursor(line []byte) (string, error) {
	d := json.NewDecoder(bytes.NewReader(line))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return "", ErrInvalidSnapshot
	}
	cursor := ""
	seen := false
	for d.More() {
		t, e = d.Token()
		if e != nil {
			return "", ErrInvalidSnapshot
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return "", ErrInvalidSnapshot
		}
		if t == "__CURSOR" {
			if seen || json.Unmarshal(raw, &cursor) != nil || !ValidCursor(cursor) {
				return "", ErrInvalidSnapshot
			}
			seen = true
		}
	}
	if _, e = d.Token(); e != nil || !seen {
		return "", ErrInvalidSnapshot
	}
	if _, e = d.Token(); e != io.EOF {
		return "", ErrInvalidSnapshot
	}
	return cursor, nil
}

func parseBrowse(ctx context.Context, q Query, now time.Time, input io.Reader, sourceReason Reason) (Snapshot, error) {
	s := empty(q, now)
	s.SchemaVersion = SchemaVersionV2
	raw := &io.LimitedReader{R: input, N: MaxRawBytes + 1}
	scan := bufio.NewScanner(raw)
	scan.Buffer(make([]byte, MaxLineBytes+1), MaxLineBytes+1)
	scanned, rowBytes := 0, 0
	last := ""
	anchor := q.Cursor == ""
	needle := strings.ToLower(q.Search)
	stop := func(reason Reason) Snapshot {
		s = mark(s, reason)
		if last != "" && last != q.Cursor {
			s.NextCursor = last
			s.Coverage = Partial
		}
		return s
	}
	for scan.Scan() {
		if ctx.Err() != nil {
			return stop(ReasonTimeout), nil
		}
		if raw.N == 0 || len(scan.Bytes()) > MaxLineBytes {
			return stop(ReasonByteLimit), nil
		}
		cursor, e := decodeCursor(scan.Bytes())
		if e != nil {
			return stop(ReasonInvalidSource), nil
		}
		// journalctl can seek to a nearby record when vacuum/rotation removed the
		// requested cursor. Require the exact first anchor, never silently skip.
		if !anchor {
			if cursor != q.Cursor {
				return mark(s, ReasonCursorUnavailable), nil
			}
			anchor = true
			last = cursor
			continue
		}
		if cursor == last {
			return stop(ReasonInvalidSource), nil
		}
		if scanned == MaxScannedRows {
			return stop(ReasonItemLimit), nil
		}
		scanned++
		row, reason := decodeLine(scan.Bytes(), q.Unit)
		if reason != ReasonNone {
			// A bounded, syntactically valid locator permits moving past one
			// unprojectable entry. Mark an explicit gap; never label it exhausted.
			last = cursor
			return stop(reason), nil
		}
		if row.Unit != q.Unit || row.Timestamp.Before(q.Start) || row.Timestamp.After(q.End) || row.Priority > q.MaxPriority {
			last = cursor
			continue
		}
		message, changed := redact(row.Message)
		row.Message = message
		if !strings.Contains(strings.ToLower(message), needle) {
			last = cursor
			continue
		}
		if len(s.Rows) == MaxRows {
			return stop(ReasonItemLimit), nil
		}
		encoded, e := json.Marshal(row)
		if e != nil {
			return stop(ReasonInvalidSource), nil
		}
		if len(message) > MaxMessageBytes {
			// Masking can expand an otherwise legal source message beyond the
			// projection budget. This row cannot fit any page: retain an explicit
			// gap and advance its validated locator so older entries stay reachable.
			last = cursor
			return stop(ReasonByteLimit), nil
		}
		if len(encoded)+1 > MaxSnapshotBytes-metadataReserve-2*MaxCursorBytes-rowBytes {
			// This row can fit a fresh page. Keep the last accepted locator so
			// the next page retries it rather than silently dropping its content.
			return stop(ReasonByteLimit), nil
		}
		s.Rows = append(s.Rows, row)
		s.ObservedCount++
		s.RedactionApplied = s.RedactionApplied || changed
		rowBytes += len(encoded) + 1
		last = cursor
	}
	if !anchor {
		return mark(s, ReasonCursorUnavailable), nil
	}
	if ctx.Err() != nil {
		return stop(ReasonTimeout), nil
	}
	if raw.N == 0 {
		return stop(ReasonByteLimit), nil
	}
	if e := scan.Err(); e != nil {
		if errors.Is(e, bufio.ErrTooLong) {
			return stop(ReasonByteLimit), nil
		}
		return stop(failureReason(e)), nil
	}
	if sourceReason != ReasonNone {
		return stop(sourceReason), nil
	}
	s.Exhausted = true
	return s, nil
}
