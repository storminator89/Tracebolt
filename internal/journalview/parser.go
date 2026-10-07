package journalview

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Parse consumes only bounded synthetic/provided JSON-lines data. Unknown
// metadata is discarded. Source order and duplicate observations are preserved.
func Parse(ctx context.Context, q Query, now time.Time, input io.Reader) (Snapshot, error) {
	return parse(ctx, q, now, input, ReasonNone)
}
func parse(ctx context.Context, q Query, now time.Time, input io.Reader, sourceReason Reason) (Snapshot, error) {
	if ctx == nil || input == nil || ValidateQuery(q, now) != nil {
		return Snapshot{}, ErrInvalidInput
	}
	if q.BrowseMode == BrowseMode {
		return parseBrowse(ctx, q, now, input, sourceReason)
	}
	s := empty(q, now)
	if ctx.Err() != nil {
		return mark(s, ReasonTimeout), nil
	}
	// The extra byte is a bounded sentinel; it is never retained/exported.
	raw := &io.LimitedReader{R: input, N: MaxRawBytes + 1}
	scan := bufio.NewScanner(raw)
	scan.Buffer(make([]byte, MaxLineBytes+1), MaxLineBytes+1)
	scanned, rowBytes := 0, 0
	for scan.Scan() {
		if ctx.Err() != nil {
			return mark(s, ReasonTimeout), nil
		}
		if raw.N == 0 || len(scan.Bytes()) > MaxLineBytes {
			return mark(s, ReasonByteLimit), nil
		}
		if scanned == MaxScannedRows {
			return mark(s, ReasonItemLimit), nil
		}
		scanned++
		row, reason := decodeLine(scan.Bytes(), q.Unit)
		if reason != ReasonNone {
			// A byte-limited command can finish with a cut JSON line. Its explicit
			// truncation dominates that final parse error; no bytes from it survive.
			if sourceReason == ReasonByteLimit {
				reason = ReasonByteLimit
			}
			return mark(s, reason), nil
		}
		if row.Unit != q.Unit || row.Timestamp.Before(q.Start) || row.Timestamp.After(q.End) || row.Priority > q.MaxPriority {
			continue
		}
		s.ObservedCount++
		if len(s.Rows) == MaxRows {
			return mark(s, ReasonItemLimit), nil
		}
		message, changed := redact(row.Message)
		if len(message) > MaxMessageBytes {
			return mark(s, ReasonByteLimit), nil
		}
		row.Message = message
		encoded, e := json.Marshal(row) // a single already size-checked row only
		if e != nil {
			return mark(s, ReasonInvalidSource), nil
		}
		if len(encoded)+1 > MaxSnapshotBytes-metadataReserve-rowBytes {
			return mark(s, ReasonByteLimit), nil
		}
		rowBytes += len(encoded) + 1
		s.Rows = append(s.Rows, row)
		s.RedactionApplied = s.RedactionApplied || changed
	}
	if ctx.Err() != nil {
		return mark(s, ReasonTimeout), nil
	}
	if raw.N == 0 {
		return mark(s, ReasonByteLimit), nil
	}
	if err := scan.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return mark(s, ReasonByteLimit), nil
		}
		return mark(s, failureReason(err)), nil
	}
	if sourceReason != ReasonNone {
		return mark(s, sourceReason), nil
	}
	return s, nil
}

func decodeLine(line []byte, selectedUnit string) (Row, Reason) {
	var serviceUnit, managerUnit, pid, uid string
	var row Row
	if !utf8.Valid(line) {
		return row, ReasonInvalidSource
	}
	d := json.NewDecoder(bytes.NewReader(line))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return row, ReasonInvalidSource
	}
	seen := map[string]bool{}
	fields := 0
	for d.More() {
		fields++
		if fields > 128 {
			return row, ReasonItemLimit
		}
		tok, e := d.Token()
		if e != nil {
			return row, ReasonInvalidSource
		}
		key, ok := tok.(string)
		if !ok {
			return row, ReasonInvalidSource
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return row, ReasonInvalidSource
		}
		switch key {
		case "__REALTIME_TIMESTAMP", "_SYSTEMD_UNIT", "_PID", "_UID", "UNIT", "PRIORITY", "MESSAGE":
			if seen[key] {
				return row, ReasonInvalidSource
			}
			seen[key] = true
			max := MaxUnitBytes
			if key == "MESSAGE" {
				max = MaxMessageBytes
			}
			if key == "__REALTIME_TIMESTAMP" {
				max = 18
			}
			if key == "_PID" || key == "_UID" {
				max = 10
			}
			if key == "PRIORITY" {
				max = 1
			}
			if len(raw) > 6*max+2 {
				return row, ReasonByteLimit
			}
			var value string
			if len(raw) < 2 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil || !utf8.ValidString(value) {
				return row, ReasonInvalidSource
			}
			if len(value) > max {
				return row, ReasonByteLimit
			}
			switch key {
			case "__REALTIME_TIMESTAMP":
				if len(value) == 0 || len(value) > 18 || len(value) > 1 && value[0] == '0' {
					return row, ReasonInvalidSource
				}
				for _, c := range value {
					if c < '0' || c > '9' {
						return row, ReasonInvalidSource
					}
				}
				us, e := strconv.ParseInt(value, 10, 64)
				if e != nil {
					return row, ReasonInvalidSource
				}
				row.Timestamp = time.UnixMicro(us).UTC()
				if !validUTC(row.Timestamp) {
					return row, ReasonInvalidSource
				}
			case "_SYSTEMD_UNIT", "UNIT":
				// PID1 may itself belong to init.scope. These bounded identity strings
				// are compared exactly; they are never trusted as the DTO's unit name.
				if value == "" || strings.ContainsAny(value, "\x00\r\n") {
					return row, ReasonInvalidSource
				}
				if key == "_SYSTEMD_UNIT" {
					serviceUnit = value
				} else {
					managerUnit = value
				}
			case "_PID", "_UID":
				if !validNumericIdentity(value, key == "_PID") {
					return row, ReasonInvalidSource
				}
				if key == "_PID" {
					pid = value
				} else {
					uid = value
				}
			case "PRIORITY":
				if len(value) != 1 || value[0] < '0' || value[0] > '7' {
					return row, ReasonInvalidSource
				}
				row.Priority = int(value[0] - '0')
			case "MESSAGE":
				row.Message = value
			}
		}
	}
	if t, e := d.Token(); e != nil || t != json.Delim('}') {
		return row, ReasonInvalidSource
	}
	if !seen["__REALTIME_TIMESTAMP"] || !seen["PRIORITY"] || !seen["MESSAGE"] || !seen["_SYSTEMD_UNIT"] && !seen["UNIT"] {
		return row, ReasonInvalidSource
	}
	if _, e := d.Token(); e != io.EOF {
		return row, ReasonInvalidSource
	}
	// Only these two reviewed branches can attribute a row to the query.
	// Application-provided UNIT alone is never enough; manager attribution
	// additionally requires journald's trusted PID 1 and UID 0 singleton fields.
	if serviceUnit == selectedUnit || pid == "1" && uid == "0" && managerUnit == selectedUnit {
		row.Unit = selectedUnit
	}
	return row, ReasonNone
}
func validNumericIdentity(s string, pid bool) bool {
	if len(s) == 0 || len(s) > 1 && s[0] == '0' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	bits := 32
	if pid {
		bits = 31
	}
	n, e := strconv.ParseUint(s, 10, bits)
	return e == nil && (!pid || n > 0)
}

// Encode validates allowlisted values and checks each bounded row before the
// final body allocation. Callers must use this rather than marshal arbitrary
// externally constructed snapshots. No cursor or raw metadata is represented.
func Encode(s Snapshot) ([]byte, error) {
	if !validSnapshotMode(s) || s.Scope != Scope || ValidateQuery(s.Query, s.ObservedAt) != nil || s.RedactionWarning != RedactionWarning || s.Rows == nil || len(s.Rows) > MaxRows || s.ObservedCount > MaxScannedRows || s.ObservedCount < uint64(len(s.Rows)) || !validReason(s.Reason) {
		return nil, ErrInvalidSnapshot
	}
	switch s.Coverage {
	case Complete:
		if s.Reason != ReasonNone || !s.CountExact || s.ObservedCount != uint64(len(s.Rows)) {
			return nil, ErrInvalidSnapshot
		}
	case Partial:
		if s.Reason == ReasonNone || s.CountExact {
			return nil, ErrInvalidSnapshot
		}
	case Failed:
		if s.Reason == ReasonNone || s.CountExact || len(s.Rows) != 0 || s.ObservedCount != 0 || s.RedactionApplied {
			return nil, ErrInvalidSnapshot
		}
	default:
		return nil, ErrInvalidSnapshot
	}
	size := metadataReserve
	for _, r := range s.Rows {
		if !validUTC(r.Timestamp) || r.Timestamp.Before(s.Query.Start) || r.Timestamp.After(s.Query.End) || r.Unit != s.Query.Unit || r.Priority < 0 || r.Priority > s.Query.MaxPriority || len(r.Message) > MaxMessageBytes || !utf8.ValidString(r.Message) {
			return nil, ErrInvalidSnapshot
		}
		b, e := json.Marshal(r)
		if e != nil {
			return nil, ErrInvalidSnapshot
		}
		size += len(b) + 1
		if size > MaxSnapshotBytes {
			return nil, ErrSourceLimit
		}
	}
	b, e := json.Marshal(s)
	if e != nil {
		return nil, ErrInvalidSnapshot
	}
	if len(b) > MaxSnapshotBytes {
		return nil, ErrSourceLimit
	}
	return b, nil
}
