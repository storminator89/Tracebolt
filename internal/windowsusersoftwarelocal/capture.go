package windowsusersoftwarelocal

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"localrmm/internal/windowsusersoftware"
	"sort"
	"time"
	"unicode/utf16"
)

var errChanged = errors.New("source_changed")
var errMalformed = errors.New("malformed_source")

type sourceReader func(context.Context) ([]windowsusersoftware.Row, error)

func failureStatus(e error) string {
	switch {
	case errors.Is(e, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(e, context.Canceled):
		return "canceled"
	case errors.Is(e, windowsusersoftware.ErrBudget):
		return "resource_limit"
	case errors.Is(e, windowsusersoftware.ErrDenied):
		return "access_denied"
	case errors.Is(e, windowsusersoftware.ErrUnsupported):
		return "unsupported"
	case errors.Is(e, errChanged):
		return "source_changed"
	case errors.Is(e, errMalformed), errors.Is(e, windowsusersoftware.ErrInvalid):
		return "malformed_source"
	default:
		return "unavailable"
	}
}
func boundedRows(rows []windowsusersoftware.Row) ([]byte, error) {
	if rows == nil || len(rows) > windowsusersoftware.MaxRows {
		return nil, windowsusersoftware.ErrBudget
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].RegistrationID < rows[j].RegistrationID })
	if _, _, e := windowsusersoftware.RowsDigest(rows); e != nil {
		return nil, e
	}
	b, e := json.Marshal(rows)
	if e != nil || len(b) > windowsusersoftware.MaxSourceBytes {
		return nil, windowsusersoftware.ErrBudget
	}
	return b, nil
}

// Two bounded enumerations detect changing registration sets and metadata. An
// API is not an atomic installed-app snapshot; equality is only checked-source
// consistency, not a claim that all installed software or portable apps exist.
func stableSource(ctx context.Context, read sourceReader) ([]windowsusersoftware.Row, string) {
	first, e := read(ctx)
	if e != nil {
		return nil, failureStatus(e)
	}
	a, e := boundedRows(first)
	if e != nil {
		return nil, failureStatus(e)
	}
	second, e := read(ctx)
	if e != nil {
		return nil, failureStatus(e)
	}
	b, e := boundedRows(second)
	if e != nil {
		return nil, failureStatus(e)
	}
	if !bytes.Equal(a, b) {
		return nil, "source_changed"
	}
	return first, "complete"
}
func collectSources(ctx context.Context, hkcu, msix sourceReader, start time.Time) windowsusersoftware.Capture {
	out := windowsusersoftware.Capture{StartedAt: start.UTC(), Rows: []windowsusersoftware.Row{}}
	h, hs := singleSource(ctx, hkcu)
	m, ms := stableSource(ctx, msix)
	out.HKCUStatus = hs
	out.MSIXStatus = ms
	out.Rows = append(out.Rows, h...)
	out.Rows = append(out.Rows, m...)
	if _, e := boundedRows(out.Rows); e != nil {
		out.Rows = []windowsusersoftware.Row{}
		out.HKCUStatus = "resource_limit"
		out.MSIXStatus = "resource_limit"
	}
	out.FinishedAt = time.Now().UTC()
	out.Complete = true
	if e := ctx.Err(); e != nil {
		out.Rows = []windowsusersoftware.Row{}
		out.Complete = false
		out.Reason = failureStatus(e)
	}
	return out
}
func decodeUTF16(v []uint16) (string, bool) {
	if len(v) > windowsusersoftware.MaxFieldUTF16 {
		return "", false
	}
	for i := 0; i < len(v); i++ {
		u := v[i]
		if u == 0 {
			return "", false
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 == len(v) || v[i+1] < 0xdc00 || v[i+1] > 0xdfff {
				return "", false
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", false
		}
	}
	return string(utf16.Decode(v)), true
}
func emptyRow(source, id string) windowsusersoftware.Row {
	return windowsusersoftware.Row{RegistrationID: id, Source: source, NameQuality: "unavailable", VersionQuality: "unavailable", PublisherQuality: "unavailable"}
}
func setField(target **string, quality *string, value *string) {
	if value != nil {
		*target = value
		*quality = "observed"
	}
}

func boundedRow(r windowsusersoftware.Row) ([]byte, error) {
	if windowsusersoftware.ValidateRow(r) != nil {
		return nil, errMalformed
	}
	return json.Marshal(r)
}

// HKCU is enumerated once; its adapter checks root and per-key timestamps.
func singleSource(ctx context.Context, read sourceReader) ([]windowsusersoftware.Row, string) {
	rows, e := read(ctx)
	if e != nil {
		return nil, failureStatus(e)
	}
	if _, e = boundedRows(rows); e != nil {
		return nil, failureStatus(e)
	}
	return rows, "complete"
}

// copyHString bounds before any native copy and decodes only the complete owned
// buffer. The caller retains its HSTRING until this function has returned.
func copyHString(address uintptr, length uint32, read func(uintptr, []byte) (uintptr, error)) (*string, error) {
	if length > windowsusersoftware.MaxFieldUTF16 || length > 0 && (address == 0 || read == nil) {
		return nil, errMalformed
	}
	var bytes [windowsusersoftware.MaxFieldUTF16 * 2]byte
	var units [windowsusersoftware.MaxFieldUTF16]uint16
	if length > 0 {
		size := int(length) * 2
		copied, err := read(address, bytes[:size])
		if err != nil {
			return nil, windowsusersoftware.ErrUnavailable
		}
		if copied != uintptr(size) {
			return nil, errMalformed
		}
		for i := 0; i < int(length); i++ {
			units[i] = binary.LittleEndian.Uint16(bytes[2*i : 2*i+2])
		}
	}
	text, ok := decodeUTF16(units[:length])
	if !ok {
		return nil, errMalformed
	}
	return &text, nil
}
