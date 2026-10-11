package windowsfullprocesses

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

// One OS-owned Toolhelp snapshot and one fixed PROCESSENTRY32 buffer are used.
// Windows controls its snapshot allocation; these bounds cover caller-owned
// buffers/rows and native API calls, not that opaque OS allocation.
const NativeNameUnits = 260
const NativeEntryWorkBytes = 1024  // exceeds both supported PROCESSENTRY32 layouts
const MaxNativeReads = MaxRows + 1 // one end-of-enumeration probe at the row ceiling
const MaxNativeWork = MaxNativeReads * NativeEntryWorkBytes

var ErrDenied = errors.New("windows_full_processes_access_denied")
var ErrUnsupported = errors.New("windows_full_processes_unsupported")

type nativeEntry struct {
	pid       uint32
	parentPID uint32
	threads   uint32
	name      [NativeNameUnits]uint16
}
type processSnapshot interface {
	// next returns done only for ERROR_NO_MORE_FILES; other errors fail capture.
	next(context.Context) (entry nativeEntry, done bool, err error)
	close()
}
type openSnapshot func(context.Context) (processSnapshot, error)

func nativeName(values [NativeNameUnits]uint16) *string {
	end := -1
	for i, v := range values {
		if v == 0 {
			end = i
			break
		}
	}
	if end <= 0 {
		return nil
	}
	units := values[:end]
	for i := 0; i < len(units); i++ {
		v := units[i]
		if v >= 0xD800 && v <= 0xDBFF {
			if i+1 >= len(units) || units[i+1] < 0xDC00 || units[i+1] > 0xDFFF {
				return nil
			}
			i++
		} else if v >= 0xDC00 && v <= 0xDFFF {
			return nil
		}
	}
	value := string(utf16.Decode(units))
	if !validText(value, false) || strings.ContainsAny(value, `/\`) {
		return nil
	}
	return &value
}

// collectSnapshot exhausts a single fixed snapshot. No process handle is opened
// and no PID from another capture/metrics sample is joined to these identifiers.
// Every failed attempt discards its prefix, preserving the prior complete view.
func collectSnapshot(parent context.Context, open openSnapshot, now func() time.Time) (Capture, error) {
	if parent == nil || open == nil || now == nil {
		return Capture{}, ErrInvalid
	}
	start := now().UTC()
	out := Capture{StartedAt: start, Rows: []Row{}}
	fail := func(reason string) (Capture, error) {
		out.FinishedAt = now().UTC()
		out.Rows = []Row{}
		out.Reason = reason
		return out, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, CaptureTimeout)
	defer cancel()
	check := func() string {
		if e := ctx.Err(); e != nil {
			if errors.Is(e, context.DeadlineExceeded) {
				return "deadline"
			}
			return "canceled"
		}
		at := now().UTC()
		if at.Before(start) {
			return "malformed_source"
		}
		if at.Sub(start) > CaptureTimeout {
			return "deadline"
		}
		return ""
	}
	reason := func(e error) string {
		switch {
		case errors.Is(e, ErrBudget):
			return "resource_limit"
		case errors.Is(e, ErrDenied):
			return "access_denied"
		case errors.Is(e, ErrUnsupported):
			return "unsupported"
		case errors.Is(e, ErrInvalid):
			return "malformed_source"
		case errors.Is(e, context.DeadlineExceeded):
			return "deadline"
		case errors.Is(e, context.Canceled):
			return "canceled"
		default:
			return "unavailable"
		}
	}
	if r := check(); r != "" {
		return fail(r)
	}
	snapshot, e := open(ctx)
	if snapshot != nil {
		defer snapshot.close()
	}
	if r := check(); r != "" {
		return fail(r)
	}
	if e != nil {
		return fail(reason(e))
	}
	if snapshot == nil {
		return fail("malformed_source")
	}
	seen := make(map[uint32]bool)
	encoded := 2
	for calls := 0; calls < MaxNativeReads; calls++ {
		if r := check(); r != "" {
			return fail(r)
		}
		entry, done, e := snapshot.next(ctx)
		if r := check(); r != "" {
			return fail(r)
		}
		if e != nil {
			return fail(reason(e))
		}
		if done {
			sort.Slice(out.Rows, func(i, j int) bool { return out.Rows[i].PID < out.Rows[j].PID })
			out.FinishedAt = now().UTC()
			if out.FinishedAt.Before(start) {
				return fail("malformed_source")
			}
			if out.FinishedAt.Sub(start) > CaptureTimeout {
				return fail("deadline")
			}
			out.Complete = true
			return out, nil
		}
		if len(out.Rows) >= MaxRows {
			return fail("resource_limit")
		}
		if seen[entry.pid] {
			return fail("source_changed")
		}
		seen[entry.pid] = true
		row := Row{PID: entry.pid, ParentPID: entry.parentPID, Threads: entry.threads, Name: nativeName(entry.name), NameQuality: "unavailable"}
		if row.Name != nil {
			row.NameQuality = "observed"
		}
		if ValidateRow(row) != nil {
			return fail("malformed_source")
		}
		raw, _ := json.Marshal(row)
		encoded += len(raw)
		if len(out.Rows) > 0 {
			encoded++
		}
		if encoded > MaxSourceBytes {
			return fail("resource_limit")
		}
		out.Rows = append(out.Rows, row)
	}
	return fail("resource_limit")
}
