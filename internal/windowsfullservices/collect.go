package windowsfullservices

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

const NativePageBytes = 256 << 10
const MaxNativePages = 256
const MaxNativeWork = 64 << 20

var ErrDenied = errors.New("windows_full_services_access_denied")
var ErrUnsupported = errors.New("windows_full_services_unsupported")

type enumerationPage struct {
	rows      []Row
	next      uint32
	more      bool
	workBytes int
}
type enumerate func(context.Context, uint32) (enumerationPage, error)

// collectPages is synchronous and owns the bounded resume loop. Resume handles
// are opaque tokens, not increasing counters. A cooperative deadline cannot
// interrupt an in-flight native API, so no abandoned goroutine is created.
func collectPages(parent context.Context, read enumerate, now func() time.Time) (Capture, error) {
	if parent == nil || read == nil || now == nil {
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
	seenTokens := map[uint32]bool{0: true}
	seenNames := map[string]bool{}
	resume := uint32(0)
	work, encoded := 0, 2
	for calls := 0; calls < MaxNativePages; calls++ {
		if e := ctx.Err(); e != nil {
			if errors.Is(e, context.DeadlineExceeded) {
				return fail("deadline")
			}
			return fail("canceled")
		}
		page, e := read(ctx, resume)
		if e != nil {
			switch {
			case errors.Is(e, ErrDenied):
				return fail("access_denied")
			case errors.Is(e, ErrUnsupported):
				return fail("unsupported")
			case errors.Is(e, ErrInvalid):
				return fail("malformed_source")
			case errors.Is(e, context.DeadlineExceeded):
				return fail("deadline")
			case errors.Is(e, context.Canceled):
				return fail("canceled")
			default:
				return fail("unavailable")
			}
		}
		if e := ctx.Err(); e != nil {
			if errors.Is(e, context.DeadlineExceeded) {
				return fail("deadline")
			}
			return fail("canceled")
		}
		finish := now().UTC()
		if finish.Before(start) {
			return fail("malformed_source")
		}
		if finish.Sub(start) > CaptureTimeout {
			return fail("deadline")
		}
		if page.workBytes <= 0 || page.workBytes > NativePageBytes {
			return fail("malformed_source")
		}
		work += page.workBytes
		if work > MaxNativeWork || len(out.Rows)+len(page.rows) > MaxRows {
			return fail("resource_limit")
		}
		for _, r := range page.rows {
			if ValidateRow(r) != nil {
				return fail("malformed_source")
			}
			key := IdentityKey(r.Name)
			if seenNames[key] {
				return fail("source_changed")
			}
			seenNames[key] = true
			raw, _ := json.Marshal(r)
			encoded += len(raw)
			if len(out.Rows) > 0 {
				encoded++
			}
			if encoded > MaxSourceBytes {
				return fail("resource_limit")
			}
			out.Rows = append(out.Rows, r)
		}
		if !page.more {
			if page.next != 0 {
				return fail("malformed_source")
			}
			out.Complete = true
			out.FinishedAt = finish
			return out, nil
		}
		if len(page.rows) == 0 || page.next == 0 || seenTokens[page.next] {
			return fail("source_changed")
		}
		seenTokens[page.next] = true
		resume = page.next
	}
	return fail("resource_limit")
}
