package windowsnetworkcontext

import (
	"context"
	"errors"
	"time"
	"unicode/utf16"
)

var ErrDenied = errors.New("windows_network_context_access_denied")
var ErrUnsupported = errors.New("windows_network_context_unsupported")

type tableSource interface {
	routes(context.Context) ([]Row, error)
	interfaces(context.Context) ([]Row, error)
}

func nativeAlias(values []uint16) *string {
	end := -1
	for i, v := range values {
		if v == 0 {
			end = i
			break
		}
	}
	if end <= 0 || end > MaxFieldUTF16 {
		return nil
	}
	units := values[:end]
	for i := 0; i < len(units); i++ {
		v := units[i]
		if v >= 0xd800 && v <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return nil
			}
			i++
		} else if v >= 0xdc00 && v <= 0xdfff {
			return nil
		}
	}
	value := string(utf16.Decode(units))
	if !validText(value, false) {
		return nil
	}
	return &value
}

// The two tables are sampled sequentially. No interface-index join is made;
// both must finish within bounds before the combined generation is complete.
func collectTables(parent context.Context, source tableSource, now func() time.Time) (Capture, error) {
	if parent == nil || source == nil || now == nil {
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
	check := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		at := now().UTC()
		if at.Before(start) {
			return ErrInvalid
		}
		if at.Sub(start) > CaptureTimeout {
			return context.DeadlineExceeded
		}
		return nil
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
	for _, kind := range []string{"route", "interface"} {
		if e := check(); e != nil {
			return fail(reason(e))
		}
		var rows []Row
		var e error
		if kind == "route" {
			rows, e = source.routes(ctx)
		} else {
			rows, e = source.interfaces(ctx)
		}
		if ce := check(); ce != nil {
			return fail(reason(ce))
		}
		if e != nil {
			return fail(reason(e))
		}
		limit := MaxRoutes
		if kind == "interface" {
			limit = MaxInterfaces
		}
		if len(rows) > limit {
			return fail("resource_limit")
		}
		for _, row := range rows {
			if e := check(); e != nil {
				return fail(reason(e))
			}
			row.ID = uint32(len(out.Rows) + 1)
			if row.Kind != kind || ValidateRow(row) != nil {
				return fail("malformed_source")
			}
			out.Rows = append(out.Rows, row)
		}
	}
	if _, _, e := RowsDigest(out.Rows); e != nil {
		return fail(reason(e))
	}
	if e := check(); e != nil {
		return fail(reason(e))
	}
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
