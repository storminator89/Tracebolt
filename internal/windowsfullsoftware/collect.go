package windowsfullsoftware

import (
	"context"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf16"
)

const MaxNativeWork = 128 << 20

// Every read/query/open operation is bounded too, including empty/failed
// reads. Handle closure is mandatory cleanup, bounded by successful opens.
const MaxNativeCalls = MaxRows*8 + 32
const NativeValueBytes = (MaxFieldUTF16 + 1) * 2

var (
	ErrDenied      = errors.New("windows_full_software_access_denied")
	ErrUnsupported = errors.New("windows_full_software_unsupported")
	ErrChanged     = errors.New("windows_full_software_source_changed")
)

type viewStamp struct {
	count    uint32
	modified uint64
}
type nativeRegistration struct {
	key                      []uint16
	name, version, publisher *string
}
type registryView interface {
	stamp(context.Context) (viewStamp, error)
	next(context.Context, uint32) (nativeRegistration, bool, error)
	close() error
}
type openView func(context.Context, string, *nativeBudget) (registryView, error)
type nativeBudget struct{ calls, bytes int }

func (b *nativeBudget) charge(bytes int) error {
	if bytes < 0 || bytes > MaxNativeWork || b.calls >= MaxNativeCalls || b.bytes > MaxNativeWork-bytes {
		return ErrBudget
	}
	b.calls++
	b.bytes += bytes
	return nil
}
func decodeUTF16(v []uint16) (string, bool) {
	for i := 0; i < len(v); i++ {
		u := v[i]
		if u == 0 {
			return "", false
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 >= len(v) || v[i+1] < 0xdc00 || v[i+1] > 0xdfff {
				return "", false
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", false
		}
	}
	return string(utf16.Decode(v)), true
}

// REG_SZ only: no expansion, allocations based on advertised length, embedded
// NUL, malformed surrogate repair, or truncation of an oversized optional value.
func decodeRegistryValue(kind uint32, raw []byte) *string {
	if kind != 1 || len(raw) < 2 || len(raw) > NativeValueBytes || len(raw)%2 != 0 || raw[len(raw)-2] != 0 || raw[len(raw)-1] != 0 {
		return nil
	}
	units := make([]uint16, len(raw)/2-1)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	value, ok := decodeUTF16(units)
	if !ok || !validText(value, true) {
		return nil
	}
	return &value
}

// collectRegistry owns one synchronous, bounded two-view enumeration. The seam
// is used by inert fixtures; native handles never escape their owning thread.
func collectRegistry(parent context.Context, open openView, now func() time.Time) (Capture, error) {
	if parent == nil || open == nil || now == nil {
		return Capture{}, ErrInvalid
	}
	start := now().UTC()
	out := Capture{StartedAt: start, Rows: []Row{}}
	fail := func(e error) (Capture, error) {
		out.Rows = []Row{}
		out.FinishedAt = now().UTC()
		switch {
		case errors.Is(e, ErrDenied):
			out.Reason = "access_denied"
		case errors.Is(e, ErrUnsupported):
			out.Reason = "unsupported"
		case errors.Is(e, ErrChanged):
			out.Reason = "source_changed"
		case errors.Is(e, ErrBudget):
			out.Reason = "resource_limit"
		case errors.Is(e, ErrInvalid):
			out.Reason = "malformed_source"
		case errors.Is(e, context.DeadlineExceeded):
			out.Reason = "deadline"
		case errors.Is(e, context.Canceled):
			out.Reason = "canceled"
		default:
			out.Reason = "unavailable"
		}
		return out, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, CaptureTimeout)
	defer cancel()
	check := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		t := now().UTC()
		if t.Before(start) {
			return ErrInvalid
		}
		if t.Sub(start) > CaptureTimeout {
			return context.DeadlineExceeded
		}
		return nil
	}
	budget := &nativeBudget{}
	seen := map[string]bool{}
	encoded := 2
	for _, view := range []string{"64", "32"} {
		if e := check(); e != nil {
			return fail(e)
		}
		source, e := open(ctx, view, budget)
		if e != nil {
			return fail(e)
		}
		// Missing root is positive evidence of no registrations in this view.
		if source == nil {
			continue
		}
		e = func() error {
			defer source.close()
			before, e := source.stamp(ctx)
			if e != nil {
				return e
			}
			if uint64(before.count) > uint64(MaxRows-len(out.Rows)) {
				return ErrBudget
			}
			for index := uint32(0); ; index++ {
				if e := check(); e != nil {
					return e
				}
				item, done, e := source.next(ctx, index)
				if e != nil {
					return e
				}
				if e = check(); e != nil {
					return e
				}
				if done {
					if index != before.count {
						return ErrChanged
					}
					break
				}
				if index >= before.count {
					return ErrChanged
				}
				if len(out.Rows) >= MaxRows {
					return ErrBudget
				}
				id, e := RegistrationID(view, item.key)
				if e != nil {
					return e
				}
				if seen[id] {
					return ErrChanged
				}
				seen[id] = true
				row := Row{RegistrationID: id, RegistryView: view, Name: item.name, Version: item.version, Publisher: item.publisher, NameQuality: "unavailable", VersionQuality: "unavailable", PublisherQuality: "unavailable"}
				if row.Name != nil {
					row.NameQuality = "observed"
				}
				if row.Version != nil {
					row.VersionQuality = "observed"
				}
				if row.Publisher != nil {
					row.PublisherQuality = "observed"
				}
				if ValidateRow(row) != nil {
					return ErrInvalid
				}
				raw, _ := json.Marshal(row)
				encoded += len(raw)
				if len(out.Rows) > 0 {
					encoded++
				}
				if encoded > MaxSourceBytes {
					return ErrBudget
				}
				out.Rows = append(out.Rows, row)
			}
			after, e := source.stamp(ctx)
			if e != nil {
				return e
			}
			if before != after {
				return ErrChanged
			}
			return check()
		}()
		if e != nil {
			return fail(e)
		}
	}
	if e := check(); e != nil {
		return fail(e)
	}
	out.FinishedAt = now().UTC()
	out.Complete = true
	return out, nil
}
