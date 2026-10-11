package windowssessions

import (
	"context"
	"encoding/binary"
	"errors"
	"sort"
	"unicode/utf16"
)

type SessionsSource func(context.Context) (Sessions, error)
type JoinSource func(context.Context) (Join, error)

func CollectWithSources(ctx context.Context, r Request, sessions SessionsSource, join JoinSource) (Snapshot, error) {
	if ctx == nil {
		return Snapshot{}, ErrInvalid
	}
	if _, e := EncodeConsent(r.Consent, r.SenderBinding); e != nil {
		return Snapshot{}, e
	}
	if !r.Consent.Enabled {
		return Snapshot{}, ErrDisabled
	}
	s := Empty(r, ErrUnavailable.Error())
	if Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if sessions != nil {
		v, e := sessions(ctx)
		if e != nil {
			v = EmptySessions(SafeReason(e))
		}
		if !validSessions(v) {
			v = EmptySessions(ErrMetadata.Error())
		}
		s.Sessions = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if join != nil {
		v, e := join(ctx)
		if e != nil {
			v = EmptyJoin(SafeReason(e))
		}
		if !validJoin(v) {
			v = EmptyJoin(ErrMetadata.Error())
		}
		s.Join = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	return FitBudget(s, MaxBytes)
}
func SafeReason(e error) string {
	switch {
	case errors.Is(e, ErrDenied):
		return ErrDenied.Error()
	case errors.Is(e, ErrUnsupported):
		return ErrUnsupported.Error()
	case errors.Is(e, ErrMetadata):
		return ErrMetadata.Error()
	case errors.Is(e, ErrBounds):
		return ErrBounds.Error()
	case errors.Is(e, ErrPartial):
		return ErrPartial.Error()
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded), errors.Is(e, ErrBudget):
		return ErrBudget.Error()
	default:
		return ErrUnavailable.Error()
	}
}

// Exact returned-byte buffers only. A terminator must be in-bounds; malformed
// UTF-16 is never silently repaired into a personal label.
func decodeLabel(raw []byte, maxUnits int) (*string, error) {
	if len(raw) < 2 || len(raw)%2 != 0 {
		return nil, ErrMetadata
	}
	if len(raw) > 2*(maxUnits+1) {
		return nil, ErrBounds
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	end := -1
	for i, u := range units {
		if u == 0 {
			end = i
			break
		}
	}
	if end < 0 {
		return nil, ErrMetadata
	}
	for _, u := range units[end:] {
		if u != 0 {
			return nil, ErrMetadata
		}
	}
	if end == 0 {
		return nil, nil
	}
	units = units[:end]
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return nil, ErrMetadata
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return nil, ErrMetadata
		}
	}
	value := string(utf16.Decode(units))
	if !validLabel(value, maxUnits) {
		return nil, ErrMetadata
	}
	return &value, nil
}
func sessionState(n uint32) string {
	states := []string{"active", "connected", "connect-query", "shadow", "disconnected", "idle", "listen", "reset", "down", "init"}
	if n < uint32(len(states)) {
		return states[n]
	}
	return "unknown"
}
func sessionProtocol(raw []byte) string {
	if len(raw) != 2 {
		return "unknown"
	}
	switch binary.LittleEndian.Uint16(raw) {
	case 0:
		return "console"
	case 2:
		return "rdp"
	}
	return "unknown"
}

type nativeSession struct{ ID, State uint32 }

// Sort only bounded numeric metadata; labels are queried only for retained IDs.
func selectSessions(rows []nativeSession) ([]nativeSession, error) {
	if len(rows) > MaxNativeSessions {
		return nil, ErrBounds
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	for i := 1; i < len(rows); i++ {
		if rows[i].ID == rows[i-1].ID {
			return nil, ErrMetadata
		}
	}
	if len(rows) > MaxRows {
		rows = rows[:MaxRows]
	}
	return rows, nil
}
func finishSessions(s Sessions) Sessions {
	s.RetainedCount = uint32(len(s.Rows))
	if s.ObservedCount == nil {
		return EmptySessions(ErrMetadata.Error())
	}
	n := *s.ObservedCount - s.RetainedCount
	s.TruncatedCount = &n
	partial := n > 0
	for _, r := range s.Rows {
		partial = partial || r.UserQuality == "denied" || r.UserQuality == "unavailable" || r.DomainQuality == "denied" || r.DomainQuality == "unavailable" || r.Protocol == "unknown" || r.State == "unknown"
	}
	s.Quality = "observed"
	s.Reason = ""
	if partial {
		s.Quality = "partial"
		s.Reason = ErrPartial.Error()
		if n > 0 {
			s.Reason = ErrBounds.Error()
		}
	}
	return s
}
