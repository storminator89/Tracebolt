package windowspatchcontext

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// All methods are synchronous. Only the owned isolated worker calls production
// sources; its process timeout bounds native calls which ignore cancellation.
type Source interface {
	SetOnline(context.Context, bool) error
	Online(context.Context) (bool, error)
	SetAutomaticUpgrade(context.Context, bool) error
	AutomaticUpgrade(context.Context) (bool, error)
	RebootRequired(context.Context) (bool, error)
	Total(context.Context) (int32, error)
	Query(context.Context, int32) (HistoryRows, error)
	Close()
}
type HistoryRows interface {
	Count(context.Context) (int32, error)
	Item(context.Context, int32) (Entry, error)
	Close()
}
type OpenSource func(context.Context) (Source, error)
type MachineSource func(context.Context) (OS, Reboot)

func CollectWithSources(ctx context.Context, req Request, open OpenSource, machine MachineSource) (Snapshot, error) {
	if ctx == nil || open == nil || machine == nil {
		return Snapshot{}, ErrInvalid
	}
	if _, e := EncodeConsent(req.Consent, req.SenderBinding); e != nil {
		return Snapshot{}, e
	}
	if !req.Consent.Enabled {
		return Snapshot{}, ErrDisabled
	}
	s := Empty(req, ErrUnavailable.Error())
	if Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	bounded, cancel := context.WithTimeout(ctx, CollectionBudget)
	defer cancel()
	finish := func(e error) (Snapshot, error) {
		if ctx.Err() != nil {
			return Snapshot{}, ctx.Err()
		}
		if e != nil {
			s.History.Reason = SafeReason(e)
			if s.History.Quality == "observed" {
				s.History.Quality = "partial"
			}
			if s.History.Quality == "unavailable" && errors.Is(e, ErrDenied) {
				s.History.Quality = "denied"
			}
		}
		s.History.Truncated = s.History.TotalCount > uint32(len(s.History.Rows))
		return fit(s, MaxBytes)
	}
	s.OS, s.Reboot = machine(bounded)
	source, e := open(bounded)
	if source != nil {
		defer source.Close()
	}
	if e != nil {
		return finish(e)
	}
	if source == nil {
		return finish(ErrUnavailable)
	}
	if e = source.SetOnline(bounded, false); e != nil {
		return finish(e)
	}
	online, e := source.Online(bounded)
	if e != nil {
		return finish(e)
	}
	if online {
		return finish(ErrOffline)
	}
	if e = source.SetAutomaticUpgrade(bounded, false); e != nil {
		return finish(e)
	}
	upgrade, e := source.AutomaticUpgrade(bounded)
	if e != nil {
		return finish(e)
	}
	if upgrade {
		return finish(ErrOffline)
	}
	reboot, e := source.RebootRequired(bounded)
	if e == nil {
		if reboot {
			s.Reboot.WindowsUpdate = "pending"
		} else {
			s.Reboot.WindowsUpdate = "clear"
		}
	} else if errors.Is(e, ErrDenied) {
		s.Reboot.WindowsUpdate = "denied"
	}
	total, e := source.Total(bounded)
	if e != nil {
		return finish(e)
	}
	if total < 0 {
		return finish(ErrMetadata)
	}
	s.History = History{Quality: "observed", CountExact: true, TotalCount: uint32(total), Rows: []Entry{}}
	if total == 0 {
		return finish(nil)
	}
	limit := total
	if limit > MaxRows {
		limit = MaxRows
	}
	rows, e := source.Query(bounded, limit)
	if rows != nil {
		defer rows.Close()
	}
	if e != nil {
		return finish(e)
	}
	if rows == nil {
		return finish(ErrUnavailable)
	}
	count, e := rows.Count(bounded)
	if e != nil {
		return finish(e)
	}
	if count < 0 || count > limit {
		return finish(ErrMetadata)
	}
	if count != limit {
		s.History.Quality = "partial"
		s.History.Reason = ErrPartial.Error()
		s.History.CountExact = false
		s.History.TotalCount = uint32(count)
	}
	for i := int32(0); i < count; i++ {
		if e = bounded.Err(); e != nil {
			return finish(e)
		}
		row, itemErr := rows.Item(bounded, i)
		if itemErr == nil {
			row.Index = uint32(i)
			row, itemErr = normalize(row)
			if itemErr == nil && (!validEntry(row, req.CollectedAt) || len(s.History.Rows) > 0 && s.History.Rows[len(s.History.Rows)-1].OccurredAt.Before(row.OccurredAt)) {
				itemErr = ErrMetadata
			}
		}
		if itemErr != nil {
			s.History.Quality = "partial"
			s.History.Reason = SafeReason(itemErr)
			continue
		}
		s.History.Rows = append(s.History.Rows, row)
	}
	after, e := source.Total(bounded)
	if e != nil || after != total {
		s.History.Quality = "partial"
		s.History.Reason = ErrPartial.Error()
		s.History.CountExact = false
		s.History.TotalCount = uint32(count)
	}
	return finish(nil)
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
	case errors.Is(e, ErrOffline):
		return ErrOffline.Error()
	case errors.Is(e, ErrPartial):
		return ErrPartial.Error()
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded), errors.Is(e, ErrBudget):
		return ErrBudget.Error()
	default:
		return ErrUnavailable.Error()
	}
}
func normalize(row Entry) (Entry, error) {
	if len(row.Title) > 8192 || !utf8.ValidString(row.Title) || len(row.UpdateID) > 36 {
		return Entry{}, ErrMetadata
	}
	row.UpdateID = strings.ToLower(row.UpdateID)
	var b strings.Builder
	space := false
	for _, r := range row.Title {
		if unicode.IsSpace(r) {
			if b.Len() > 0 {
				space = true
			}
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		n := utf8.RuneLen(r)
		if space {
			n++
		}
		if b.Len()+n > MaxTitleBytes {
			row.MetadataTruncated = true
			break
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	row.Title = b.String()
	return row, nil
}
