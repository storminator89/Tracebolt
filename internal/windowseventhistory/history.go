// Package windowseventhistory implements a separately consented, bounded local
// Application/System metadata search and exact selected-message read. It grants
// no authority itself and does not change the existing recent-header reader.
package windowseventhistory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowsevents"
)

const (
	MaxSearchEvents      = 100
	MaxSearchBytes       = 256 << 10
	MaxRange             = 7 * 24 * time.Hour
	MaxLookback          = 30 * 24 * time.Hour
	MaxSelectedEvents    = windowseventcontent.MaxSelectedEvents
	MaxMessageBytes      = windowseventcontent.MaxMessageBytes
	MaxTotalMessageBytes = windowseventcontent.MaxTotalMessageBytes
	CollectionTimeout    = 5 * time.Second
	Source               = "windows-event-log-bounded-history"
	PrivacyWarning       = "Application/System event history and selected messages are operator-only. Messages may contain credentials, personal data and other secrets; do not send to AI providers or export. Complete means only that this bounded query was exhausted, not that retained history is complete or immutable."
	QualityObserved      = windowseventcontent.QualityObserved
	QualityBounded       = windowseventcontent.QualityBounded
	QualityPartial       = windowseventcontent.QualityPartial
	QualityUnavailable   = windowseventcontent.QualityUnavailable
)

var (
	ErrInvalidInput = errors.New("windows_event_history_invalid_input")
	ErrUnsupported  = errors.New("windows_event_history_unsupported_platform")
	ErrAccessDenied = errors.New("windows_event_history_access_denied")
	ErrUnavailable  = errors.New("windows_event_history_source_unavailable")
	ErrReadFailed   = errors.New("windows_event_history_read_failed")
	ErrInvalidData  = errors.New("windows_event_history_invalid_metadata")
	ErrBufferLimit  = errors.New("windows_event_history_metadata_buffer_limit")
	ErrResultLimit  = errors.New("windows_event_history_result_limit")
)

type Event = windowsevents.Event
type Result = windowseventcontent.Result

// Search has no arbitrary query, provider expression, path or remote target.
// The interval is [Start, End). Optional numeric filters are exact matches.
type Search struct {
	Channel string    `json:"channel"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Level   *uint8    `json:"level,omitempty"`
	EventID *uint16   `json:"eventId,omitempty"`
}
type Request struct {
	Events []Event `json:"events"`
	Search *Search `json:"search,omitempty"`
}
type Report struct {
	Source      string    `json:"source"`
	Warning     string    `json:"warning"`
	Quality     string    `json:"quality"`
	CollectedAt time.Time `json:"collected_at"`
	Complete    bool      `json:"complete"`
	Truncated   bool      `json:"truncated"`
	Events      []Result  `json:"events"`
	Search      *Search   `json:"search,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

func (Request) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("<windows-event-history request redacted>"))
}
func (Report) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("<windows-event-history report redacted>"))
}
func (Search) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("<windows-event-history search redacted>"))
}
func allowedChannel(s string) bool { return s == "Application" || s == "System" }
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1601 && t.Year() <= 9999
}
func validEvent(e Event, ch string) bool {
	return e.Channel == ch && allowedChannel(ch) && e.RecordID != 0 && validProvider(e.Provider) && validTime(e.Timestamp) && e.Timestamp.Nanosecond()%100 == 0
}
func validSearch(s Search) bool {
	return allowedChannel(s.Channel) && validTime(s.Start) && validTime(s.End) && s.Start.Before(s.End) && s.End.Sub(s.Start) <= MaxRange
}

// ValidateSearch binds age and future bounds to the original operation creation,
// not a retry, follow-up creation, receipt, or display time.
func ValidateSearch(s Search, created time.Time) error {
	if !validSearch(s) || !validTime(created) || s.End.After(created) || s.Start.Before(created.Add(-MaxLookback)) {
		return ErrInvalidInput
	}
	return nil
}
func CloneSearch(s *Search) *Search {
	if s == nil {
		return nil
	}
	out := *s
	if s.Level != nil {
		v := *s.Level
		out.Level = &v
	}
	if s.EventID != nil {
		v := *s.EventID
		out.EventID = &v
	}
	return &out
}
func sameSearch(a, b *Search) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Channel == b.Channel && a.Start == b.Start && a.End == b.End && (a.Level == nil && b.Level == nil || a.Level != nil && b.Level != nil && *a.Level == *b.Level) && (a.EventID == nil && b.EventID == nil || a.EventID != nil && b.EventID != nil && *a.EventID == *b.EventID)
}
func ValidateRequest(q Request) error {
	if q.Search != nil {
		if len(q.Events) != 0 || !validSearch(*q.Search) {
			return ErrInvalidInput
		}
		return nil
	}
	if windowseventcontent.ValidateRequest(windowseventcontent.Request{Events: q.Events}) != nil {
		return ErrInvalidInput
	}
	return nil
}
func matches(e Event, s Search) bool {
	return validEvent(e, s.Channel) && !e.Timestamp.Before(s.Start) && e.Timestamp.Before(s.End) && (s.Level == nil || e.Level == *s.Level) && (s.EventID == nil || e.EventID == *s.EventID)
}

// Read dispatches only after independent local consent and consume-once checks
// performed by its caller. Message reads reverify all six original fields.
func Read(ctx context.Context, q Request) (Report, error) {
	if ctx == nil || ValidateRequest(q) != nil {
		return Report{}, ErrInvalidInput
	}
	if q.Search != nil {
		return readSearch(ctx, *CloneSearch(q.Search))
	}
	r, err := windowseventcontent.Read(ctx, windowseventcontent.Request{Events: q.Events})
	if r.Source == "" {
		return Report{}, err
	}
	return Report{Source: Source, Warning: PrivacyWarning, Quality: r.Quality, CollectedAt: r.CollectedAt, Complete: r.Complete, Truncated: r.Truncated, Events: r.Events}, err
}

type cursor interface {
	Next(context.Context) (bool, error)
	Metadata() (Event, error)
	Close() error
}
type openSearch func(context.Context, Search) (cursor, error)

func searchWith(ctx context.Context, s Search, open openSearch) (report Report, err error) {
	if ctx == nil || open == nil || !validSearch(s) || s.End.After(time.Now().UTC()) {
		return Report{}, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, CollectionTimeout)
	defer cancel()
	report = Report{Source: Source, Warning: PrivacyWarning, Quality: QualityUnavailable, CollectedAt: time.Now().UTC(), Events: []Result{}, Search: CloneSearch(&s)}
	defer func() {
		if err != nil {
			err = safeError(err)
			report.Complete = false
			report.Quality = QualityUnavailable
			if len(report.Events) > 0 {
				report.Quality = QualityPartial
			}
			report.Reason = err.Error()
		}
	}()
	if err = ctx.Err(); err != nil {
		return
	}
	r, e := open(ctx, s)
	if e != nil {
		err = e
		return
	}
	if r == nil {
		err = ErrReadFailed
		return
	}
	defer func() {
		if e := r.Close(); e != nil && err == nil {
			err = e
		}
		if err == nil {
			err = ctx.Err()
		}
	}()
	for {
		if err = ctx.Err(); err != nil {
			return
		}
		var more bool
		more, err = r.Next(ctx)
		if err != nil {
			return
		}
		if err = ctx.Err(); err != nil {
			return
		}
		if !more {
			report.Quality = QualityObserved
			report.Complete = true
			return
		}
		if len(report.Events) == MaxSearchEvents {
			report.Quality = QualityBounded
			report.Truncated = true
			report.Reason = ErrResultLimit.Error()
			return
		}
		var e Event
		e, err = r.Metadata()
		if err != nil {
			return
		}
		if err = ctx.Err(); err != nil {
			return
		}
		if !matches(e, s) || len(report.Events) > 0 && e.RecordID >= report.Events[len(report.Events)-1].Event.RecordID {
			err = ErrInvalidData
			return
		}
		report.Events = append(report.Events, Result{Event: e, Quality: QualityObserved, Complete: true})
		raw, marshalErr := json.Marshal(report)
		// Reserve finite space for the final fixed quality/reason fields.
		if marshalErr != nil || len(raw) > MaxSearchBytes-256 {
			report.Events = report.Events[:len(report.Events)-1]
			report.Quality = QualityBounded
			report.Truncated = true
			report.Reason = ErrResultLimit.Error()
			return
		}
	}
}
func safeError(err error) error {
	for _, known := range []error{context.Canceled, context.DeadlineExceeded, ErrUnsupported, ErrAccessDenied, ErrUnavailable, ErrReadFailed, ErrInvalidData, ErrBufferLimit} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrReadFailed
}
func validReason(reason string) bool {
	for _, e := range []error{context.Canceled, context.DeadlineExceeded, ErrUnsupported, ErrAccessDenied, ErrUnavailable, ErrReadFailed, ErrInvalidData, ErrBufferLimit} {
		if reason == e.Error() {
			return true
		}
	}
	return false
}
func ValidateReport(r Report, q Request) error {
	if ValidateRequest(q) != nil || r.Source != Source || r.Warning != PrivacyWarning || !validTime(r.CollectedAt) || !sameSearch(r.Search, q.Search) {
		return ErrInvalidData
	}
	if q.Search == nil {
		if r.Reason != "" || windowseventcontent.ValidateReport(windowseventcontent.Report{Source: windowseventcontent.Source, Warning: windowseventcontent.PrivacyWarning, Quality: r.Quality, CollectedAt: r.CollectedAt, Complete: r.Complete, Truncated: r.Truncated, Events: r.Events}, windowseventcontent.Request{Events: q.Events}) != nil {
			return ErrInvalidData
		}
		return nil
	}
	if r.Events == nil || q.Search.End.After(r.CollectedAt) || len(r.Events) > MaxSearchEvents {
		return ErrInvalidData
	}
	for i, p := range r.Events {
		if !matches(p.Event, *q.Search) || p.Message != "" || p.Quality != QualityObserved || !p.Complete || p.Truncated || p.Reason != "" || i > 0 && p.Event.RecordID >= r.Events[i-1].Event.RecordID {
			return ErrInvalidData
		}
	}
	switch r.Quality {
	case QualityObserved:
		if !r.Complete || r.Truncated || r.Reason != "" {
			return ErrInvalidData
		}
	case QualityBounded:
		if r.Complete || !r.Truncated || len(r.Events) == 0 || r.Reason != ErrResultLimit.Error() {
			return ErrInvalidData
		}
	case QualityPartial:
		if r.Complete || len(r.Events) == 0 || !validReason(r.Reason) {
			return ErrInvalidData
		}
	case QualityUnavailable:
		if r.Complete || r.Truncated || len(r.Events) != 0 || !validReason(r.Reason) {
			return ErrInvalidData
		}
	default:
		return ErrInvalidData
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxSearchBytes {
		return ErrInvalidData
	}
	return nil
}

// Fixed generated XPath uses only validated UTC timestamps and typed numeric
// values. No caller-provided text is interpolated, including the channel name.
func searchXPath(s Search) (string, error) {
	if !validSearch(s) {
		return "", ErrInvalidInput
	}
	q := "*[System[TimeCreated[@SystemTime>='" + s.Start.Format(time.RFC3339Nano) + "' and @SystemTime<'" + s.End.Format(time.RFC3339Nano) + "']"
	if s.Level != nil {
		q += " and Level=" + strconv.FormatUint(uint64(*s.Level), 10)
	}
	if s.EventID != nil {
		q += " and EventID=" + strconv.FormatUint(uint64(*s.EventID), 10)
	}
	return q + "]]", nil
}
