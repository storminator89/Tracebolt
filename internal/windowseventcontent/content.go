// Package windowseventcontent provides a separate, explicit local read of a
// bounded selection of Windows event messages. It is not a consent mechanism.
// Existing windowsevents metadata collection never invokes this package.
package windowseventcontent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"localrmm/internal/windowsevents"
)

const (
	MaxSelectedEvents    = 16
	MaxMessageBytes      = 16 * 1024
	MaxTotalMessageBytes = 64 * 1024
	CollectionTimeout    = 5 * time.Second
	Source               = "windows-event-log-message-content"
	PrivacyWarning       = "Event messages may contain credentials, personal data and other secrets. Authorized operator-only content; do not send to AI providers or export."
	QualityObserved      = "observed"
	QualityBounded       = "bounded"
	QualityPartial       = "partial"
	QualityUnavailable   = "unavailable"
)

var (
	ErrInvalidInput         = errors.New("windows_event_content_invalid_input")
	ErrUnsupported          = errors.New("windows_event_content_unsupported_platform")
	ErrAccessDenied         = errors.New("windows_event_content_access_denied")
	ErrUnavailable          = errors.New("windows_event_content_source_unavailable")
	ErrReadFailed           = errors.New("windows_event_content_read_failed")
	ErrInvalidData          = errors.New("windows_event_content_invalid_data")
	ErrBufferLimit          = errors.New("windows_event_content_native_buffer_limit")
	ErrNotFound             = errors.New("windows_event_content_record_not_found")
	ErrIdentityMismatch     = errors.New("windows_event_content_identity_mismatch")
	ErrPublisherUnavailable = errors.New("windows_event_content_publisher_unavailable")
	ErrMessageUnavailable   = errors.New("windows_event_content_message_unavailable")
	ErrContentLimit         = errors.New("windows_event_content_message_limit")
	ErrTotalLimit           = errors.New("windows_event_content_total_limit")
)

// Event is the existing six-field metadata identity, not an additional scope.
type Event = windowsevents.Event

// Request selects exact already-known event identities, with no default query.
// Its caller must independently verify an explicit local content grant.
type Request struct {
	Events []windowsevents.Event `json:"events"`
}

type Result struct {
	Event     windowsevents.Event `json:"event"`
	Message   string              `json:"message"`
	Quality   string              `json:"quality"`
	Complete  bool                `json:"complete"`
	Truncated bool                `json:"truncated"`
	Reason    string              `json:"reason,omitempty"`
}

// Complete describes only the exact requested messages. It does not establish
// historical completeness, an immutable log snapshot, or publisher availability.
type Report struct {
	Source      string    `json:"source"`
	Warning     string    `json:"warning"`
	Quality     string    `json:"quality"`
	CollectedAt time.Time `json:"collected_at"`
	Complete    bool      `json:"complete"`
	Truncated   bool      `json:"truncated"`
	Events      []Result  `json:"events"`
}

// Diagnostic formatting is always redacted, including %+v, %#v, %s and %q.
// JSON serialization is intentionally a content-bearing operation for callers.
func (Request) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("<windows-event-content request redacted>"))
}
func (Result) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("<windows-event-content result redacted>"))
}
func (Report) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("<windows-event-content report redacted>"))
}

type cursor interface {
	Next(context.Context) (bool, error)
	Metadata(context.Context) (Event, error)
	Message(context.Context, string) (string, error)
	Close() error
}
type openSelection func(context.Context, Event) (cursor, error)

func allowedChannel(channel string) bool { return channel == "Application" || channel == "System" }

func validEvent(event Event, channel string) bool {
	return allowedChannel(channel) && event.Channel == channel && event.RecordID != 0 &&
		validProvider(event.Provider) && !event.Timestamp.IsZero() && event.Timestamp.Location() == time.UTC &&
		event.Timestamp.Year() >= 1601 && event.Timestamp.Year() <= 9999 && event.Timestamp.Nanosecond()%100 == 0
}

func sameEvent(a, b Event) bool {
	return a.RecordID == b.RecordID && a.EventID == b.EventID && a.Level == b.Level &&
		a.Provider == b.Provider && a.Channel == b.Channel && a.Timestamp.Equal(b.Timestamp)
}

// ValidateRequest performs no native operation. It rejects unsupported channels,
// missing identities and duplicate channel/record pairs before any native read.
func ValidateRequest(request Request) error {
	if len(request.Events) < 1 || len(request.Events) > MaxSelectedEvents {
		return ErrInvalidInput
	}
	type key struct {
		channel string
		id      uint64
	}
	seen := make(map[key]bool, len(request.Events))
	for _, event := range request.Events {
		k := key{event.Channel, event.RecordID}
		if !validEvent(event, event.Channel) || seen[k] {
			return ErrInvalidInput
		}
		seen[k] = true
	}
	return nil
}

func readWith(ctx context.Context, request Request, open openSelection) (Report, error) {
	if err := ValidateRequest(request); err != nil {
		return Report{}, err
	}
	if ctx == nil || open == nil {
		return Report{}, ErrInvalidInput
	}
	// The caller must not mutate its slice during this call, as for any Go API.
	selected := append([]Event(nil), request.Events...)
	ctx, cancel := context.WithTimeout(ctx, CollectionTimeout)
	defer cancel()
	report := Report{Source: Source, Warning: PrivacyWarning, CollectedAt: time.Now().UTC(), Events: make([]Result, 0, len(selected))}
	remaining := MaxTotalMessageBytes
	var errs []error
	for _, event := range selected {
		var part Result
		var err error
		if remaining == 0 {
			part = Result{Event: event, Quality: QualityBounded, Truncated: true, Reason: ErrTotalLimit.Error()}
		} else {
			part, err = readOne(ctx, event, remaining, open)
		}
		remaining -= len(part.Message)
		report.Events = append(report.Events, part)
		if err != nil {
			errs = append(errs, err)
		}
	}
	report.Quality, report.Complete, report.Truncated = reportState(report.Events)
	return report, errors.Join(errs...)
}

func readOne(ctx context.Context, selected Event, remaining int, open openSelection) (part Result, err error) {
	part = Result{Event: selected, Quality: QualityUnavailable}
	defer func() {
		if err != nil {
			err = safeError(err)
			// A failing formatter may have populated incomplete native text. Never
			// return it as a fallback, including on cancellation or close failure.
			part.Message = ""
			part.Complete, part.Truncated = false, false
			part.Quality, part.Reason = QualityUnavailable, err.Error()
		}
	}()
	if err = ctx.Err(); err != nil {
		return part, err
	}
	reader, err := open(ctx, selected)
	if err != nil {
		return part, err
	}
	if reader == nil {
		return part, ErrReadFailed
	}
	defer func() {
		if closeErr := reader.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		if err == nil {
			err = ctx.Err()
		}
	}()
	if err = ctx.Err(); err != nil {
		return part, err
	}
	more, err := reader.Next(ctx)
	if err != nil {
		return part, err
	}
	if err = ctx.Err(); err != nil {
		return part, err
	}
	if !more {
		return part, ErrNotFound
	}
	actual, err := reader.Metadata(ctx)
	if err != nil {
		return part, err
	}
	if !validEvent(actual, selected.Channel) {
		return part, ErrInvalidData
	}
	if !sameEvent(actual, selected) {
		return part, ErrIdentityMismatch
	}
	if err = ctx.Err(); err != nil {
		return part, err
	}
	message, err := reader.Message(ctx, actual.Provider)
	if err != nil {
		return part, err
	}
	if err = ctx.Err(); err != nil {
		return part, err
	}
	if !validMessage(message) {
		return part, ErrInvalidData
	}
	limit := min(MaxMessageBytes, remaining)
	part.Message, part.Truncated = boundedMessage(message, limit)
	part.Complete, part.Quality = !part.Truncated, QualityObserved
	if part.Truncated {
		part.Quality, part.Reason = QualityBounded, ErrContentLimit.Error()
		if remaining < MaxMessageBytes {
			part.Reason = ErrTotalLimit.Error()
		}
	}
	return part, nil
}

func validMessage(message string) bool {
	return utf8.ValidString(message) && !strings.ContainsRune(message, '\x00')
}

func boundedMessage(message string, limit int) (string, bool) {
	if len(message) <= limit {
		return message, false
	}
	for limit > 0 && !utf8.RuneStart(message[limit]) {
		limit--
	}
	// Clone prevents the returned prefix from retaining the complete native text.
	return strings.Clone(message[:limit]), true
}

func safeError(err error) error {
	for _, known := range []error{context.Canceled, context.DeadlineExceeded, ErrUnsupported,
		ErrAccessDenied, ErrUnavailable, ErrInvalidData, ErrBufferLimit, ErrNotFound,
		ErrIdentityMismatch, ErrPublisherUnavailable, ErrMessageUnavailable, ErrReadFailed} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrReadFailed
}

func reportState(events []Result) (quality string, complete, truncated bool) {
	complete = true
	observed, failed := false, false
	for _, part := range events {
		complete = complete && part.Complete
		truncated = truncated || part.Truncated
		failed = failed || part.Quality == QualityUnavailable
		observed = observed || part.Quality == QualityObserved || (part.Quality == QualityBounded && part.Message != "")
	}
	quality = QualityObserved
	if truncated {
		quality = QualityBounded
	}
	if failed {
		quality = QualityUnavailable
		if observed {
			quality = QualityPartial
		}
	}
	return
}

// ValidateReport checks the full portable content boundary against the original
// selection; it neither reads logs nor grants consent to transmit this report.
func ValidateReport(report Report, request Request) error {
	if ValidateRequest(request) != nil || report.Source != Source || report.Warning != PrivacyWarning || len(report.Events) != len(request.Events) ||
		report.CollectedAt.IsZero() || report.CollectedAt.Location() != time.UTC ||
		report.CollectedAt.Year() < 1601 || report.CollectedAt.Year() > 9999 {
		return ErrInvalidData
	}
	total := 0
	for i, part := range report.Events {
		if !validEvent(part.Event, request.Events[i].Channel) || !sameEvent(part.Event, request.Events[i]) ||
			!validMessage(part.Message) || len(part.Message) > MaxMessageBytes {
			return ErrInvalidData
		}
		if total == MaxTotalMessageBytes && (part.Quality != QualityBounded || part.Message != "" || part.Reason != ErrTotalLimit.Error()) {
			return ErrInvalidData
		}
		switch part.Quality {
		case QualityObserved:
			if !part.Complete || part.Truncated || part.Reason != "" {
				return ErrInvalidData
			}
		case QualityBounded:
			if part.Complete || !part.Truncated {
				return ErrInvalidData
			}
			remaining := MaxTotalMessageBytes - total
			limit := min(MaxMessageBytes, remaining)
			wantReason := ErrContentLimit.Error()
			if remaining < MaxMessageBytes {
				wantReason = ErrTotalLimit.Error()
			}
			if part.Reason != wantReason || len(part.Message) > limit || len(part.Message) < max(0, limit-3) {
				return ErrInvalidData
			}
		case QualityUnavailable:
			if part.Complete || part.Truncated || part.Message != "" || !validReason(part.Reason) {
				return ErrInvalidData
			}
		default:
			return ErrInvalidData
		}
		total += len(part.Message)
		if total > MaxTotalMessageBytes {
			return ErrInvalidData
		}
	}
	quality, complete, truncated := reportState(report.Events)
	if report.Quality != quality || report.Complete != complete || report.Truncated != truncated {
		return ErrInvalidData
	}
	return nil
}

func validReason(reason string) bool {
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, ErrUnsupported, ErrAccessDenied,
		ErrUnavailable, ErrInvalidData, ErrBufferLimit, ErrNotFound, ErrIdentityMismatch,
		ErrPublisherUnavailable, ErrMessageUnavailable, ErrReadFailed} {
		if reason == err.Error() {
			return true
		}
	}
	return false
}
