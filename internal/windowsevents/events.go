// Package windowsevents provides an opt-in, bounded, local Windows Event Log
// metadata reader. It never reads event messages, XML, EventData, or identities.
// Calling Collect is not a grant of consent; callers must obtain local approval.
package windowsevents

import (
	"context"
	"errors"
	"time"
)

const (
	MaxEventsPerChannel = 100
	CollectionTimeout   = 5 * time.Second
	Source              = "windows-event-log-system-metadata"
	QualityObserved     = "observed"
	QualityBounded      = "bounded"
	QualityPartial      = "partial"
	QualityUnavailable  = "unavailable"
)

var (
	ErrInvalidInput = errors.New("windows_events_invalid_input")
	ErrUnsupported  = errors.New("windows_events_unsupported_platform")
	ErrAccessDenied = errors.New("windows_events_access_denied")
	ErrUnavailable  = errors.New("windows_events_source_unavailable")
	ErrReadFailed   = errors.New("windows_events_read_failed")
	ErrInvalidData  = errors.New("windows_events_invalid_metadata")
	ErrBufferLimit  = errors.New("windows_events_metadata_buffer_limit")
)

// Event contains only the six explicitly selected System properties. EventID
// is the schema's 16-bit EventID, not an EventID/Qualifiers composite.
type Event struct {
	RecordID  uint64    `json:"record_id"`
	EventID   uint16    `json:"event_id"`
	Level     uint8     `json:"level"`
	Provider  string    `json:"provider"`
	Timestamp time.Time `json:"timestamp"`
	Channel   string    `json:"channel"`
}

type ChannelReport struct {
	Channel   string  `json:"channel"`
	Source    string  `json:"source"`
	Quality   string  `json:"quality"`
	Complete  bool    `json:"complete"`
	Truncated bool    `json:"truncated"`
	Reason    string  `json:"reason,omitempty"`
	Events    []Event `json:"events"`
}

// Complete means the query was exhausted, not that a log is immutable or that
// all historical events still exist. Truncated means an additional event was
// observed past the requested limit, without rendering that event.
type Report struct {
	Source          string          `json:"source"`
	Quality         string          `json:"quality"`
	CollectedAt     time.Time       `json:"collected_at"`
	LimitPerChannel int             `json:"limit_per_channel"`
	Complete        bool            `json:"complete"`
	Truncated       bool            `json:"truncated"`
	Channels        []ChannelReport `json:"channels"`
}

// cursor is private: callers cannot inject native handles, paths or queries.
// Next holds at most one event. Metadata is never called for the lookahead.
type cursor interface {
	Next(context.Context) (bool, error)
	Metadata() (Event, error)
	Close() error
}

type openChannel func(context.Context, string) (cursor, error)

func allowedChannel(channel string) bool {
	return channel == "Application" || channel == "System"
}

func validateInput(ctx context.Context, channels []string, limit int) error {
	if ctx == nil || len(channels) < 1 || len(channels) > 2 || limit < 1 || limit > MaxEventsPerChannel {
		return ErrInvalidInput
	}
	seen := make(map[string]bool, 2)
	for _, channel := range channels {
		if !allowedChannel(channel) || seen[channel] {
			return ErrInvalidInput
		}
		seen[channel] = true
	}
	return nil
}

func collectWith(ctx context.Context, channels []string, limit int, open openChannel) (Report, error) {
	if err := validateInput(ctx, channels, limit); err != nil {
		return Report{}, err
	}
	if open == nil {
		return Report{}, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, CollectionTimeout)
	defer cancel()
	report := Report{Source: Source, Quality: QualityObserved, CollectedAt: time.Now().UTC(),
		LimitPerChannel: limit, Complete: true, Channels: make([]ChannelReport, 0, len(channels))}
	var errs []error
	observed := false
	for _, channel := range channels {
		part, err := collectChannel(ctx, channel, limit, open)
		report.Channels = append(report.Channels, part)
		report.Complete = report.Complete && part.Complete
		report.Truncated = report.Truncated || part.Truncated
		observed = observed || part.Reason == "" || len(part.Events) > 0
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		report.Quality = QualityPartial
		if !observed {
			report.Quality = QualityUnavailable
		}
	} else if report.Truncated {
		report.Quality = QualityBounded
	}
	return report, errors.Join(errs...)
}

func collectChannel(ctx context.Context, channel string, limit int, open openChannel) (part ChannelReport, err error) {
	part = ChannelReport{Channel: channel, Source: Source, Quality: QualityUnavailable, Events: []Event{}}
	// Source errors have a fixed taxonomy, never OS-formatted messages or data.
	defer func() {
		if err != nil {
			err = safeError(err)
			part.Complete = false
			part.Reason = err.Error()
			part.Quality = QualityUnavailable
			if len(part.Events) > 0 {
				part.Quality = QualityPartial
			}
		}
	}()
	if err = ctx.Err(); err != nil {
		return part, err
	}
	reader, err := open(ctx, channel)
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
	}()
	for i := 0; i <= limit; i++ {
		if err = ctx.Err(); err != nil {
			return part, err
		}
		var more bool
		more, err = reader.Next(ctx)
		if err != nil {
			return part, err
		}
		if err = ctx.Err(); err != nil {
			return part, err
		}
		if !more {
			part.Complete = true
			part.Quality = QualityObserved
			return part, nil
		}
		if i == limit {
			part.Truncated = true
			part.Quality = QualityBounded
			return part, nil
		}
		if err = ctx.Err(); err != nil {
			return part, err
		}
		var event Event
		event, err = reader.Metadata()
		if err != nil {
			return part, err
		}
		if !validEvent(event, channel) {
			return part, ErrInvalidData
		}
		part.Events = append(part.Events, event)
	}
	return part, ErrReadFailed
}

func safeError(err error) error {
	for _, known := range []error{context.Canceled, context.DeadlineExceeded, ErrUnsupported,
		ErrAccessDenied, ErrUnavailable, ErrInvalidData, ErrBufferLimit, ErrReadFailed} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrReadFailed
}

func validEvent(event Event, channel string) bool {
	return allowedChannel(channel) && event.Channel == channel && event.RecordID != 0 &&
		validProvider(event.Provider) && !event.Timestamp.IsZero() &&
		event.Timestamp.Location() == time.UTC && event.Timestamp.Year() >= 1601 && event.Timestamp.Year() <= 9999
}
