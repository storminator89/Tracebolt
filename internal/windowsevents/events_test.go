package windowsevents

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fixtureCursor struct {
	rows        []Event
	at          int
	nextCalls   int
	renderCalls int
	closed      bool
	nextErr     error
	renderErr   error
	closeErr    error
	cancel      context.CancelFunc
}

func (f *fixtureCursor) Next(context.Context) (bool, error) {
	f.nextCalls++
	if f.cancel != nil {
		f.cancel()
	}
	if f.nextErr != nil {
		return false, f.nextErr
	}
	if f.at == len(f.rows) {
		return false, nil
	}
	f.at++
	return true, nil
}
func (f *fixtureCursor) Metadata() (Event, error) {
	f.renderCalls++
	if f.renderErr != nil {
		return Event{}, f.renderErr
	}
	return f.rows[f.at-1], nil
}
func (f *fixtureCursor) Close() error { f.closed = true; return f.closeErr }

func fixtureEvent(channel string, id uint64) Event {
	return Event{RecordID: id, EventID: 42, Level: 4, Provider: "Tracebolt-Synthetic-Fixture",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 600, time.UTC), Channel: channel}
}

func TestRejectInvalidInputsBeforeOpening(t *testing.T) {
	tests := []struct {
		name     string
		channels []string
		limit    int
	}{
		{"empty", nil, 1}, {"empty value", []string{""}, 1},
		{"Security", []string{"Security"}, 1}, {"case", []string{"application"}, 1},
		{"space", []string{"System "}, 1}, {"null", []string{"System\x00"}, 1},
		{"xpath", []string{"System/*"}, 1}, {"file", []string{`C:\System.evtx`}, 1},
		{"remote", []string{`\\server\System`}, 1}, {"duplicates", []string{"System", "System"}, 1},
		{"too many", []string{"Application", "System", "Security"}, 1},
		{"zero", []string{"System"}, 0}, {"negative", []string{"System"}, -1},
		{"over limit", []string{"System"}, MaxEventsPerChannel + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opened := false
			_, err := collectWith(context.Background(), tt.channels, tt.limit, func(context.Context, string) (cursor, error) {
				opened = true
				return nil, nil
			})
			if !errors.Is(err, ErrInvalidInput) || opened {
				t.Fatal("invalid input reached source or was accepted")
			}
		})
	}
	if _, err := collectWith(nil, []string{"System"}, 1, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil context was accepted")
	}
}

func TestBoundedCollectionAndLookahead(t *testing.T) {
	for _, rowCount := range []int{0, 2, 3, 4, 200} {
		t.Run(strconv.Itoa(rowCount), func(t *testing.T) {
			f := &fixtureCursor{}
			for i := 0; i < rowCount; i++ {
				f.rows = append(f.rows, fixtureEvent("System", uint64(rowCount-i)))
			}
			r, err := collectWith(context.Background(), []string{"System"}, 3, func(context.Context, string) (cursor, error) { return f, nil })
			if err != nil {
				t.Fatal(err)
			}
			want := min(rowCount, 3)
			if len(r.Channels) != 1 || len(r.Channels[0].Events) != want || f.renderCalls != want || f.nextCalls > 4 || !f.closed {
				t.Fatal("collection exceeded bounds or leaked cursor")
			}
			if r.Truncated != (rowCount > 3) || r.Complete != (rowCount <= 3) || r.Channels[0].Complete != r.Complete {
				t.Fatal("incorrect truncation/completeness")
			}
			if r.Source != Source || r.CollectedAt.Location() != time.UTC || r.LimitPerChannel != 3 {
				t.Fatal("missing provenance")
			}
			wantQuality := QualityObserved
			if rowCount > 3 {
				wantQuality = QualityBounded
			}
			if r.Quality != wantQuality {
				t.Fatal("incorrect bounded quality")
			}
		})
	}
}

func TestMaximumLimitAndChannelIsolation(t *testing.T) {
	readers := map[string]*fixtureCursor{}
	r, err := collectWith(context.Background(), []string{"Application", "System"}, MaxEventsPerChannel, func(_ context.Context, channel string) (cursor, error) {
		f := &fixtureCursor{}
		for i := 101; i > 0; i-- {
			f.rows = append(f.rows, fixtureEvent(channel, uint64(i)))
		}
		readers[channel] = f
		return f, nil
	})
	if err != nil || len(r.Channels) != 2 || !r.Truncated || r.Complete {
		t.Fatal("maximum request failed")
	}
	for _, part := range r.Channels {
		f := readers[part.Channel]
		if len(part.Events) != 100 || f.renderCalls != 100 || f.nextCalls != 101 || !f.closed {
			t.Fatal("per-channel limit was not enforced")
		}
		for _, event := range part.Events {
			if event.Channel != part.Channel {
				t.Fatal("cross-channel metadata")
			}
		}
	}
}

func TestSourceFailuresRemainVisibleAndSanitized(t *testing.T) {
	r, err := collectWith(context.Background(), []string{"Application", "System"}, 2, func(_ context.Context, channel string) (cursor, error) {
		if channel == "Application" {
			return nil, ErrAccessDenied
		}
		return &fixtureCursor{rows: []Event{fixtureEvent("System", 1)}}, nil
	})
	if !errors.Is(err, ErrAccessDenied) || r.Complete || r.Quality != QualityPartial || !r.Channels[1].Complete ||
		r.Channels[0].Reason != ErrAccessDenied.Error() || r.Channels[0].Quality != QualityUnavailable {
		t.Fatal("source failure was concealed or healthy channel discarded")
	}
	const secret = "sensitive raw source details"
	r, err = collectWith(context.Background(), []string{"System"}, 1, func(context.Context, string) (cursor, error) { return nil, errors.New(secret) })
	b, marshalErr := json.Marshal(r)
	if marshalErr != nil || !errors.Is(err, ErrReadFailed) || strings.Contains(string(b), secret) || strings.Contains(err.Error(), secret) {
		t.Fatal("source error leaked raw text")
	}
}

func TestCancellationAndCloseFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opened := false
	r, err := collectWith(ctx, []string{"System"}, 1, func(context.Context, string) (cursor, error) { opened = true; return nil, nil })
	if !errors.Is(err, context.Canceled) || opened || r.Complete {
		t.Fatal("cancellation did not stop source")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	f := &fixtureCursor{rows: []Event{fixtureEvent("System", 1)}, cancel: cancel}
	_, err = collectWith(ctx, []string{"System"}, 1, func(context.Context, string) (cursor, error) { return f, nil })
	if !errors.Is(err, context.Canceled) || f.renderCalls != 0 || !f.closed {
		t.Fatal("cancellation leaked handle or rendered more metadata")
	}
	f = &fixtureCursor{rows: []Event{fixtureEvent("System", 1)}, closeErr: ErrReadFailed}
	r, err = collectWith(context.Background(), []string{"System"}, 1, func(context.Context, string) (cursor, error) { return f, nil })
	if !errors.Is(err, ErrReadFailed) || r.Complete || r.Channels[0].Complete || r.Quality != QualityPartial {
		t.Fatal("close failure was hidden")
	}
}

func TestEmptySuccessfulChannelIsStillObserved(t *testing.T) {
	r, err := collectWith(context.Background(), []string{"Application", "System"}, 2, func(_ context.Context, channel string) (cursor, error) {
		if channel == "Application" {
			return nil, ErrAccessDenied
		}
		return &fixtureCursor{}, nil
	})
	if !errors.Is(err, ErrAccessDenied) || r.Quality != QualityPartial || !r.Channels[1].Complete {
		t.Fatal("successful empty source was mislabeled unavailable")
	}
}

func TestCollectionSuppliesFiniteContext(t *testing.T) {
	_, err := collectWith(context.Background(), []string{"System"}, 1, func(ctx context.Context, _ string) (cursor, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > CollectionTimeout {
			t.Fatal("source received an unbounded context")
		}
		return &fixtureCursor{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCancellationDuringEmptyLookaheadIsNotComplete(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fixtureCursor{cancel: cancel}
	r, err := collectWith(ctx, []string{"System"}, 1, func(context.Context, string) (cursor, error) { return f, nil })
	if !errors.Is(err, context.Canceled) || r.Complete || !f.closed {
		t.Fatal("canceled lookahead claimed complete")
	}
}

func TestRenderFailureAndWrongChannel(t *testing.T) {
	for _, f := range []*fixtureCursor{
		{rows: []Event{fixtureEvent("System", 1)}, renderErr: ErrBufferLimit},
		{rows: []Event{fixtureEvent("Application", 1)}},
		{nextErr: context.DeadlineExceeded},
	} {
		r, err := collectWith(context.Background(), []string{"System"}, 1, func(context.Context, string) (cursor, error) { return f, nil })
		if err == nil || r.Complete || len(r.Channels[0].Events) != 0 || !f.closed {
			t.Fatal("failed metadata appeared successful")
		}
	}
}

func TestReportCannotContainEventContent(t *testing.T) {
	want := []string{"RecordID", "EventID", "Level", "Provider", "Timestamp", "Channel"}
	typ := reflect.TypeOf(Event{})
	if typ.NumField() != len(want) {
		t.Fatal("metadata schema expanded")
	}
	for i, name := range want {
		if typ.Field(i).Name != name {
			t.Fatal("metadata schema changed")
		}
	}
	paths := metadataPaths()
	if !reflect.DeepEqual(paths, [metadataPropertyCount]string{
		"Event/System/EventRecordID", "Event/System/EventID", "Event/System/Level", "Event/System/Provider/@Name",
		"Event/System/TimeCreated/@SystemTime", "Event/System/Channel",
	}) {
		t.Fatal("render selection changed")
	}
}
