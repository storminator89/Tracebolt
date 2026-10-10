package windowseventcontent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type fixtureCursor struct {
	event                                              Event
	message                                            string
	nextErr, metadataErr, messageErr, closeErr         error
	missing                                            bool
	nextCalls, metadataCalls, messageCalls, closeCalls int
	cancel                                             context.CancelFunc
	cancelAt                                           string
}

func (f *fixtureCursor) stage(name string) {
	if f.cancel != nil && f.cancelAt == name {
		f.cancel()
	}
}
func (f *fixtureCursor) Next(context.Context) (bool, error) {
	f.nextCalls++
	f.stage("next")
	return !f.missing, f.nextErr
}
func (f *fixtureCursor) Metadata(context.Context) (Event, error) {
	f.metadataCalls++
	f.stage("metadata")
	return f.event, f.metadataErr
}
func (f *fixtureCursor) Message(_ context.Context, provider string) (string, error) {
	f.messageCalls++
	f.stage("message")
	if provider != f.event.Provider {
		return "", errors.New("unexpected unverified provider")
	}
	return f.message, f.messageErr
}
func (f *fixtureCursor) Close() error { f.closeCalls++; f.stage("close"); return f.closeErr }
func fixtureEvent(channel string, id uint64) Event {
	return Event{RecordID: id, EventID: 42, Level: 4, Provider: "Tracebolt-Synthetic-Fixture",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 600, time.UTC), Channel: channel}
}
func fixtureRead(t *testing.T, f *fixtureCursor) (Report, error) {
	t.Helper()
	req := Request{Events: []Event{fixtureEvent("System", 1)}}
	report, err := readWith(context.Background(), req, func(context.Context, Event) (cursor, error) { return f, nil })
	if ValidateReport(report, req) != nil {
		t.Fatal("collector produced invalid report")
	}
	return report, err
}

func TestInvalidSelectionsNeverOpen(t *testing.T) {
	base := fixtureEvent("System", 1)
	requests := []Request{{}, {Events: []Event{base, base}}}
	for _, mutate := range []func(*Event){
		func(e *Event) { e.Channel = "Security" }, func(e *Event) { e.Channel = "system" },
		func(e *Event) { e.Channel = "System " }, func(e *Event) { e.Channel = "System\x00" },
		func(e *Event) { e.Channel = "*[System]" }, func(e *Event) { e.Channel = `C:\System.evtx` },
		func(e *Event) { e.Channel = `\\host\System` }, func(e *Event) { e.RecordID = 0 },
		func(e *Event) { e.Provider = "" }, func(e *Event) { e.Provider = "bad\nprovider" },
		func(e *Event) { e.Timestamp = time.Time{} },
		func(e *Event) { e.Timestamp = e.Timestamp.In(time.FixedZone("other", 0)) },
		func(e *Event) { e.Timestamp = e.Timestamp.Add(time.Nanosecond) },
	} {
		e := base
		mutate(&e)
		requests = append(requests, Request{Events: []Event{e}})
	}
	oversize := Request{}
	for i := 0; i <= MaxSelectedEvents; i++ {
		oversize.Events = append(oversize.Events, fixtureEvent("System", uint64(i+1)))
	}
	requests = append(requests, oversize)
	for _, req := range requests {
		opened := false
		_, err := readWith(context.Background(), req, func(context.Context, Event) (cursor, error) { opened = true; return nil, nil })
		if !errors.Is(err, ErrInvalidInput) || opened {
			t.Fatal("invalid selection reached source")
		}
	}
	if _, err := readWith(nil, Request{Events: []Event{base}}, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil accepted")
	}
}

func TestSixFieldIdentityCheckedBeforeFormatting(t *testing.T) {
	for _, mutate := range []func(*Event){
		func(e *Event) { e.RecordID++ }, func(e *Event) { e.EventID++ }, func(e *Event) { e.Level++ },
		func(e *Event) { e.Provider = "Other-Fixture" }, func(e *Event) { e.Timestamp = e.Timestamp.Add(time.Second) },
		func(e *Event) { e.Channel = "Application" },
	} {
		f := &fixtureCursor{event: fixtureEvent("System", 1), message: "must never format"}
		mutate(&f.event)
		r, err := fixtureRead(t, f)
		if err == nil || f.messageCalls != 0 || f.closeCalls != 1 || r.Complete || r.Events[0].Message != "" {
			t.Fatal("identity mismatch released content")
		}
	}
}

func TestSelectedContentAndEmptySuccessfulMessage(t *testing.T) {
	for _, text := range []string{"Synthetic message\r\nwith value 😀", ""} {
		f := &fixtureCursor{event: fixtureEvent("System", 1), message: text}
		r, err := fixtureRead(t, f)
		if err != nil || !r.Complete || r.Quality != QualityObserved || r.Events[0].Message != text || f.nextCalls != 1 || f.metadataCalls != 1 || f.messageCalls != 1 || f.closeCalls != 1 {
			t.Fatal("selected message failed")
		}
		if r.Warning != PrivacyWarning || r.CollectedAt.Location() != time.UTC {
			t.Fatal("missing privacy/provenance")
		}
	}
}

func TestMixedAvailabilityAndSanitizedFailures(t *testing.T) {
	req := Request{Events: []Event{fixtureEvent("Application", 1), fixtureEvent("System", 1)}}
	r, err := readWith(context.Background(), req, func(_ context.Context, e Event) (cursor, error) {
		if e.Channel == "Application" {
			return nil, ErrPublisherUnavailable
		}
		return &fixtureCursor{event: e, message: "fixture"}, nil
	})
	if !errors.Is(err, ErrPublisherUnavailable) || r.Quality != QualityPartial || r.Complete || ValidateReport(r, req) != nil {
		t.Fatal("mixed availability lost")
	}
	for _, sourceErr := range []error{ErrPublisherUnavailable, ErrMessageUnavailable, ErrAccessDenied, ErrBufferLimit, errors.New("PRIVATE SOURCE SECRET")} {
		f := &fixtureCursor{event: fixtureEvent("System", 1), message: "PRIVATE PARTIAL MESSAGE", messageErr: sourceErr}
		r, err := fixtureRead(t, f)
		encoded, _ := json.Marshal(r)
		if err == nil || r.Quality != QualityUnavailable || strings.Contains(string(encoded), "PRIVATE") || strings.Contains(err.Error(), "PRIVATE") || f.closeCalls != 1 {
			t.Fatal("failure leaked raw details")
		}
	}
}

func TestRecordMissingInvalidTextAndCloseFailure(t *testing.T) {
	for _, f := range []*fixtureCursor{
		{missing: true}, {event: fixtureEvent("System", 1), message: "\xff"}, {event: fixtureEvent("System", 1), message: "a\x00b"},
		{event: fixtureEvent("System", 1), message: "fixture", closeErr: errors.New("private close failure")},
		{nextErr: ErrUnavailable}, {metadataErr: ErrInvalidData},
	} {
		r, err := fixtureRead(t, f)
		if err == nil || r.Complete || r.Events[0].Message != "" || f.closeCalls != 1 {
			t.Fatal("failed source looked complete")
		}
	}
}

func TestCancellationBetweenNativeSteps(t *testing.T) {
	for _, stage := range []string{"before", "open", "next", "metadata", "message", "close"} {
		ctx, cancel := context.WithCancel(context.Background())
		f := &fixtureCursor{event: fixtureEvent("System", 1), message: "fixture", cancel: cancel, cancelAt: stage}
		opened := false
		if stage == "before" {
			cancel()
		}
		req := Request{Events: []Event{f.event}}
		r, err := readWith(ctx, req, func(context.Context, Event) (cursor, error) {
			opened = true
			if stage == "open" {
				cancel()
			}
			return f, nil
		})
		cancel()
		if !errors.Is(err, context.Canceled) || r.Complete || r.Events[0].Message != "" || ValidateReport(r, req) != nil {
			t.Fatal("cancellation admitted content")
		}
		if (stage == "before" && opened) || (opened && f.closeCalls != 1) {
			t.Fatal("cancellation leaked source")
		}
		if stage != "message" && stage != "close" && f.messageCalls != 0 {
			t.Fatal("formatting continued after cancellation")
		}
	}
}

func TestByteBoundsAndNoReadsAfterAggregateBudget(t *testing.T) {
	for _, message := range []string{strings.Repeat("x", MaxMessageBytes+1), strings.Repeat("😀", MaxMessageBytes/4+1), strings.Repeat("€", MaxMessageBytes/3+1)} {
		f := &fixtureCursor{event: fixtureEvent("System", 1), message: message}
		r, err := fixtureRead(t, f)
		if err != nil || !r.Truncated || r.Complete || r.Quality != QualityBounded || len(r.Events[0].Message) > MaxMessageBytes || !utf8.ValidString(r.Events[0].Message) {
			t.Fatal("message bound failed")
		}
	}
	req := Request{}
	for i := 0; i < MaxSelectedEvents; i++ {
		req.Events = append(req.Events, fixtureEvent("System", uint64(i+1)))
	}
	opened := 0
	r, err := readWith(context.Background(), req, func(_ context.Context, e Event) (cursor, error) {
		opened++
		return &fixtureCursor{event: e, message: strings.Repeat("x", MaxMessageBytes)}, nil
	})
	total := 0
	for _, part := range r.Events {
		total += len(part.Message)
	}
	if err != nil || opened != 4 || total != MaxTotalMessageBytes || !r.Truncated || r.Complete || ValidateReport(r, req) != nil {
		t.Fatal("aggregate bound failed")
	}
}

func TestDiagnosticFormattingAlwaysRedacted(t *testing.T) {
	e := fixtureEvent("System", 1)
	e.Provider = "PRIVATE-PROVIDER"
	req := Request{Events: []Event{e}}
	part := Result{Event: e, Message: "PRIVATE-CREDENTIAL"}
	report := Report{Events: []Result{part}}
	for _, value := range []any{req, &req, part, &part, report, &report} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%#q"} {
			got := fmt.Sprintf(verb, value)
			if strings.Contains(got, "PRIVATE") || !strings.Contains(got, "redacted") {
				t.Fatal("diagnostic format exposed data")
			}
		}
	}
}

func TestValidateReportRejectsMalformedWireStates(t *testing.T) {
	req := Request{Events: []Event{fixtureEvent("System", 1)}}
	original, _ := fixtureRead(t, &fixtureCursor{event: req.Events[0], message: "fixture"})
	for _, mutate := range []func(*Report){
		func(r *Report) { r.Source = "other" }, func(r *Report) { r.Warning = "" }, func(r *Report) { r.CollectedAt = time.Time{} },
		func(r *Report) { r.Complete = false }, func(r *Report) { r.Truncated = true }, func(r *Report) { r.Quality = QualityPartial },
		func(r *Report) { r.Events = nil }, func(r *Report) { r.Events[0].Event.RecordID++ }, func(r *Report) { r.Events[0].Event.Provider = "other" },
		func(r *Report) { r.Events[0].Message = strings.Repeat("x", MaxMessageBytes+1) }, func(r *Report) { r.Events[0].Message = "\xff" },
		func(r *Report) { r.Events[0].Reason = "raw private text" }, func(r *Report) { r.Events[0].Complete = false },
		func(r *Report) {
			r.Events[0].Quality = QualityUnavailable
			r.Events[0].Complete = false
			r.Events[0].Reason = ErrMessageUnavailable.Error()
		},
		func(r *Report) {
			r.Events[0].Quality = QualityBounded
			r.Events[0].Complete = false
			r.Events[0].Truncated = true
			r.Events[0].Reason = ErrContentLimit.Error()
		},
	} {
		r := original
		r.Events = append([]Result(nil), original.Events...)
		mutate(&r)
		if ValidateReport(r, req) == nil {
			t.Fatal("malformed report passed validation")
		}
	}
	encoded, _ := json.Marshal(original)
	var decoded Report
	if json.Unmarshal(encoded, &decoded) != nil || ValidateReport(decoded, req) != nil {
		t.Fatal("valid report failed JSON roundtrip")
	}
}

func TestSelectionQueryCannotAcceptArbitrarySyntax(t *testing.T) {
	if selectionQuery(^uint64(0)) != "*[System[EventRecordID=18446744073709551615]]" {
		t.Fatal("record selector changed")
	}
	_, err := readWith(context.Background(), Request{Events: []Event{fixtureEvent("System", 1)}}, func(ctx context.Context, e Event) (cursor, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > CollectionTimeout {
			t.Fatal("missing finite context")
		}
		return &fixtureCursor{event: e, message: "fixture"}, nil
	})
	if err != nil {
		t.Fatal("bounded request failed")
	}
}
