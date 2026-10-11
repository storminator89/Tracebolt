package windowseventhistory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func fixtureSearch() Search {
	end := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	return Search{Channel: "Application", Start: end.Add(-7 * 24 * time.Hour), End: end}
}
func fixtureEvent(s Search, id uint64) Event {
	return Event{RecordID: id, EventID: 42, Level: 2, Provider: "Synthetic fixture", Timestamp: s.Start.Add(time.Hour), Channel: s.Channel}
}

type fakeCursor struct {
	rows                          []Event
	index, nexts, renders, closed int
	nextErr, closeErr             error
	cancel                        context.CancelFunc
}

func (f *fakeCursor) Next(context.Context) (bool, error) {
	f.nexts++
	if f.nextErr != nil && f.index == len(f.rows) {
		return false, f.nextErr
	}
	if f.index == len(f.rows) {
		return false, nil
	}
	f.index++
	return true, nil
}
func (f *fakeCursor) Metadata() (Event, error) {
	f.renders++
	if f.cancel != nil {
		f.cancel()
	}
	return f.rows[f.index-1], nil
}
func (f *fakeCursor) Close() error { f.closed++; return f.closeErr }
func runSearch(t *testing.T, s Search, f *fakeCursor) (Report, error) {
	t.Helper()
	return searchWith(context.Background(), s, func(context.Context, Search) (cursor, error) { return f, nil })
}
func TestSearchRangeAndTypedXPath(t *testing.T) {
	now := time.Now().UTC()
	s := Search{Channel: "System", Start: now.Add(-MaxLookback), End: now.Add(-MaxLookback + MaxRange)}
	if ValidateSearch(s, now) != nil {
		t.Fatal("exact bounds rejected")
	}
	for _, change := range []func(*Search){func(s *Search) { s.Start = s.Start.Add(-time.Nanosecond) }, func(s *Search) { s.End = s.Start.Add(MaxRange + time.Nanosecond) }, func(s *Search) { s.End = now.Add(time.Second) }, func(s *Search) { s.Channel = "Security" }, func(s *Search) { s.Start = s.End }, func(s *Search) { s.Start = s.Start.In(time.FixedZone("UTC", 0)) }} {
		b := s
		change(&b)
		if ValidateSearch(b, now) == nil {
			t.Fatal("invalid search accepted")
		}
	}
	level := uint8(0)
	id := uint16(65535)
	s.Level = &level
	s.EventID = &id
	xpath, e := searchXPath(s)
	if e != nil || !strings.Contains(xpath, "Level=0 and EventID=65535") || strings.Contains(xpath, "System[System") {
		t.Fatal("fixed typed query failed")
	}
	raw, _ := json.Marshal(s)
	if !strings.Contains(string(raw), `"level":0`) {
		t.Fatal("zero optional filter lost")
	}
	empty := fixtureSearch()
	raw, _ = json.Marshal(empty)
	if strings.Contains(string(raw), `"level":`) || strings.Contains(string(raw), `"eventId":`) {
		t.Fatal("absent optional filters not omitted")
	}
	if ValidateRequest(Request{Search: &s, Events: []Event{fixtureEvent(s, 1)}}) == nil || ValidateRequest(Request{}) == nil {
		t.Fatal("request branches merged")
	}
}
func TestBoundedSearchOnlyRendersHundredWithSingleLookahead(t *testing.T) {
	s := fixtureSearch()
	f := &fakeCursor{}
	for i := 0; i < 105; i++ {
		f.rows = append(f.rows, fixtureEvent(s, uint64(1000-i)))
	}
	r, e := runSearch(t, s, f)
	if e != nil || len(r.Events) != 100 || f.nexts != 101 || f.renders != 100 || f.closed != 1 || r.Complete || !r.Truncated || r.Quality != QualityBounded || ValidateReport(r, Request{Search: &s}) != nil {
		t.Fatalf("bounds or report invalid: next=%d render=%d closed=%d", f.nexts, f.renders, f.closed)
	}
	for _, part := range r.Events {
		if part.Message != "" {
			t.Fatal("search formatted message")
		}
	}
	raw, _ := json.Marshal(r)
	if len(raw) > MaxSearchBytes {
		t.Fatal("byte limit bypass")
	}
}
func TestEmptyExhaustedSearchAndSourceFailureDiffer(t *testing.T) {
	s := fixtureSearch()
	for _, size := range []int{0, 1, 100} {
		f := &fakeCursor{}
		for i := 0; i < size; i++ {
			f.rows = append(f.rows, fixtureEvent(s, uint64(1000-i)))
		}
		r, e := runSearch(t, s, f)
		if e != nil || !r.Complete || r.Truncated || r.Quality != QualityObserved || f.nexts != size+1 || ValidateReport(r, Request{Search: &s}) != nil {
			t.Fatal("exhausted search rejected")
		}
	}
	for _, size := range []int{0, 1} {
		f := &fakeCursor{nextErr: errors.New("secret native diagnostic")}
		if size > 0 {
			f.rows = []Event{fixtureEvent(s, 1)}
		}
		r, e := runSearch(t, s, f)
		if e != ErrReadFailed || r.Reason != ErrReadFailed.Error() || r.Complete || ValidateReport(r, Request{Search: &s}) != nil {
			t.Fatal("failure lost or invalid")
		}
	}
	f := &fakeCursor{rows: []Event{fixtureEvent(s, 1)}, closeErr: ErrAccessDenied}
	r, e := runSearch(t, s, f)
	if e != ErrAccessDenied || r.Quality != QualityPartial || r.Complete || ValidateReport(r, Request{Search: &s}) != nil {
		t.Fatal("close failure reported complete")
	}
}
func TestSearchValidatesEveryReturnedIdentityAndFilter(t *testing.T) {
	s := fixtureSearch()
	lev := uint8(2)
	id := uint16(42)
	s.Level = &lev
	s.EventID = &id
	for _, mutate := range []func(*Event){func(e *Event) { e.Channel = "System" }, func(e *Event) { e.Timestamp = s.End }, func(e *Event) { e.Timestamp = s.Start.Add(-time.Second) }, func(e *Event) { e.Level = 3 }, func(e *Event) { e.EventID = 4 }, func(e *Event) { e.RecordID = 0 }, func(e *Event) { e.Provider = "\x00" }} {
		e := fixtureEvent(s, 1)
		mutate(&e)
		f := &fakeCursor{rows: []Event{e}}
		r, err := runSearch(t, s, f)
		if err != ErrInvalidData || len(r.Events) != 0 || f.closed != 1 || ValidateReport(r, Request{Search: &s}) != nil {
			t.Fatal("invalid source identity survived")
		}
	}
	f := &fakeCursor{rows: []Event{fixtureEvent(s, 1), fixtureEvent(s, 1)}}
	r, e := runSearch(t, s, f)
	if e != ErrInvalidData || len(r.Events) != 1 || r.Complete {
		t.Fatal("duplicate record accepted")
	}
}
func TestSearchCancellationAndUntrustedReports(t *testing.T) {
	s := fixtureSearch()
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeCursor{rows: []Event{fixtureEvent(s, 1)}, cancel: cancel}
	r, e := searchWith(ctx, s, func(context.Context, Search) (cursor, error) { return f, nil })
	if e != context.Canceled || f.closed != 1 || len(r.Events) != 0 || ValidateReport(r, Request{Search: &s}) != nil {
		t.Fatal("cancellation released source data")
	}
	good, _ := runSearch(t, s, &fakeCursor{rows: []Event{fixtureEvent(s, 1)}})
	for _, mutate := range []func(*Report){func(r *Report) { r.Events[0].Message = "secret" }, func(r *Report) { r.Events[0].Complete = false }, func(r *Report) { r.Quality = QualityBounded }, func(r *Report) { r.Search = nil }, func(r *Report) { r.Reason = "native secret" }, func(r *Report) { r.Warning = "" }, func(r *Report) { r.Events[0].Event.Timestamp = s.End }} {
		r := good
		r.Events = append([]Result{}, good.Events...)
		mutate(&r)
		if ValidateReport(r, Request{Search: &s}) == nil {
			t.Fatal("forged report accepted")
		}
	}
	for _, v := range []any{good, Request{Search: &s}, s} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(verb, v), "Synthetic fixture") {
				t.Fatal("diagnostic data leak")
			}
		}
	}
}
