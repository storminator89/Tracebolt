package windowsvolumes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func consent() Consent {
	return Consent{ConsentVersion, Scope, strings.Repeat("b", 64), strings.Repeat("a", 32), true}
}
func generation() string { return "sample_" + strings.Repeat("c", 32) }
func guid(i int) string  { return fmt.Sprintf(`\\?\Volume{00000000-0000-0000-0000-%012x}\`, i) }

var stamp = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

type fakeCursor struct {
	count, index, reads    int
	closed                 bool
	nextErr, errorCapacity error
	cancel                 context.CancelFunc
	drive                  string
}

func (f *fakeCursor) Next(context.Context) (string, error) {
	if f.index >= f.count {
		if f.nextErr != nil {
			return "", f.nextErr
		}
		return "", io.EOF
	}
	f.index++
	return guid(f.index), nil
}
func (f *fakeCursor) DriveType(context.Context, string) (string, error) {
	if f.drive != "" {
		return f.drive, ErrDriveType
	}
	return "fixed", nil
}
func (f *fakeCursor) Capacity(context.Context, string) (uint64, uint64, uint64, error) {
	f.reads++
	if f.cancel != nil {
		f.cancel()
	}
	return 100, 200, 50, f.errorCapacity
}
func (f *fakeCursor) Close() error { f.closed = true; return nil }
func collectFake(t *testing.T, f *fakeCursor) Snapshot {
	t.Helper()
	s, e := collectUsing(context.Background(), generation(), consent(), consent().SenderBinding, func(context.Context) (cursor, error) { return f, nil }, func() time.Time { return stamp })
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestConsentAndCanonical(t *testing.T) {
	c := consent()
	b, e := EncodeConsent(c, c.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeConsent(b, c.SenderBinding); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(b, ' '), []byte(strings.Replace(string(b), `"enabled":true`, `"enabled":true,"enabled":true`, 1)), []byte(strings.Replace(string(b), `"enabled":true`, `"enabled":true,"other":1`, 1))} {
		if _, e = DecodeConsent(bad, c.SenderBinding); e == nil {
			t.Fatal("accepted noncanonical consent")
		}
	}
	if _, e = DecodeConsent(b, strings.Repeat("d", 64)); e == nil {
		t.Fatal("foreign binding")
	}
}
func TestObservedQuotaAndEmpty(t *testing.T) {
	for _, count := range []int{0, 1} {
		f := &fakeCursor{count: count}
		s := collectFake(t, f)
		if !s.Complete || !s.CountExact || s.Quality != "observed" || s.CollectedAt != stamp || !f.closed {
			t.Fatalf("%+v", s)
		}
		b, _ := json.Marshal(s)
		if _, e := Decode(b); e != nil {
			t.Fatal(e)
		}
		if count > 0 && s.Rows[0].Capacity.FreeBytes != "200" {
			t.Fatal("quota free must be distinct")
		}
	}
}
func TestBoundsAndCounts(t *testing.T) {
	for _, n := range []int{64, 65, 128, 129} {
		f := &fakeCursor{count: n}
		s := collectFake(t, f)
		want := n
		if want > 128 {
			want = 128
		}
		if int(s.ObservedCount) != want || len(s.Rows) > 64 || f.index > 128 || f.reads > 128 || !f.closed {
			t.Fatalf("%d: %+v", n, s)
		}
		if n >= 128 && s.CountExact {
			t.Fatal("cap cannot prove exact")
		}
		if n < 128 && !s.CountExact {
			t.Fatal("EOF proves count")
		}
		if !s.Truncated || s.Complete || s.Quality != "bounded" {
			t.Fatal("byte/row trimming must be explicit")
		}
		b, _ := json.Marshal(s)
		if len(b) > MaxBytes {
			t.Fatal("bytes cap")
		}
	}
}
func TestFailuresAndScope(t *testing.T) {
	for _, e := range []error{ErrDenied, ErrUnavailable, ErrUnsupported} {
		s, err := collectUsing(context.Background(), generation(), consent(), consent().SenderBinding, func(context.Context) (cursor, error) { return nil, e }, func() time.Time { return stamp })
		if err != nil || s.Complete || s.CountExact || len(s.Rows) != 0 || s.Reason != e.Error() {
			t.Fatalf("%+v %v", s, err)
		}
	}
	f := &fakeCursor{count: 2, nextErr: ErrDenied, errorCapacity: ErrDenied}
	s := collectFake(t, f)
	if s.Quality != "partial" || s.CountExact || s.Rows[0].Quality != "denied" || s.Rows[0].Capacity != nil {
		t.Fatalf("%+v", s)
	}
	f = &fakeCursor{count: 1, drive: "unknown"}
	s = collectFake(t, f)
	if f.reads != 0 || s.Rows[0].Reason != ErrDriveType.Error() {
		t.Fatal("unsupported drive must not probe capacity")
	}
}
func TestNoReadWithoutConsentOrAfterCancel(t *testing.T) {
	for _, mode := range []string{"disabled", "foreign", "generation", "cancel"} {
		c := consent()
		binding := c.SenderBinding
		g := generation()
		ctx, cancel := context.WithCancel(context.Background())
		switch mode {
		case "disabled":
			c.Enabled = false
		case "foreign":
			binding = strings.Repeat("d", 64)
		case "generation":
			g = "bad"
		case "cancel":
			cancel()
		}
		_, err := collectUsing(ctx, g, c, binding, func(context.Context) (cursor, error) { t.Fatal("read without consent"); return nil, nil }, time.Now)
		cancel()
		if err == nil {
			t.Fatal(mode)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeCursor{count: 100, cancel: cancel}
	_, err := collectUsing(ctx, generation(), consent(), consent().SenderBinding, func(context.Context) (cursor, error) { return f, nil }, time.Now)
	if !errors.Is(err, context.Canceled) || !f.closed || f.reads != 1 {
		t.Fatal("cancellation/close")
	}
}
func TestRejectMalformedSnapshot(t *testing.T) {
	base := collectFake(t, &fakeCursor{count: 1})
	cases := []func(*Snapshot){func(s *Snapshot) { s.Rows[0].VolumeID = `C:\` }, func(s *Snapshot) { s.Rows[0].VolumeID = strings.ToUpper(guid(10)) }, func(s *Snapshot) { s.Rows[0].Capacity.TotalBytes = "01" }, func(s *Snapshot) { s.Rows[0].Capacity.AvailableBytes = "101" }, func(s *Snapshot) { s.Rows[0].Capacity.FreeBytes = "18446744073709551616" }, func(s *Snapshot) { s.Rows[0].Reason = "private path" }, func(s *Snapshot) { s.Rows[0].Quality = "denied" }, func(s *Snapshot) { s.CountExact = false }, func(s *Snapshot) { s.Rows = append(s.Rows, s.Rows[0]); s.ObservedCount = 2 }}
	raw, _ := json.Marshal(base)
	for i, mut := range cases {
		var s Snapshot
		json.Unmarshal(raw, &s)
		mut(&s)
		if Validate(s) == nil {
			t.Fatalf("accepted %d", i)
		}
	}
	for _, bad := range []string{string(raw) + " ", strings.Replace(string(raw), `"scope":`, `"unknown":1,"scope":`, 1), strings.Replace(string(raw), `"complete":true`, `"complete":true,"complete":true`, 1)} {
		if _, err := Decode([]byte(bad)); err == nil {
			t.Fatal("accepted noncanonical")
		}
	}
}

func TestFitBudgetRetainsTruth(t *testing.T) {
	for _, e := range []error{nil, ErrDenied} {
		s := collectFake(t, &fakeCursor{count: 3, nextErr: e})
		original, _ := json.Marshal(s)
		fit, err := FitBudget(s, 450)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(fit)
		if len(b) > 450 || fit.ObservedCount != 3 || fit.CountExact != s.CountExact || fit.CollectedAt != s.CollectedAt || !fit.Truncated || fit.Complete {
			t.Fatalf("%+v", fit)
		}
		after, _ := json.Marshal(s)
		if string(original) != string(after) {
			t.Fatal("mutated input")
		}
		if _, err = FitBudget(s, 1); err == nil {
			t.Fatal("impossible budget")
		}
	}
}

func TestFullUint64AndBoundedContradictions(t *testing.T) {
	s := collectFake(t, &fakeCursor{count: 1})
	s.Rows[0].Capacity = &Capacity{"18446744073709551615", "18446744073709551615", "18446744073709551615"}
	if Validate(s) != nil {
		t.Fatal("full uint64 precision")
	}
	s.Quality = "bounded"
	s.Complete = false
	s.Truncated = true
	if Validate(s) == nil {
		t.Fatal("bounded exact count without omitted row")
	}
	s.CountExact = false
	if Validate(s) == nil {
		t.Fatal("native cap must preserve 128 lower bound")
	}
	s.ObservedCount = 128
	if Validate(s) != nil {
		t.Fatal("bounded native cap")
	}
}
func TestDeadlineAndRowUnavailable(t *testing.T) {
	s := collectFake(t, &fakeCursor{count: 1, nextErr: context.DeadlineExceeded, errorCapacity: ErrUnavailable})
	if s.Quality != "partial" || s.Reason != context.DeadlineExceeded.Error() || s.Rows[0].Capacity != nil || s.Rows[0].Quality != "unavailable" {
		t.Fatalf("%+v", s)
	}
}

func TestUnknownTypeNeverHasCapacity(t *testing.T) {
	s := collectFake(t, &fakeCursor{count: 1})
	s.Rows[0].DriveType = "unknown"
	if Validate(s) == nil {
		t.Fatal("unknown type must not have observed capacity")
	}
	s.Rows[0].Quality = "unavailable"
	s.Rows[0].Capacity = nil
	s.Rows[0].Reason = ErrDriveType.Error()
	if Validate(s) != nil {
		t.Fatal("unknown unsupported type must remain representable")
	}
	s.Rows[0].DriveType = "fixed"
	if Validate(s) == nil {
		t.Fatal("unsupported drive type reason must map unknown")
	}
	s.Rows[0].DriveType = "unknown"
	s.Rows[0].Reason = ErrDenied.Error()
	s.Rows[0].Quality = "denied"
	if Validate(s) != nil {
		t.Fatal("denied type query must remain representable")
	}
}
