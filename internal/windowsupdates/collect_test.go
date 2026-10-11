package windowsupdates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

const generation = "sample_0123456789abcdef0123456789abcdef"
const grant = "0123456789abcdef0123456789abcdef"
const binding = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var epoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func request() Request {
	return Request{Consent: Consent{SchemaVersion: ConsentVersion, Scope: Scope, SenderBinding: binding, GrantID: grant, Enabled: true}, SenderBinding: binding, GenerationID: generation, CollectedAt: epoch}
}
func row(n int) Update {
	return Update{UpdateID: fmt.Sprintf("12345678-1234-1234-1234-%012x", n), Revision: 3, Title: "Synthetic security update", KBArticleIDs: []string{"KB1234567"}, Severity: "important", Downloaded: true}
}

type fakeSource struct {
	calls           []string
	fail            string
	err             error
	online, upgrade bool
	closed          int
	result          *fakeResult
	hook            func(string)
}

func (f *fakeSource) call(name string) error {
	f.calls = append(f.calls, name)
	if f.hook != nil {
		f.hook(name)
	}
	if f.fail == name {
		return f.err
	}
	return nil
}
func (f *fakeSource) SetOnline(_ context.Context, v bool) error {
	if v {
		panic("online collection requested")
	}
	return f.call("set-offline")
}
func (f *fakeSource) Online(context.Context) (bool, error) { return f.online, f.call("get-online") }
func (f *fakeSource) SetAutomaticUpgrade(_ context.Context, v bool) error {
	if v {
		panic("WUA upgrade requested")
	}
	return f.call("set-no-upgrade")
}
func (f *fakeSource) AutomaticUpgrade(context.Context) (bool, error) {
	return f.upgrade, f.call("get-upgrade")
}
func (f *fakeSource) Search(_ context.Context, s string) (Result, error) {
	if s != SearchCriteria {
		panic("unreviewed search")
	}
	if e := f.call("search"); e != nil {
		return nil, e
	}
	if f.result == nil {
		return nil, nil
	}
	return f.result, nil
}
func (f *fakeSource) Close() { f.closed++ }
func (f *fakeSource) open(context.Context) (Source, error) {
	if e := f.call("open"); e != nil {
		return nil, e
	}
	return f, nil
}

type fakeResult struct {
	code, count       int32
	rows              []Update
	calls             []int32
	closed            int
	codeErr, countErr error
	itemErr           map[int32]error
	hook              func(int32)
}

func (f *fakeResult) Code(context.Context) (int32, error)  { return f.code, f.codeErr }
func (f *fakeResult) Count(context.Context) (int32, error) { return f.count, f.countErr }
func (f *fakeResult) Item(_ context.Context, i int32) (Update, error) {
	f.calls = append(f.calls, i)
	if f.hook != nil {
		f.hook(i)
	}
	if e := f.itemErr[i]; e != nil {
		return Update{}, e
	}
	if int(i) < len(f.rows) {
		return f.rows[i], nil
	}
	return row(int(i) + 1), nil
}
func (f *fakeResult) Close()       { f.closed++ }
func fake(count int32) *fakeSource { return &fakeSource{result: &fakeResult{code: 2, count: count}} }
func mustCollect(t *testing.T, f *fakeSource) Snapshot {
	t.Helper()
	s, e := CollectWithSource(context.Background(), request(), f.open)
	if e != nil {
		t.Fatal(e)
	}
	if e = Validate(s); e != nil {
		t.Fatalf("invalid result: %+v", s)
	}
	return s
}

func TestOfflineControlsBeforeFixedSearch(t *testing.T) {
	f := fake(2)
	s := mustCollect(t, f)
	if !reflect.DeepEqual(f.calls, []string{"open", "set-offline", "get-online", "set-no-upgrade", "get-upgrade", "search"}) {
		t.Fatal(f.calls)
	}
	if f.closed != 1 || f.result.closed != 1 || s.Quality != "observed" || !s.CountExact || s.ObservedCount != 2 || s.Truncated || len(s.Rows) != 2 || s.CacheFreshness != "unknown" || !s.CollectedAt.Equal(epoch) {
		t.Fatalf("%+v", s)
	}
	if e := ValidateBinding(s, generation, grant, epoch); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Snapshot){func(s *Snapshot) { s.GenerationID = "sample_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, func(s *Snapshot) { s.GrantID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, func(s *Snapshot) { s.CollectedAt = s.CollectedAt.Add(time.Second) }} {
		v := s
		change(&v)
		if ValidateBinding(v, generation, grant, epoch) == nil {
			t.Fatal("binding mismatch accepted")
		}
	}
}
func TestNoSourceBeforeValidEnabledConsent(t *testing.T) {
	changes := []func(*Request){func(r *Request) { r.Consent.Enabled = false }, func(r *Request) { r.Consent = Consent{} }, func(r *Request) { r.Consent.Scope = "windows-network-endpoints-v1" }, func(r *Request) { r.SenderBinding = strings.Repeat("b", 64) }, func(r *Request) { r.Consent.GrantID = "" }, func(r *Request) { r.GenerationID = "" }, func(r *Request) { r.CollectedAt = time.Time{} }, func(r *Request) { r.CollectedAt = r.CollectedAt.In(time.FixedZone("UTC", 0)) }}
	for i, change := range changes {
		r := request()
		change(&r)
		f := fake(1)
		if _, e := CollectWithSource(context.Background(), r, f.open); e == nil || len(f.calls) != 0 {
			t.Fatalf("case %d read without valid grant: %v %v", i, e, f.calls)
		}
	}
	f := fake(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := CollectWithSource(ctx, request(), f.open); e != context.Canceled || len(f.calls) != 0 {
		t.Fatal(e, f.calls)
	}
	if _, e := CollectWithSource(nil, request(), f.open); e != ErrInvalid {
		t.Fatal(e)
	}
	if _, e := CollectWithSource(context.Background(), request(), nil); e != ErrInvalid {
		t.Fatal(e)
	}
}
func TestMandatoryOfflineControlsFailClosed(t *testing.T) {
	for _, name := range []string{"open", "set-offline", "get-online", "set-no-upgrade", "get-upgrade", "search"} {
		t.Run(name, func(t *testing.T) {
			f := fake(2)
			f.fail = name
			f.err = errors.New("vendor secret path c:\\private\\token")
			s := mustCollect(t, f)
			if s.Quality != "unavailable" || s.Reason != ErrUnavailable.Error() || len(s.Rows) != 0 || s.CountExact || f.calls[len(f.calls)-1] != name {
				t.Fatal(s, f.calls)
			}
			if name != "open" && f.closed != 1 {
				t.Fatal("source leaked")
			}
			if f.result.closed != 0 {
				t.Fatal("unopened result closed")
			}
			b, _ := Encode(s)
			if strings.Contains(string(b), "secret") {
				t.Fatal("raw error leaked")
			}
		})
	}
	for _, online := range []bool{true, false} {
		f := fake(2)
		f.online = online
		f.upgrade = !online
		s := mustCollect(t, f)
		if s.Reason != ErrOffline.Error() {
			t.Fatal(s)
		}
		for _, c := range f.calls {
			if c == "search" {
				t.Fatal("searched before offline verification")
			}
		}
	}
	f := fake(2)
	f.fail = "set-offline"
	f.err = ErrDenied
	s := mustCollect(t, f)
	if s.Quality != "denied" || s.Reason != ErrDenied.Error() {
		t.Fatal(s)
	}
}
func TestCancellationAfterEveryControlStopsBeforeNextCall(t *testing.T) {
	for _, name := range []string{"open", "set-offline", "get-online", "set-no-upgrade", "get-upgrade", "search"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := fake(2)
			f.hook = func(s string) {
				if s == name {
					cancel()
				}
			}
			s, e := CollectWithSource(ctx, request(), f.open)
			if e != context.Canceled || !reflect.DeepEqual(s, Snapshot{}) || f.calls[len(f.calls)-1] != name || f.closed != 1 {
				t.Fatal(s, e, f.calls, f.closed)
			}
		})
	}
}
func TestResultTruthAndNoCleanConclusionFromEmptyCache(t *testing.T) {
	f := fake(0)
	s := mustCollect(t, f)
	if s.Quality != "observed" || s.CacheFreshness != "unknown" || !s.CountExact || len(s.Rows) != 0 {
		t.Fatal(s)
	}
	f = fake(0)
	f.result.code = 3
	s = mustCollect(t, f)
	if s.Quality != "partial" || s.CountExact || s.Reason != ErrPartial.Error() {
		t.Fatal(s)
	}
	for _, code := range []int32{-1, 0, 1, 4, 5, 6} {
		f = fake(10)
		f.result.code = code
		s = mustCollect(t, f)
		if s.Quality != "unavailable" || s.ObservedCount != 0 || len(f.result.calls) != 0 || f.result.closed != 1 {
			t.Fatal(code, s)
		}
	}
	for _, which := range []string{"code", "count", "negative-count"} {
		f = fake(2)
		switch which {
		case "code":
			f.result.codeErr = ErrDenied
		case "count":
			f.result.countErr = ErrUnavailable
		case "negative-count":
			f.result.count = -1
		}
		s = mustCollect(t, f)
		if s.ObservedCount != 0 || len(f.result.calls) != 0 {
			t.Fatal(which, s)
		}
	}
}
func TestNativeTraversalRowAndFrameBounds(t *testing.T) {
	f := fake(1<<31 - 1)
	s := mustCollect(t, f)
	if len(f.result.calls) != MaxNativeRows || len(s.Rows) != MaxRows || !s.CountExact || s.ObservedCount != 1<<31-1 || !s.Truncated {
		t.Fatal(s, len(f.result.calls))
	}
	f = fake(MaxRows)
	f.result.rows = make([]Update, MaxRows)
	for i := range f.result.rows {
		u := row(MaxRows - i)
		u.Title = strings.Repeat("界", MaxTitleBytes/3)
		u.KBArticleIDs = []string{"KB1234567890", "KB2345678901", "KB3456789012", "KB4567890123", "KB5678901234", "KB6789012345", "KB7890123456", "KB8901234567"}
		f.result.rows[i] = u
	}
	s = mustCollect(t, f)
	b, e := Encode(s)
	if e != nil || len(b) > MaxBytes || !s.Truncated || len(s.Rows) >= MaxRows || s.ObservedCount != MaxRows {
		t.Fatal(len(b), e, s)
	}
	for i := 1; i < len(s.Rows); i++ {
		if !less(s.Rows[i-1], s.Rows[i]) {
			t.Fatal("rows not sorted")
		}
	}
}
func TestBadRowsStayPartialAndErrorReasonsSanitized(t *testing.T) {
	f := fake(4)
	f.result.itemErr = map[int32]error{1: errors.New("private token secret"), 3: ErrDenied}
	f.result.rows = []Update{row(1), row(2), row(1), row(4)}
	s := mustCollect(t, f)
	if s.Quality != "partial" || s.Reason != ErrDenied.Error() || !s.CountExact || s.ObservedCount != 4 || len(s.Rows) != 1 || !s.Truncated {
		t.Fatal(s)
	}
	f = fake(1)
	f.result.rows = []Update{row(1)}
	f.result.rows[0].UpdateID = "url-or-host-secret"
	s = mustCollect(t, f)
	if len(s.Rows) != 0 || s.Reason != ErrMetadata.Error() || s.Quality != "partial" {
		t.Fatal(s)
	}
	f = fake(1)
	f.result.itemErr = map[int32]error{0: context.DeadlineExceeded}
	s = mustCollect(t, f)
	if s.Reason != ErrBudget.Error() {
		t.Fatal(s)
	}
}
func TestCanceledRowsReturnNoSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := fake(4)
	f.result.hook = func(i int32) {
		if i == 1 {
			cancel()
		}
	}
	s, e := CollectWithSource(ctx, request(), f.open)
	if e != context.Canceled || !reflect.DeepEqual(s, Snapshot{}) || len(f.result.calls) != 2 || f.result.closed != 1 || f.closed != 1 {
		t.Fatal(s, e, f)
	}
}
func TestSourceNilAndFailureOwnership(t *testing.T) {
	s, e := CollectWithSource(context.Background(), request(), func(context.Context) (Source, error) { return nil, nil })
	if e != nil || s.Reason != ErrUnavailable.Error() {
		t.Fatal(s, e)
	}
	f := fake(1)
	s, e = CollectWithSource(context.Background(), request(), func(context.Context) (Source, error) { return f, ErrDenied })
	if e != nil || f.closed != 1 || s.Quality != "denied" {
		t.Fatal(s, e, f.closed)
	}
	f = fake(1)
	f.result = nil
	s = mustCollect(t, f)
	if s.Quality != "unavailable" || f.closed != 1 {
		t.Fatal(s)
	}
}
func TestSanitizedMetadata(t *testing.T) {
	u := row(1)
	u.UpdateID = strings.ToUpper(u.UpdateID)
	u.Title = " \tPatch\r\n \u202eupdate\x00\u2066  ✓  "
	u.KBArticleIDs = []string{"1234567", "KB7654321", "KB1234567"}
	u.Severity = "Critical"
	got, e := normalize(u)
	if e != nil || got.Title != "Patch update ✓" || got.Severity != "critical" || !reflect.DeepEqual(got.KBArticleIDs, []string{"KB1234567", "KB7654321"}) {
		t.Fatal(got, e)
	}
	if u.KBArticleIDs[0] != "1234567" {
		t.Fatal("normalization mutated source slice")
	}
	u = row(1)
	u.Title = strings.Repeat("界", 200)
	got, e = normalize(u)
	if e != nil || len(got.Title) > MaxTitleBytes || !got.MetadataTruncated {
		t.Fatal(got, e)
	}
	u = row(1)
	u.KBArticleIDs = nil
	u.Severity = ""
	got, e = normalize(u)
	if e != nil || got.KBArticleIDs == nil || got.Severity != "unspecified" {
		t.Fatal(got, e)
	}
	for name, change := range map[string]func(*Update){"uuid": func(u *Update) { u.UpdateID = "00000000-0000-0000-0000-000000000000" }, "revision": func(u *Update) { u.Revision = 1 << 31 }, "empty-title": func(u *Update) { u.Title = "\u202e\x00" }, "utf8": func(u *Update) { u.Title = "\xff" }, "huge-title": func(u *Update) { u.Title = strings.Repeat("x", MaxNativeStringUnits*4+1) }, "bad-kb": func(u *Update) { u.KBArticleIDs = []string{"KB0123"} }, "url-kb": func(u *Update) { u.KBArticleIDs = []string{"http://x"} }, "many-kb": func(u *Update) { u.KBArticleIDs = make([]string, MaxKBArticles+1) }, "severity": func(u *Update) { u.Severity = "secret string" }, "oversized-severity": func(u *Update) { u.Severity = strings.Repeat("A", 8192) }} {
		u = row(1)
		change(&u)
		if _, e := normalize(u); e == nil {
			t.Fatal(name)
		}
	}
}
func TestCanonicalSnapshotAndConsent(t *testing.T) {
	s := mustCollect(t, fake(2))
	b, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	round, e := Decode(b)
	if e != nil || !reflect.DeepEqual(round, s) {
		t.Fatal(e)
	}
	bad := []string{string(b) + " ", strings.Replace(string(b), `"source":"wua-cache"`, `"source":"live"`, 1), strings.Replace(string(b), `"cacheFreshness":"unknown"`, `"cacheFreshness":"fresh"`, 1), strings.Replace(string(b), `"scope":`, `"extra":true,"scope":`, 1), strings.Replace(string(b), `"countExact":true`, `"countExact":null`, 1), strings.Replace(string(b), `"observedCount":2`, `"observedCount":2,"observedCount":2`, 1), strings.Replace(string(b), `"observedCount":2`, `"observedCount":2147483648`, 1), strings.Replace(string(b), `"truncated":false`, `"truncated":true`, 1), strings.Replace(string(b), `"quality":"observed"`, `"quality":"clean"`, 1), strings.Replace(string(b), `"collectedAt":"2026-10-10T12:00:00Z"`, `"collectedAt":"2026-10-10T12:00:00+00:00"`, 1)}
	for i, raw := range bad {
		if _, e := Decode([]byte(raw)); e == nil {
			t.Fatal("accepted noncanonical snapshot", i)
		}
	}
	c := request().Consent
	cb, e := EncodeConsent(c, binding)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := DecodeConsent(cb, binding); e != nil || got != c {
		t.Fatal(got, e)
	}
	for _, raw := range []string{string(cb) + " ", strings.Replace(string(cb), `"enabled":true`, `"enabled":null`, 1), strings.Replace(string(cb), Scope, "windows-network-endpoints-v1", 1), strings.Replace(string(cb), `"scope":`, `"scope":"other","scope":`, 1)} {
		if _, e := DecodeConsent([]byte(raw), binding); e == nil {
			t.Fatal("accepted bad consent")
		}
	}
	if _, e := DecodeConsent(cb, strings.Repeat("a", 64)); e == nil {
		t.Fatal("accepted wrong binding")
	}
}
func TestFitPreservesIdentityAgeCountsAndOwnsNestedSlices(t *testing.T) {
	s := mustCollect(t, fake(3))
	before, _ := json.Marshal(s)
	b, _ := Encode(s)
	smaller, e := FitBudget(s, len(b)-1)
	if e != nil || len(smaller.Rows) != 2 || !smaller.Truncated || smaller.ObservedCount != 3 || smaller.GrantID != s.GrantID || smaller.GenerationID != s.GenerationID || !smaller.CollectedAt.Equal(s.CollectedAt) || smaller.Quality != s.Quality || smaller.CacheFreshness != s.CacheFreshness {
		t.Fatal(smaller, e)
	}
	smaller.Rows[0].KBArticleIDs[0] = "KB9999999"
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("mutated input")
	}
	if _, e := FitBudget(s, 1); e != ErrBounds {
		t.Fatal(e)
	}
	if _, e := FitBudget(s, 0); e != ErrInvalid {
		t.Fatal(e)
	}
}
func TestRejectContradictorySnapshot(t *testing.T) {
	for name, change := range map[string]func(*Snapshot){"null-rows": func(s *Snapshot) { s.Rows = nil }, "count-underflow": func(s *Snapshot) { s.ObservedCount = 0 }, "dup-row": func(s *Snapshot) { s.Rows[1] = s.Rows[0] }, "unsorted": func(s *Snapshot) { s.Rows[0], s.Rows[1] = s.Rows[1], s.Rows[0] }, "raw-title": func(s *Snapshot) { s.Rows[0].Title = "danger\u202e" }, "dup-kb": func(s *Snapshot) { s.Rows[0].KBArticleIDs = []string{"KB1234", "KB1234"} }, "partial-without-reason": func(s *Snapshot) { s.Quality = "partial" }, "denied-with-data": func(s *Snapshot) { s.Quality = "denied"; s.Reason = ErrDenied.Error() }, "reason-content": func(s *Snapshot) { s.Quality = "partial"; s.Reason = "secret" }, "exact-observed": func(s *Snapshot) { s.CountExact = false }} {
		s := mustCollect(t, fake(2))
		change(&s)
		if Validate(s) == nil {
			t.Fatal(name)
		}
	}
}
func FuzzSnapshotDecode(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"scope":"windows-cached-update-inspection-v1"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, e := Decode(b)
		if e != nil {
			return
		}
		encoded, e := Encode(s)
		if e != nil || !reflect.DeepEqual(encoded, b) {
			t.Fatal("noncanonical decode")
		}
	})
}
