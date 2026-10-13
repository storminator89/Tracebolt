package macoslogwindow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func text(s string) *string { return &s }
func fixtureRequest(t testing.TB) Request {
	t.Helper()
	r, err := DefaultRequest(time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func fixtureProjection(t testing.TB) Projection {
	t.Helper()
	r := fixtureRequest(t)
	captured := r.CreatedAt.Add(time.Second)
	return Projection{ProjectionSchema, r, Observed, "", &captured, []Row{
		{r.Start, text("synthetic-process"), text("example.synthetic"), text("fixture"), text("synthetic message"), false},
	}}
}

func TestRequestTimeBounds(t *testing.T) {
	r := fixtureRequest(t)
	if r.End != r.CreatedAt || r.Start != r.CreatedAt.Add(-DefaultWindow) || r.ExpiresAt != r.CreatedAt.Add(Lifetime) {
		t.Fatal("moving or incorrect default window")
	}
	for name, edit := range map[string]func(*Request){
		"old scope":       func(q *Request) { q.Scope = "basic-readonly-v1" },
		"inventory scope": func(q *Request) { q.Scope = "macos-read-inventory-v1" },
		"windows scope":   func(q *Request) { q.Scope = "windows-application-system-event-history-v1" },
		"old schema":      func(q *Request) { q.SchemaVersion = "tracebolt.macos-read-inventory.v1" },
		"http":            func(q *Request) { q.Transport = "http-test" },
		"zero creation":   func(q *Request) { q.CreatedAt = time.Time{} },
		"local offset":    func(q *Request) { q.Start = q.Start.In(time.FixedZone("offset", 3600)) },
		"alias utc":       func(q *Request) { q.End = q.End.In(time.FixedZone("alias", 0)) },
		"empty interval":  func(q *Request) { q.Start = q.End },
		"reverse":         func(q *Request) { q.Start = q.End.Add(time.Nanosecond) },
		"over fifteen":    func(q *Request) { q.Start = q.End.Add(-MaxWindow - time.Nanosecond) },
		"future":          func(q *Request) { q.End = q.CreatedAt.Add(time.Nanosecond) },
		"too old": func(q *Request) {
			q.Start = q.CreatedAt.Add(-MaxLookback - time.Nanosecond)
			q.End = q.Start.Add(time.Minute)
		},
		"extended expiry": func(q *Request) { q.ExpiresAt = q.ExpiresAt.Add(time.Nanosecond) },
		"short expiry":    func(q *Request) { q.ExpiresAt = q.ExpiresAt.Add(-time.Nanosecond) },
		"year overflow":   func(q *Request) { q.CreatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		t.Run(name, func(t *testing.T) {
			q := r
			edit(&q)
			if err := ValidateRequest(q); err == nil {
				t.Fatal("accepted invalid request")
			}
			if raw, err := EncodeRequest(q); err == nil || raw != nil {
				t.Fatal("encoded invalid request")
			}
		})
	}
	for _, start := range []time.Time{r.CreatedAt.Add(-MaxLookback), r.CreatedAt.Add(-MaxWindow)} {
		q := r
		q.Start, q.End = start, start.Add(MaxWindow)
		if err := ValidateRequest(q); err != nil {
			t.Fatal("rejected exact boundary", err)
		}
	}
	for _, tc := range []struct {
		now  time.Time
		want error
	}{
		{r.CreatedAt, nil}, {r.ExpiresAt.Add(-time.Nanosecond), nil},
		{r.CreatedAt.Add(-time.Nanosecond), ErrClock}, {r.ExpiresAt, ErrExpired},
		{r.ExpiresAt.Add(time.Hour), ErrExpired}, {time.Time{}, ErrClock},
	} {
		if err := ValidateLive(r, tc.now); !errors.Is(err, tc.want) {
			t.Fatalf("live error %v, want %v", err, tc.want)
		}
	}
	if _, err := DefaultRequest(time.Time{}); err == nil {
		t.Fatal("zero default")
	}
}

func TestCanonicalRequest(t *testing.T) {
	r := fixtureRequest(t)
	raw, err := EncodeRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRequest(raw)
	if err != nil || got != r {
		t.Fatal("round trip", err)
	}
	for _, b := range [][]byte{
		nil, []byte("null"), append(bytes.Clone(raw), '\n'), append(bytes.Clone(raw), raw...),
		bytes.Replace(raw, []byte(`"scope":`), []byte(`"scope":"old","scope":`), 1),
		bytes.Replace(raw, []byte(`"transport":`), []byte(`"Transport":`), 1),
		bytes.Replace(raw, []byte(`"tls"`), []byte(`null`), 1),
		bytes.Replace(raw, []byte(`"tls"`), []byte(`"\u0074ls"`), 1),
		bytes.Replace(raw, []byte(`"transport":`), []byte(`"predicate":"TRUEPREDICATE","transport":`), 1),
		bytes.Repeat([]byte(" "), MaxRequestBytes+1),
	} {
		if got, err := DecodeRequest(b); err == nil || got != (Request{}) {
			t.Fatal("accepted noncanonical request")
		}
	}
}

func TestProjectionStatesAndSyntheticFixture(t *testing.T) {
	r := fixtureRequest(t)
	now := r.CreatedAt.Add(2 * time.Second)
	for _, tc := range []struct {
		state, reason string
		capture, rows bool
	}{
		{Observed, "", true, true}, {Observed, "", true, false},
		{Partial, ReasonSourcePartial, true, true}, {Partial, ReasonCandidateLimit, true, false},
		{Denied, ReasonAccessDenied, false, false}, {Unavailable, ReasonUnsupported, false, false},
		{Lost, ReasonLost, false, false},
	} {
		p := fixtureProjection(t)
		p.State, p.Reason = tc.state, tc.reason
		if !tc.capture {
			p.CapturedAt = nil
		}
		if !tc.rows {
			p.Rows = []Row{}
		}
		raw, err := EncodeProjection(p, r, now)
		if err != nil {
			t.Fatal(tc.state, err)
		}
		got, err := DecodeProjection(raw, r, now)
		if err != nil || !reflect.DeepEqual(got, p) {
			t.Fatal("state changed", tc.state, err)
		}
	}
	raw, err := os.ReadFile("testdata/synthetic-projection.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeProjection(raw, r, now)
	if err != nil || !reflect.DeepEqual(got, fixtureProjection(t)) {
		t.Fatal("synthetic fixture differs", err)
	}
}

func TestProjectionFailureTruthAndOriginalBinding(t *testing.T) {
	r := fixtureRequest(t)
	now := r.CreatedAt.Add(2 * time.Second)
	for name, edit := range map[string]func(*Projection){
		"unknown schema":         func(p *Projection) { p.SchemaVersion = "apple.log.json.v1" },
		"unknown state":          func(p *Projection) { p.State = "complete" },
		"nil rows":               func(p *Projection) { p.Rows = nil },
		"unknown reason":         func(p *Projection) { p.State, p.Reason = Partial, "secret native error" },
		"partial without reason": func(p *Projection) { p.State = Partial },
		"false denial":           func(p *Projection) { p.State, p.Reason = Denied, ReasonAccessDenied },
		"false lost":             func(p *Projection) { p.State, p.Reason = Lost, ReasonLost },
		"false empty": func(p *Projection) {
			p.State, p.Reason, p.CapturedAt, p.Rows = Observed, ReasonAccessDenied, nil, []Row{}
		},
		"failed with rows": func(p *Projection) {
			p.State, p.Reason, p.CapturedAt = Unavailable, ReasonUnavailable, nil
		},
		"no capture": func(p *Projection) { p.CapturedAt = nil },
		"early capture": func(p *Projection) {
			x := r.CreatedAt.Add(-time.Nanosecond)
			p.CapturedAt = &x
		},
		"future capture": func(p *Projection) { x := now.Add(time.Nanosecond); p.CapturedAt = &x },
		"window end":     func(p *Projection) { p.Rows[0].Timestamp = r.End },
		"before window":  func(p *Projection) { p.Rows[0].Timestamp = r.Start.Add(-time.Nanosecond) },
		"moved query":    func(p *Projection) { p.Request.Start = r.Start.Add(time.Second) },
		"new age": func(p *Projection) {
			p.Request.CreatedAt = r.CreatedAt.Add(time.Second)
			p.Request.ExpiresAt = p.Request.CreatedAt.Add(Lifetime)
		},
		"oversize message": func(p *Projection) { p.Rows[0].Message = text(strings.Repeat("x", MaxMessageBytes+1)) },
		"oversize label":   func(p *Projection) { p.Rows[0].Process = text(strings.Repeat("x", MaxLabelBytes+1)) },
		"invalid utf8":     func(p *Projection) { p.Rows[0].Message = text(string([]byte{0xff})) },
		"nil truncated":    func(p *Projection) { p.Rows[0].Message = nil; p.Rows[0].MessageTruncated = true },
	} {
		t.Run(name, func(t *testing.T) {
			p := fixtureProjection(t)
			edit(&p)
			if raw, err := EncodeProjection(p, r, now); err == nil || raw != nil {
				t.Fatal("accepted invalid projection")
			}
		})
	}
	p := fixtureProjection(t)
	if raw, err := EncodeProjection(p, r, r.ExpiresAt); !errors.Is(err, ErrExpired) || raw != nil {
		t.Fatal("retry refreshed original expiry", err)
	}
}

func TestTextIsDataAndBoundsAreEncodedBytes(t *testing.T) {
	p := fixtureProjection(t)
	now := p.Request.CreatedAt.Add(time.Minute)
	message := "<script>alert('synthetic')</script>\n&& process == 'x'; $(whoami)\x00é🔒<private>"
	p.Rows[0].Message = &message
	p.Rows[0].Category = text("<img src=x onerror=alert(1)>")
	p.Rows[0].Subsystem = nil
	p.Rows[0].Process = text("")
	raw, err := EncodeProjection(p, p.Request, now)
	if err != nil || bytes.Contains(raw, []byte("<script>")) {
		t.Fatal("HTML escaping", err)
	}
	got, err := DecodeProjection(raw, p.Request, now)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("string data was transformed", err)
	}
	for _, value := range []any{p, &p, p.Rows[0], &p.Rows[0], p.Rows, p.Request} {
		if out := fmt.Sprintf("%v %+v %#v %s", value, value, value, value); strings.Contains(out, "script") || strings.Contains(out, "synthetic-process") {
			t.Fatal("formatter disclosed content")
		}
	}
	p.Rows[0].Message = text(strings.Repeat("é", MaxMessageBytes/2))
	p.Rows[0].MessageTruncated = true
	if _, err := EncodeProjection(p, p.Request, now); err != nil {
		t.Fatal("exact UTF-8 byte limit", err)
	}
	p.Rows = make([]Row, MaxRows)
	for i := range p.Rows {
		p.Rows[i] = Row{Timestamp: p.Request.Start, Message: text("")}
	}
	if _, err := EncodeProjection(p, p.Request, now); err != nil {
		t.Fatal("exact row limit", err)
	}
	p.Rows = append(p.Rows, p.Rows[0])
	if raw, err := EncodeProjection(p, p.Request, now); !errors.Is(err, ErrBounds) || raw != nil {
		t.Fatal("row cutoff returned prefix", err)
	}
	p.Rows = p.Rows[:100]
	for i := range p.Rows {
		p.Rows[i].Message = text(strings.Repeat("<", 1024)) // Escapes to six bytes each.
	}
	if raw, err := EncodeProjection(p, p.Request, now); !errors.Is(err, ErrBounds) || raw != nil {
		t.Fatal("escaped projection exceeds cap", err)
	}
	if got, err := DecodeProjection(bytes.Repeat([]byte("x"), MaxProjectionBytes+1), p.Request, now); !errors.Is(err, ErrBounds) || got.SchemaVersion != "" {
		t.Fatal("oversize parser accepted data", err)
	}
}

func TestProjectionParserRejectsNoncanonicalAndNativeShapes(t *testing.T) {
	p := fixtureProjection(t)
	now := p.Request.CreatedAt.Add(time.Minute)
	raw, err := EncodeProjection(p, p.Request, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{
		[]byte(`[{"timestamp":"2026-10-13 12:00:00+0000","eventMessage":"synthetic"}]`),
		[]byte(`{"eventMessage":"synthetic","processID":42}`), []byte("null"),
		append(bytes.Clone(raw), '\n'), append(bytes.Clone(raw), raw...),
		bytes.Replace(raw, []byte(`"state":`), []byte(`"state":"denied","state":`), 1),
		bytes.Replace(raw, []byte(`"reason":`), []byte(`"predicate":"TRUEPREDICATE","reason":`), 1),
		bytes.Replace(raw, []byte(`"message":`), []byte(`"Message":`), 1),
		bytes.Replace(raw, []byte(`"synthetic message"`), []byte(`"\ud800"`), 1),
		bytes.Replace(raw, []byte(`"synthetic message"`), []byte{'"', 0xff, '"'}, 1),
		bytes.Replace(raw, []byte(`"messageTruncated":false`), []byte(`"messageTruncated":null`), 1),
	} {
		if got, err := DecodeProjection(b, p.Request, now); err == nil || got.SchemaVersion != "" || len(got.Rows) != 0 {
			t.Fatal("returned noncanonical/native input or a failure prefix")
		}
	}
	// Marshaling an invalid Go string must not silently repair it for this API.
	p.Rows[0].Category = text(string([]byte{0xff}))
	if _, err := json.Marshal(p); err != nil {
		t.Fatal("test setup", err)
	}
	if _, err := EncodeProjection(p, p.Request, now); err == nil {
		t.Fatal("accepted repaired UTF-8")
	}
	// A tiny noncanonical row array must hit the limit during decoding, not after
	// materializing and re-encoding potentially hundreds of thousands of Row values.
	oversize := bytes.Replace(raw, []byte(`"rows":[`), []byte(`"rows":[`+strings.Repeat("{},", MaxRows+1)), 1)
	if got, err := DecodeProjection(oversize, p.Request, now); !errors.Is(err, ErrBounds) || got.Rows != nil {
		t.Fatal("row budget was not enforced during decode", err)
	}
}

func TestExactEncodedProjectionBoundary(t *testing.T) {
	p := fixtureProjection(t)
	now := p.Request.CreatedAt.Add(time.Minute)
	p.Rows = make([]Row, 128)
	for i := range p.Rows {
		p.Rows[i] = Row{Timestamp: p.Request.Start, Message: text("")}
	}
	base, err := EncodeProjection(p, p.Request, now)
	if err != nil {
		t.Fatal(err)
	}
	remaining := MaxProjectionBytes - len(base)
	last := -1
	for i := range p.Rows {
		n := min(remaining, MaxMessageBytes)
		p.Rows[i].Message = text(strings.Repeat("x", n))
		remaining -= n
		if n < MaxMessageBytes {
			last = i
		}
	}
	if remaining != 0 || last < 0 {
		t.Fatal("boundary fixture has insufficient capacity")
	}
	raw, err := EncodeProjection(p, p.Request, now)
	if err != nil || len(raw) != MaxProjectionBytes {
		t.Fatal("exact encoded boundary rejected", err)
	}
	if got, err := DecodeProjection(raw, p.Request, now); err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("exact parser boundary rejected", err)
	}
	p.Rows[last].Message = text(*p.Rows[last].Message + "x")
	if got, err := EncodeProjection(p, p.Request, now); !errors.Is(err, ErrBounds) || got != nil {
		t.Fatal("one-byte-over encode accepted", err)
	}
	raw, err = json.Marshal(p)
	if err != nil || len(raw) != MaxProjectionBytes+1 {
		t.Fatal("over-boundary fixture incorrect", err)
	}
	if got, err := DecodeProjection(raw, p.Request, now); !errors.Is(err, ErrBounds) || got.Rows != nil {
		t.Fatal("one-byte-over decode accepted", err)
	}
}

func FuzzProjection(f *testing.F) {
	p := fixtureProjection(f)
	now := p.Request.CreatedAt.Add(time.Minute)
	raw, err := EncodeProjection(p, p.Request, now)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte("null"))
	f.Add([]byte(`[{"eventMessage":"synthetic"}]`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := DecodeProjection(raw, p.Request, now)
		if err != nil {
			if got.SchemaVersion != "" || len(got.Rows) != 0 {
				t.Fatal("failure returned content")
			}
			return
		}
		encoded, err := EncodeProjection(got, p.Request, now)
		if err != nil || !bytes.Equal(raw, encoded) {
			t.Fatal("accepted noncanonical input", err)
		}
	})
}
