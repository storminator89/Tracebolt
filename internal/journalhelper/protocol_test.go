package journalhelper

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"localrmm/internal/journalview"
)

func sampleRequest() Request {
	return Request{Operation: QueryOperation, SenderBinding: strings.Repeat("a", 64), Query: journalview.Query{Unit: "demo.service", Start: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC), End: time.Date(2026, 10, 4, 12, 1, 0, 0, time.UTC), MaxPriority: 4}}
}
func TestProtocolRoundTripAndStrictInput(t *testing.T) {
	query := sampleRequest()
	verify := query
	verify.Operation = VerifyOperation
	verify.PolicyDigest = "sha256:" + strings.Repeat("b", 64)
	verify.Revision = "sha256:" + strings.Repeat("c", 64)
	for _, r := range []Request{query, verify} {
		b, e := EncodeRequest(r)
		if e != nil {
			t.Fatal(e)
		}
		got, e := readRequest(bytes.NewReader(b))
		if e != nil || got != r {
			t.Fatalf("roundtrip: %v", e)
		}
	}
	valid, _ := EncodeRequest(query)
	variants := map[string][]byte{"empty": nil, "truncated": valid[:len(valid)-1], "extra-unit-byte": append(append([]byte{}, valid...), 0)}
	for name, index := range map[string]int{"magic": 0, "operation": 8, "zero-unit": 105, "priority": 123, "unit-path": 124} {
		b := append([]byte{}, valid...)
		b[index] = 255
		variants[name] = b
	}
	b := append([]byte{}, valid...)
	binary.BigEndian.PutUint32(b[4:8], MaxRequestBytes)
	variants["request-ceiling"] = b
	b = append([]byte{}, valid...)
	b[41] = 1
	variants["query-carries-digest"] = b
	// Extra trailing bytes form another frame, which the server never processes;
	// a length that explicitly includes them is rejected.
	b = variants["extra-unit-byte"]
	binary.BigEndian.PutUint32(b[4:8], uint32(len(b)-8))
	for n, b := range variants {
		t.Run(n, func(t *testing.T) {
			if _, e := readRequest(bytes.NewReader(b)); e == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	for _, mutate := range []func(*Request){func(r *Request) { r.Operation = 0 }, func(r *Request) { r.SenderBinding = strings.Repeat("0", 64) }, func(r *Request) { r.SenderBinding = "sha256:" + r.SenderBinding }, func(r *Request) { r.Query.Unit = "/etc/passwd" }, func(r *Request) { r.Query.MaxPriority = 8 }, func(r *Request) { r.PolicyDigest = "sha256:" + strings.Repeat("b", 64) }, func(r *Request) { r.Query.Start = r.Query.End }} {
		r := query
		mutate(&r)
		if _, e := EncodeRequest(r); e == nil {
			t.Fatal("invalid request encoded")
		}
	}
}
func TestResponseBoundAndIncompleteFrame(t *testing.T) {
	r := Response{Status: StatusSnapshot, PolicyDigest: "sha256:" + strings.Repeat("a", 64), Revision: "sha256:" + strings.Repeat("b", 64), body: &responseBody{raw: []byte(`{"safe":"fixture"}`)}}
	h, e := responseHeader(r)
	if e != nil {
		t.Fatal(e)
	}
	got, e := ReadResponse(bytes.NewReader(append(h, r.Body()...)))
	if e != nil || !bytes.Equal(got.Body(), r.Body()) {
		t.Fatal("response framing")
	}
	if _, e := ReadResponse(bytes.NewReader(h)); e == nil {
		t.Fatal("accepted incomplete content")
	}
	bad := append([]byte{}, h...)
	binary.BigEndian.PutUint32(bad[69:], MaxResponseBytes+1)
	if _, e := ReadResponse(bytes.NewReader(bad)); e == nil {
		t.Fatal("oversize accepted")
	}
	for _, r := range []Response{{Status: 255}, {Status: StatusVerified}, {Status: StatusDenied, body: &responseBody{raw: []byte("raw error")}}, {Status: StatusDenied, PolicyDigest: "sha256:" + strings.Repeat("a", 64)}, {Status: StatusSnapshot, body: &responseBody{raw: make([]byte, MaxResponseBytes+1)}}} {
		if _, e := responseHeader(r); e == nil {
			t.Fatal("invalid response")
		}
	}
	if strings.Contains(r.String(), "fixture") {
		t.Fatal("diagnostic content leak")
	}
	body := r.Body()
	body[0] = 0
	if bytes.Equal(body, r.Body()) {
		t.Fatal("Body accessor aliases protected content")
	}
}
func FuzzRequestDecoderBounded(f *testing.F) {
	b, _ := EncodeRequest(sampleRequest())
	f.Add(b)
	f.Add([]byte("TBJ1"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxRequestBytes+32 {
			return
		}
		r, e := readRequest(bytes.NewReader(b))
		if e != nil {
			return
		}
		encoded, e := EncodeRequest(r)
		if e != nil || len(encoded) > MaxRequestBytes {
			t.Fatal("unbounded accepted request")
		}
	})
}
func TestWriteAllRejectsBadWriter(t *testing.T) {
	if writeAll(zeroWriter{}, []byte{1}) == nil {
		t.Fatal("zero write accepted")
	}
	if writeAll(errorWriter{}, []byte{1}) == nil {
		t.Fatal("error ignored")
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestResponseFormattingNeverRevealsContentForAnyVerb(t *testing.T) {
	r := Response{Status: StatusSnapshot, PolicyDigest: "sha256:" + strings.Repeat("a", 64), Revision: "sha256:" + strings.Repeat("b", 64), body: &responseBody{raw: []byte("PRIVATE-FIXTURE-CONTENT")}}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%b", "%f", "%e", "%o", "%t", "%c", "%U", "%p", "%T", "%20.5s"} {
		for _, v := range []any{r, &r} {
			out := fmt.Sprintf(format, v)
			if strings.Contains(out, "PRIVATE") || strings.Contains(out, "50524956") || strings.Contains(out, "80 82 73 86") {
				t.Fatalf("format %s leaked payload", format)
			}
			if format != "%T" && format != "%p" && out != r.String() {
				t.Fatalf("format %s bypassed fixed formatter", format)
			}
		}
	}
}

func TestEntireResponseIncludingHeaderStaysWithinCeiling(t *testing.T) {
	r := Response{Status: StatusSnapshot, PolicyDigest: "sha256:" + strings.Repeat("a", 64), Revision: "sha256:" + strings.Repeat("b", 64), body: &responseBody{raw: make([]byte, maxResponsePayload)}}
	h, e := responseHeader(r)
	if e != nil || len(h)+len(r.payload()) != MaxResponseBytes {
		t.Fatal("whole-frame boundary")
	}
	r.body.raw = append(r.body.raw, 0)
	if _, e := responseHeader(r); e == nil {
		t.Fatal("header overhead escaped response cap")
	}
}

func TestResponseRejectsUint32LengthBeforeIntConversion(t *testing.T) {
	for _, length := range []uint32{1 << 31, ^uint32(0)} {
		header := make([]byte, responseHeaderBytes)
		copy(header, wireMagic[:])
		header[4] = StatusSnapshot
		binary.BigEndian.PutUint32(header[69:], length)
		if _, e := ReadResponse(bytes.NewReader(header)); e == nil {
			t.Fatal("unbounded uint32 length accepted")
		}
	}
}
