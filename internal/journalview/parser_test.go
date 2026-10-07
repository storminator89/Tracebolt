package journalview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func fixtureQuery() (Query, time.Time) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	return Query{Unit: "demo.service", Start: now.Add(-time.Hour), End: now, MaxPriority: 7}, now
}
func fixtureLine(q Query, msg string) string {
	b, _ := json.Marshal(map[string]any{"__REALTIME_TIMESTAMP": fmt.Sprint(q.Start.UnixMicro()), "_SYSTEMD_UNIT": q.Unit, "PRIORITY": "6", "MESSAGE": msg, "_UID": "1234", "ACCOUNT": "fixture-account", "_MACHINE_ID": "fixture-machine", "__CURSOR": "fixture-cursor", "_BOOT_ID": "fixture-boot"})
	return string(b) + "\n"
}
func mustParse(t *testing.T, q Query, now time.Time, in io.Reader) Snapshot {
	t.Helper()
	s, e := Parse(context.Background(), q, now, in)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Encode(s); e != nil {
		t.Fatalf("snapshot does not encode: %#v %v", s, e)
	}
	return s
}
func TestQueryValidation(t *testing.T) {
	q, now := fixtureQuery()
	for _, unit := range []string{"demo.service", "demo-agent.service", "worker@one.service", "db.v2.service"} {
		a := q
		a.Unit = unit
		if ValidateQuery(a, now) != nil {
			t.Fatal(unit)
		}
	}
	for _, unit := range []string{"", ".service", "-a.service", "../a.service", "a*.service", "a?.service", "a[1].service", "a.service x=1", "a\\x2f.service", "x@.service", "x@@y.service", "x.socket", "x.service\n", "x.service\x00", "_SYSTEMD_UNIT=a.service", strings.Repeat("a", 248) + ".service"} {
		a := q
		a.Unit = unit
		if ValidateQuery(a, now) == nil {
			t.Fatalf("accepted %q", unit)
		}
	}
	cases := []Query{q, q, q, q, q, q, q, q}
	cases[0].MaxPriority = -1
	cases[1].MaxPriority = 8
	cases[2].End = now.Add(time.Microsecond)
	cases[3].Start = now.Add(-25 * time.Hour)
	cases[4].Start = now.Add(-time.Hour - time.Microsecond)
	cases[5].Start = q.End
	cases[6].Start = q.Start.Add(time.Nanosecond)
	cases[7].Start = q.Start.In(time.FixedZone("other", 3600))
	for i, a := range cases {
		if ValidateQuery(a, now) == nil {
			t.Fatal("accepted bad query", i)
		}
	}
	if ValidateQuery(q, now.In(time.FixedZone("UTC alias", 0))) == nil {
		t.Fatal("accepted noncanonical UTC")
	}
}
func TestAllowlistFilterOrderingAndEmpty(t *testing.T) {
	q, now := fixtureQuery()
	later := q
	later.Start = later.Start.Add(time.Minute)
	other := q
	other.Unit = "other.service"
	old := q
	old.Start = old.Start.Add(-time.Microsecond)
	input := fixtureLine(later, "later") + fixtureLine(other, "excluded") + fixtureLine(old, "excluded old") + fixtureLine(q, "earlier") + fixtureLine(q, "earlier")
	s := mustParse(t, q, now, strings.NewReader(input))
	if s.Coverage != Complete || s.ObservedCount != 3 || !s.CountExact || len(s.Rows) != 3 || s.Rows[0].Message != "later" || s.Rows[1].Message != "earlier" || s.Rows[2].Message != "earlier" || s.Query != q || !s.ObservedAt.Equal(now) {
		t.Fatalf("%+v", s)
	}
	b, _ := Encode(s)
	for _, secret := range []string{"fixture-account", "fixture-machine", "fixture-cursor", "fixture-boot", "_UID", "_MACHINE_ID", "__CURSOR", "_BOOT_ID"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("metadata leak", secret)
		}
	}
	a, _ := Encode(s)
	if !bytes.Equal(a, b) {
		t.Fatal("nondeterministic encode")
	}
	s = mustParse(t, q, now, strings.NewReader(""))
	if s.Coverage != Complete || !s.CountExact || s.ObservedCount != 0 || len(s.Rows) != 0 {
		t.Fatalf("empty: %+v", s)
	}
	q.MaxPriority = 3
	s = mustParse(t, q, now, strings.NewReader(fixtureLine(q, "too low severity")))
	if len(s.Rows) != 0 || s.Coverage != Complete {
		t.Fatal(s)
	}
}
func TestMalformedAndAmbiguousRows(t *testing.T) {
	q, now := fixtureQuery()
	line := strings.TrimSpace(fixtureLine(q, "valid"))
	bad := []string{"\n", "[]", "{", line + line, strings.Replace(line, `"PRIORITY":"6"`, `"PRIORITY":6`, 1), strings.Replace(line, `"MESSAGE":"valid"`, `"MESSAGE":null`, 1), strings.Replace(line, `"MESSAGE":"valid"`, `"MESSAGE":["one","two"]`, 1), strings.Replace(line, `"PRIORITY":"6"`, `"PRIORITY":"8"`, 1), strings.Replace(line, `"MESSAGE":"valid"`, `"MESSAGE":"one","MESSAGE":"two"`, 1), strings.Replace(line, `"_SYSTEMD_UNIT":"demo.service",`, "", 1), strings.Replace(line, "valid", string([]byte{255}), 1)}
	for _, in := range bad {
		s := mustParse(t, q, now, strings.NewReader(in))
		if s.Coverage != Failed || s.Reason != ReasonInvalidSource || s.CountExact || len(s.Rows) != 0 {
			t.Fatalf("bad input %q => %+v", in, s)
		}
	}
	s := mustParse(t, q, now, strings.NewReader(fixtureLine(q, "first")+"{"))
	if s.Coverage != Partial || s.Reason != ReasonInvalidSource || len(s.Rows) != 1 || s.CountExact {
		t.Fatal(s)
	}
}
func TestRedactionBestEffort(t *testing.T) {
	q, now := fixtureQuery()
	for _, in := range []string{`password=synthetic-password tail`, `"password": "synthetic-password"`, `api_key='synthetic-secret with spaces'`, `Authorization: Bearer synthetic-token`, `Authorization: Basic c3ludGhldGlj`, `https://fixture-user:synthetic-password@example.invalid/a`, `-----BEGIN PRIVATE KEY-----\nsynthetic-key\n-----END PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----synthetic-key`} {
		s := mustParse(t, q, now, strings.NewReader(fixtureLine(q, in)))
		if !s.RedactionApplied || !strings.Contains(s.Rows[0].Message, "[REDACTED") || strings.Contains(s.Rows[0].Message, "synthetic-") || s.RedactionWarning != RedactionWarning {
			t.Fatalf("mask %q => %+v", in, s)
		}
	}
	s := mustParse(t, q, now, strings.NewReader(fixtureLine(q, "normal fixture message")))
	if s.RedactionApplied || s.RedactionWarning == "" {
		t.Fatal(s)
	}
}
func TestAllBounds(t *testing.T) {
	q, now := fixtureQuery()
	s := mustParse(t, q, now, strings.NewReader(strings.Repeat(fixtureLine(q, "ok"), MaxRows)))
	if s.Coverage != Complete || len(s.Rows) != MaxRows {
		t.Fatal("exact row bound")
	}
	s = mustParse(t, q, now, strings.NewReader(strings.Repeat(fixtureLine(q, "ok"), MaxRows+1)))
	if s.Coverage != Partial || s.Reason != ReasonItemLimit || len(s.Rows) != MaxRows || s.ObservedCount != MaxRows+1 || s.CountExact {
		t.Fatal("row bound")
	}
	other := q
	other.Unit = "other.service"
	s = mustParse(t, q, now, strings.NewReader(strings.Repeat(fixtureLine(other, "ok"), MaxScannedRows+1)))
	if s.Coverage != Partial || s.Reason != ReasonItemLimit || s.ObservedCount != 0 {
		t.Fatal("scan bound")
	}
	s = mustParse(t, q, now, strings.NewReader(fixtureLine(q, strings.Repeat("a", MaxMessageBytes+1))))
	if s.Coverage != Partial || s.Reason != ReasonByteLimit {
		t.Fatal("message bound")
	}
	s = mustParse(t, q, now, strings.NewReader(strings.Repeat("x", MaxLineBytes+1)))
	if s.Reason != ReasonByteLimit || s.Coverage != Partial {
		t.Fatal("line bound")
	}
	s = mustParse(t, q, now, strings.NewReader(strings.Repeat(fixtureLine(q, strings.Repeat("<", MaxMessageBytes)), MaxRows)))
	if s.Coverage != Partial || s.Reason != ReasonByteLimit || len(s.Rows) == 0 || len(s.Rows) >= MaxRows {
		t.Fatal("escaped body bound")
	}
	b, _ := Encode(s)
	if len(b) > MaxSnapshotBytes {
		t.Fatal("oversized body")
	}
	// Huge dropped metadata consumes the raw byte budget, not retained storage.
	line := strings.TrimSpace(fixtureLine(other, "ok"))
	line = line[:len(line)-1] + `,"DROPPED":"` + strings.Repeat("x", 32<<10) + `"}` + "\n"
	r := &countReader{r: strings.NewReader(strings.Repeat(line, MaxRawBytes/len(line)+2))}
	s = mustParse(t, q, now, r)
	if s.Reason != ReasonByteLimit || r.n > MaxRawBytes+1 {
		t.Fatalf("raw cap %d %+v", r.n, s)
	}
}

type countReader struct {
	r io.Reader
	n int
}

func (r *countReader) Read(p []byte) (int, error) { n, e := r.r.Read(p); r.n += n; return n, e }

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic raw failure; never export")
}
func TestCancellationAndSourceFailures(t *testing.T) {
	q, now := fixtureQuery()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s, e := Parse(ctx, q, now, strings.NewReader(""))
	if e != nil || s.Coverage != Failed || s.Reason != ReasonTimeout {
		t.Fatal(s, e)
	}
	s = mustParse(t, q, now, brokenReader{})
	if s.Reason != ReasonReadFailed || s.Coverage != Failed || s.CountExact {
		t.Fatal(s)
	}
	if _, e := Parse(context.Background(), Query{}, now, strings.NewReader("")); e != ErrInvalidInput {
		t.Fatal(e)
	}
	if _, e := Parse(nil, q, now, strings.NewReader("")); e != ErrInvalidInput {
		t.Fatal(e)
	}
}
func TestEncodeRejectsInvalidSnapshotBeforeFinalAllocation(t *testing.T) {
	q, now := fixtureQuery()
	s := empty(q, now)
	s.Rows = make([]Row, MaxRows+1)
	if _, e := Encode(s); e == nil {
		t.Fatal("rows")
	}
	s = empty(q, now)
	s.RedactionWarning = "safe"
	if _, e := Encode(s); e == nil {
		t.Fatal("warning")
	}
	s = empty(q, now)
	s.Coverage = Failed
	if _, e := Encode(s); e == nil {
		t.Fatal("coverage")
	}
	s = empty(q, now)
	s.Rows = []Row{{q.Start, q.Unit, 6, strings.Repeat("a", MaxMessageBytes+1)}}
	s.ObservedCount = 1
	if _, e := Encode(s); e == nil {
		t.Fatal("message")
	}
}

func TestDiagnosticFormattingCannotDumpMessages(t *testing.T) {
	q, now := fixtureQuery()
	s := mustParse(t, q, now, strings.NewReader(fixtureLine(q, "sensitive fixture content")))
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		for _, value := range []any{s, &s, s.Rows[0], &s.Rows[0], s.Rows} {
			out := fmt.Sprintf(format, value)
			if strings.Contains(out, "sensitive fixture content") {
				t.Fatalf("raw content leaked with %s", format)
			}
		}
	}
	b, e := Encode(s)
	if e != nil || !strings.Contains(string(b), "sensitive fixture content") {
		t.Fatal("deliberate serializer changed", e)
	}
}

func FuzzParseAlwaysProducesBoundedEncodableSnapshot(f *testing.F) {
	q, now := fixtureQuery()
	f.Add([]byte(""))
	f.Add([]byte(fixtureLine(q, "fixture password=synthetic")))
	f.Add([]byte(fixtureLine(q, "first") + "{"))
	f.Add([]byte(`{"MESSAGE":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*MaxLineBytes {
			t.Skip()
		}
		s, e := Parse(context.Background(), q, now, bytes.NewReader(data))
		if e != nil {
			t.Fatal(e)
		}
		encoded, e := Encode(s)
		if e != nil {
			t.Fatalf("non-encodable parser result: coverage=%s reason=%s observed=%d rows=%d error=%v", s.Coverage, s.Reason, s.ObservedCount, len(s.Rows), e)
		}
		if len(encoded) > MaxSnapshotBytes || len(s.Rows) > MaxRows {
			t.Fatal("output bound")
		}
	})
}

func managerFixture(q Query, msg, pid, uid, unit string) string {
	b, _ := json.Marshal(map[string]any{"__REALTIME_TIMESTAMP": fmt.Sprint(q.Start.UnixMicro()), "_SYSTEMD_UNIT": "init.scope", "_PID": pid, "_UID": uid, "UNIT": unit, "PRIORITY": "3", "MESSAGE": msg})
	return string(b) + "\n"
}
func TestTrustedPID1ManagerBranchAndSharedFilters(t *testing.T) {
	q, now := fixtureQuery()
	input := fixtureLine(q, "service emitted") + managerFixture(q, "Failed to start fixture service.", "1", "0", q.Unit)
	s := mustParse(t, q, now, strings.NewReader(input))
	if s.Coverage != Complete || len(s.Rows) != 2 || s.Rows[1].Unit != q.Unit || s.Rows[1].Message != "Failed to start fixture service." {
		t.Fatal("manager row omitted")
	}
	b, _ := Encode(s)
	for _, field := range []string{`"_PID"`, `"_UID"`, `"UNIT"`, `"_SYSTEMD_UNIT"`, "init.scope"} {
		if bytes.Contains(b, []byte(field)) {
			t.Fatal("identity metadata exported", field)
		}
	}
	// A process cannot authorize application-supplied UNIT by itself. Valid but
	// nonmatching branch identities are excluded, just like other query filters.
	for _, in := range []string{
		managerFixture(q, "untrusted application UNIT", "2", "0", q.Unit),
		managerFixture(q, "nonroot PID1", "1", "1234", q.Unit),
		managerFixture(q, "wrong target", "1", "0", "other.service"),
		strings.Replace(managerFixture(q, "missing UID", "1", "0", q.Unit), `"_UID":"0",`, "", 1),
	} {
		got := mustParse(t, q, now, strings.NewReader(in))
		if len(got.Rows) != 0 || got.Coverage != Complete || got.ObservedCount != 0 {
			t.Fatal("invalid manager attribution retained")
		}
	}
	old := q
	old.Start = old.Start.Add(-1_000)
	got := mustParse(t, q, now, strings.NewReader(managerFixture(old, "too old", "1", "0", q.Unit)))
	if len(got.Rows) != 0 {
		t.Fatal("manager time filter")
	}
	q.MaxPriority = 2
	got = mustParse(t, q, now, strings.NewReader(managerFixture(q, "priority three", "1", "0", q.Unit)))
	if len(got.Rows) != 0 {
		t.Fatal("manager severity filter")
	}
}
func TestRelevantIdentityFieldsAreScalarSingletons(t *testing.T) {
	q, now := fixtureQuery()
	line := managerFixture(q, "manager fixture", "1", "0", q.Unit)
	for _, field := range []struct{ name, value string }{{"_SYSTEMD_UNIT", "init.scope"}, {"_PID", "1"}, {"_UID", "0"}, {"UNIT", q.Unit}} {
		token := fmt.Sprintf(`"%s":"%s"`, field.name, field.value)
		for _, replacement := range []string{fmt.Sprintf(`"%s":["%s"]`, field.name, field.value), fmt.Sprintf(`"%s":null`, field.name), token + "," + token} {
			got := mustParse(t, q, now, strings.NewReader(strings.Replace(line, token, replacement, 1)))
			if got.Coverage != Failed || got.Reason != ReasonInvalidSource {
				t.Fatalf("accepted ambiguous %s", field.name)
			}
		}
	}
	for _, identity := range []string{"01", "-1", "+1", "", "4294967296", "1x"} {
		got := mustParse(t, q, now, strings.NewReader(managerFixture(q, "bad PID", identity, "0", q.Unit)))
		if got.Coverage != Failed || got.Reason != ReasonInvalidSource {
			t.Fatal("bad PID", identity)
		}
		got = mustParse(t, q, now, strings.NewReader(managerFixture(q, "bad UID", "1", identity, q.Unit)))
		if got.Coverage != Failed || got.Reason != ReasonInvalidSource {
			t.Fatal("bad UID", identity)
		}
	}
	// No coredump/object/slice attribution fallback.
	objectOnly := strings.Replace(line, `"UNIT":"demo.service"`, `"OBJECT_SYSTEMD_UNIT":"demo.service","COREDUMP_UNIT":"demo.service","SLICE":"demo.service"`, 1)
	got := mustParse(t, q, now, strings.NewReader(objectOnly))
	if len(got.Rows) != 0 {
		t.Fatal("expanded unwanted branch")
	}
}
