package windowssessions

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf16"
)

func fixture(t *testing.T) Snapshot {
	t.Helper()
	raw, e := os.ReadFile("testdata/snapshot.json")
	if e != nil {
		t.Fatal(e)
	}
	s, e := Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Encode(s)
	if e != nil || !bytes.Equal(got, raw) {
		t.Fatal("canonical Go/UI fixture changed", e)
	}
	return s
}
func request(t *testing.T) Request {
	s := fixture(t)
	b := strings.Repeat("a", 64)
	return Request{Consent{ConsentVersion, Scope, b, s.GrantID, true}, b, s.GenerationID, s.CollectedAt}
}
func TestCanonicalFixtureAndClosedModel(t *testing.T) {
	s := fixture(t)
	raw, _ := Encode(s)
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"sessions":`), []byte(`"clientIP":"private","sessions":`), 1), bytes.Replace(raw, []byte(`"scope":`), []byte(`"scope":"windows-session-context-v1","scope":`), 1)} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("noncanonical or unknown fields accepted")
		}
	}
	for _, change := range []func(*Snapshot){func(s *Snapshot) { s.Sessions.ObservedCount = nil }, func(s *Snapshot) { s.Sessions.RetainedCount++ }, func(s *Snapshot) { s.Sessions.Rows[1].SessionID = 1 }, func(s *Snapshot) { s.Sessions.Rows[2].UserName = s.Sessions.Rows[0].UserName }, func(s *Snapshot) { s.Sessions.Quality = "observed"; s.Sessions.Reason = "" }, func(s *Snapshot) { s.Join.Status = "azure-ad" }, func(s *Snapshot) { s.Join.Name = nil }, func(s *Snapshot) { s.Sessions.Rows[0].State = "logged-on" }} {
		v := fixture(t)
		change(&v)
		if Validate(v) == nil {
			t.Fatal("inconsistent semantics accepted")
		}
	}
}
func TestBoundedUTF16AndNativeSessionSelection(t *testing.T) {
	encode := func(s string) []byte {
		v := append(utf16.Encode([]rune(s)), 0)
		b := make([]byte, len(v)*2)
		for i, u := range v {
			binary.LittleEndian.PutUint16(b[i*2:], u)
		}
		return b
	}
	for _, s := range []string{"demo", "界", "😀", strings.Repeat("x", MaxLabelUnits)} {
		got, e := decodeLabel(encode(s), MaxLabelUnits)
		if e != nil || got == nil || *got != s {
			t.Fatal("valid label lost", e)
		}
	}
	if v, e := decodeLabel([]byte{0, 0}, MaxLabelUnits); v != nil || e != nil {
		t.Fatal("empty differs from unavailable")
	}
	for _, raw := range [][]byte{nil, {0}, {'a', 0}, {0, 0, 1, 0}, {0, 0xd8, 0, 0}, encode("a\nb"), encode(strings.Repeat("x", MaxLabelUnits+1))} {
		if _, e := decodeLabel(raw, MaxLabelUnits); e == nil {
			t.Fatal("invalid label accepted")
		}
	}
	rows := make([]nativeSession, MaxRows+1)
	for i := range rows {
		rows[i] = nativeSession{uint32(len(rows) - i), 0}
	}
	got, e := selectSessions(rows)
	if e != nil || len(got) != MaxRows || got[0].ID != 1 {
		t.Fatal("bounded stable retention", e)
	}
	if _, e := selectSessions(make([]nativeSession, MaxNativeSessions+1)); e != ErrBounds {
		t.Fatal("native count bound")
	}
	if _, e := selectSessions([]nativeSession{{1, 0}, {1, 4}}); e != ErrMetadata {
		t.Fatal("duplicate id")
	}
	if sessionProtocol([]byte{2, 0}) != "rdp" || sessionProtocol([]byte{0, 0}) != "console" || sessionProtocol([]byte{1, 0}) != "unknown" || sessionProtocol([]byte{2}) != "unknown" || sessionState(99) != "unknown" {
		t.Fatal("native enums")
	}
}
func TestIndependentSourcesConsentAndCancellation(t *testing.T) {
	r := request(t)
	s, e := CollectWithSources(context.Background(), r, func(context.Context) (Sessions, error) { return Sessions{}, ErrDenied }, func(context.Context) (Join, error) { return fixture(t).Join, nil })
	if e != nil || s.Sessions.Quality != "denied" || s.Sessions.ObservedCount != nil || s.Join.Status != "workgroup" {
		t.Fatal("source denial erased sibling", e)
	}
	called := false
	r.Consent.Enabled = false
	_, e = CollectWithSources(context.Background(), r, func(context.Context) (Sessions, error) { called = true; return Sessions{}, nil }, nil)
	if e != ErrDisabled || called {
		t.Fatal("missing consent read source")
	}
	r = request(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = CollectWithSources(ctx, r, nil, nil); e != context.Canceled {
		t.Fatal("cancellation lost")
	}
}
func TestFittingPreservesCountsOriginalAgeAndGrant(t *testing.T) {
	s := fixture(t)
	raw, _ := json.Marshal(s)
	v, e := FitBudget(s, len(raw)-1)
	if e != nil || len(v.Sessions.Rows) != 2 || *v.Sessions.ObservedCount != 3 || v.Sessions.RetainedCount != 2 || *v.Sessions.TruncatedCount != 1 || v.GrantID != s.GrantID || !v.CollectedAt.Equal(s.CollectedAt) || v.Join.Name == nil || len(s.Sessions.Rows) != 3 {
		t.Fatal("fitting changed authority/counts", e)
	}
}

func TestNativeLabelEscapingFitsWithoutLosingObservedCount(t *testing.T) {
	r := request(t)
	s, e := CollectWithSources(context.Background(), r, func(context.Context) (Sessions, error) {
		n := uint32(MaxRows)
		zero := uint32(0)
		v := Sessions{Quality: "observed", ObservedCount: &n, RetainedCount: n, TruncatedCount: &zero, Rows: []Session{}}
		for i := uint32(0); i < n; i++ {
			name := strings.Repeat("<", MaxLabelUnits)
			v.Rows = append(v.Rows, Session{SessionID: i, UserName: &name, UserQuality: "observed", DomainName: &name, DomainQuality: "observed", State: "active", Protocol: "rdp"})
		}
		return v, nil
	}, func(context.Context) (Join, error) { return fixture(t).Join, nil })
	if e != nil || Validate(s) != nil || s.Sessions.RetainedCount >= MaxRows || *s.Sessions.ObservedCount != MaxRows || *s.Sessions.TruncatedCount+s.Sessions.RetainedCount != MaxRows {
		t.Fatal("native escaped labels lost bound/counts", e)
	}
}
