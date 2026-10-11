package windowssecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func requestFixture() Request {
	b := strings.Repeat("a", 64)
	return Request{Consent: Consent{ConsentVersion, Scope, b, strings.Repeat("9", 32), true}, SenderBinding: b, GenerationID: "sample_" + strings.Repeat("c", 32), CollectedAt: time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)}
}
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
	encoded, e := Encode(s)
	if e != nil || !bytes.Equal(raw, encoded) {
		t.Fatal("noncanonical", e)
	}
	return s
}
func TestCanonicalFixtureAndContradictions(t *testing.T) {
	s := fixture(t)
	raw, _ := Encode(s)
	for _, f := range []func(*Snapshot){func(s *Snapshot) { s.Defender.Mode = "unprotected" }, func(s *Snapshot) { s.Defender.Quality = "denied" }, func(s *Snapshot) { s.Defender.SignatureVersion = nil }, func(s *Snapshot) { s.Defender.SignatureVersion = func() *string { v := "private/path"; return &v }() }, func(s *Snapshot) { s.Defender.SignatureAgeDays = func() *uint32 { v := uint32(65535); return &v }() }, func(s *Snapshot) { s.Firewall.Profiles[0].Profile = "public" }, func(s *Snapshot) { s.Firewall.Profiles[1].Enabled = "protected" }, func(s *Snapshot) { s.Firewall.Profiles = s.Firewall.Profiles[:2] }, func(s *Snapshot) { s.Firewall.Reason = "private native error" }, func(s *Snapshot) { s.Scope = "windows-patch-context-v1" }} {
		var copy Snapshot
		json.Unmarshal(raw, &copy)
		f(&copy)
		if Validate(copy) == nil {
			t.Fatal("contradiction")
		}
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"mode":`), []byte(`"path":"private","mode":`), 1), bytes.Replace(raw, []byte(`"mode":`), []byte(`"mode":"normal","mode":`), 1)} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("noncanonical accepted")
		}
	}
}
func TestSeparateGrantBeforeAnyNativeRead(t *testing.T) {
	for _, kind := range []string{"off", "scope", "binding", "capture"} {
		r := requestFixture()
		switch kind {
		case "off":
			r.Consent.Enabled = false
		case "scope":
			r.Consent.Scope = "windows-inventory"
		case "binding":
			r.SenderBinding = strings.Repeat("c", 64)
		case "capture":
			r.CollectedAt = time.Time{}
		}
		_, e := CollectWithSources(context.Background(), r, func(context.Context) (Defender, error) { t.Fatal("native Defender"); return Defender{}, nil }, func(context.Context) (Firewall, error) { t.Fatal("native firewall"); return Firewall{}, nil })
		if e == nil {
			t.Fatal(kind)
		}
	}
}
func TestIndependentSourcesNeverInferGlobalProtection(t *testing.T) {
	good := fixture(t)
	for _, failure := range []error{ErrDenied, ErrUnsupported, ErrUnavailable, ErrBudget} {
		s, e := CollectWithSources(context.Background(), requestFixture(), func(context.Context) (Defender, error) { return Defender{}, failure }, func(context.Context) (Firewall, error) { return good.Firewall, nil })
		if e != nil || s.Defender.Mode != "unknown" || s.Defender.Reason != SafeReason(failure) || s.Firewall.Quality != "observed" {
			t.Fatal("source coupling", e)
		}
		s, e = CollectWithSources(context.Background(), requestFixture(), func(context.Context) (Defender, error) { return good.Defender, nil }, func(context.Context) (Firewall, error) { return Firewall{}, failure })
		if e != nil || s.Defender.Mode != "passive" || s.Defender.AntivirusEnabled != "off" || s.Firewall.Reason != SafeReason(failure) {
			t.Fatal("source coupling", e)
		}
	}
}
func TestPartialFieldsAndOpaqueErrors(t *testing.T) {
	d := fixture(t).Defender
	d.Mode = "unknown"
	d = finishDefender(d, ErrPartial.Error())
	if !validDefender(d) || d.Quality != "partial" {
		t.Fatal("unknown mode inferred")
	}
	f := EmptyFirewall(ErrUnavailable.Error())
	f.Profiles[2].Enabled = "off"
	f = finishFirewall(f, ErrDenied.Error())
	if !validFirewall(f) || f.Quality != "partial" {
		t.Fatal("positive partial lost")
	}
	if SafeReason(ErrInvalid) != ErrUnavailable.Error() {
		t.Fatal("raw error")
	}
}
