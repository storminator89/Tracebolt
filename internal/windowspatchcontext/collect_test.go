package windowspatchcontext

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func fixtureRequest() Request {
	b := strings.Repeat("a", 64)
	return Request{Consent: Consent{ConsentVersion, Scope, b, strings.Repeat("b", 32), true}, SenderBinding: b, GenerationID: "sample_" + strings.Repeat("c", 32), CollectedAt: time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)}
}

type sourceFixture struct {
	calls   []string
	total   int32
	after   int32
	count   int32
	online  bool
	upgrade bool
	denied  bool
	bad     bool
	totals  int
	closed  bool
}

func (s *sourceFixture) SetOnline(context.Context, bool) error {
	s.calls = append(s.calls, "offline")
	return nil
}
func (s *sourceFixture) Online(context.Context) (bool, error) { return s.online, nil }
func (s *sourceFixture) SetAutomaticUpgrade(context.Context, bool) error {
	s.calls = append(s.calls, "no-upgrade")
	return nil
}
func (s *sourceFixture) AutomaticUpgrade(context.Context) (bool, error) { return s.upgrade, nil }
func (s *sourceFixture) RebootRequired(context.Context) (bool, error) {
	s.calls = append(s.calls, "reboot")
	if s.denied {
		return false, ErrDenied
	}
	return true, nil
}
func (s *sourceFixture) Total(context.Context) (int32, error) {
	s.totals++
	if s.totals > 1 && s.after >= 0 {
		return s.after, nil
	}
	return s.total, nil
}
func (s *sourceFixture) Query(_ context.Context, n int32) (HistoryRows, error) {
	s.calls = append(s.calls, "history")
	if n > MaxRows || n < 1 {
		return nil, ErrBounds
	}
	return s, nil
}
func (s *sourceFixture) Count(context.Context) (int32, error) { return s.count, nil }
func (s *sourceFixture) Item(_ context.Context, i int32) (Entry, error) {
	if s.bad && i == 1 {
		return Entry{}, errors.New("private native error")
	}
	return Entry{Index: uint32(i), UpdateID: "12345678-1234-1234-1234-123456789abc", Title: "Synthetic retained update <tag>", Revision: 2, OccurredAt: fixtureRequest().CollectedAt.Add(-time.Duration(i+1) * time.Hour), Operation: "installation", Result: "succeeded", HResult: "00000000"}, nil
}
func (s *sourceFixture) Close() { s.closed = true }
func machineFixture(context.Context) (OS, Reboot) {
	v := Value{Quality: "absent"}
	return OS{v, v, v, v}, Reboot{"unavailable", "clear", "pending"}
}
func collectFixture(t *testing.T, s *sourceFixture) Snapshot {
	t.Helper()
	v, e := CollectWithSources(context.Background(), fixtureRequest(), func(context.Context) (Source, error) { return s, nil }, machineFixture)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestPatchContextNoSourceWithoutExactEnabledGrant(t *testing.T) {
	for _, kind := range []string{"off", "scope", "binding", "capture"} {
		r := fixtureRequest()
		switch kind {
		case "off":
			r.Consent.Enabled = false
		case "scope":
			r.Consent.Scope = "windows-cached-update-inspection-v1"
		case "binding":
			r.SenderBinding = strings.Repeat("d", 64)
		case "capture":
			r.CollectedAt = time.Time{}
		}
		_, e := CollectWithSources(context.Background(), r, func(context.Context) (Source, error) { t.Fatal("opened native"); return nil, nil }, func(context.Context) (OS, Reboot) { t.Fatal("read machine"); return OS{}, Reboot{} })
		if e == nil {
			t.Fatal(kind)
		}
	}
}
func TestPatchContextBoundedHistoryAndIndependentIndicators(t *testing.T) {
	s := &sourceFixture{total: 10000, after: -1, count: 64}
	v := collectFixture(t, s)
	if len(v.History.Rows) != 64 || v.History.TotalCount != 10000 || !v.History.Truncated || !v.History.CountExact || v.Reboot.WindowsUpdate != "pending" || !s.closed {
		t.Fatal("lost bounded truth", v)
	}
	if strings.Join(s.calls, ",") != "offline,no-upgrade,reboot,history" {
		t.Fatal(s.calls)
	}
	raw, _ := Encode(v)
	fit, e := FitBudget(v, len(raw)-100)
	if e != nil || len(fit.History.Rows) >= 64 || fit.History.TotalCount != 10000 || !fit.CollectedAt.Equal(v.CollectedAt) {
		t.Fatal("fit changed authority", e)
	}
}
func TestPatchContextOfflineControlsAndUnknownReboot(t *testing.T) {
	for _, online := range []bool{true, false} {
		s := &sourceFixture{total: 1, count: 1, after: -1, online: online, upgrade: !online}
		v := collectFixture(t, s)
		if v.History.Reason != ErrOffline.Error() || v.Reboot.WindowsUpdate != "unavailable" || len(s.calls) > 2 {
			t.Fatal("unsafe fallback")
		}
	}
	s := &sourceFixture{total: 0, after: -1, denied: true}
	v := collectFixture(t, s)
	if v.Reboot.WindowsUpdate != "denied" || v.History.Quality != "observed" || len(v.History.Rows) != 0 {
		t.Fatal("denied inferred clear")
	}
}
func TestPatchContextHistoryLossAndBadRowsStayPartial(t *testing.T) {
	s := &sourceFixture{total: 100, after: 5, count: 4, bad: true}
	v := collectFixture(t, s)
	if v.History.Quality != "partial" || v.History.CountExact || v.History.TotalCount != 4 || len(v.History.Rows) != 3 || !v.History.Truncated {
		t.Fatal("racy count promoted", v.History)
	}
}
func TestPatchContextCanonicalPrivacyAndContradictions(t *testing.T) {
	v := collectFixture(t, &sourceFixture{total: 2, count: 2, after: -1})
	raw, e := Encode(v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(raw); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"scope":`), []byte(`"secret":"private","scope":`), 1)} {
		if _, e = Decode(bad); e == nil {
			t.Fatal("noncanonical accepted")
		}
	}
	for _, mutate := range []func(*Snapshot){func(v *Snapshot) { v.History.Rows[1].Index = 0 }, func(v *Snapshot) { v.History.Rows[1].OccurredAt = v.CollectedAt }, func(v *Snapshot) { v.History.Rows[0].Title = "bad\nlabel" }, func(v *Snapshot) { v.Reboot.Servicing = "absent" }, func(v *Snapshot) { v.OS.Build = Value{Value: ptr("001"), Quality: "observed"} }, func(v *Snapshot) { v.History.Quality = "unavailable" }} {
		var copy Snapshot
		json.Unmarshal(raw, &copy)
		mutate(&copy)
		if Validate(copy) == nil {
			t.Fatal("contradiction admitted")
		}
	}
}
func ptr(s string) *string { return &s }
func TestPatchContextFileOperationMetadataOnly(t *testing.T) {
	for _, v := range []struct {
		typ, size                uint32
		success, missing, denied bool
		want                     string
	}{{7, 10, true, false, false, "pending"}, {7, 4, true, false, false, "unavailable"}, {7, 3, true, false, false, "unavailable"}, {1, 10, true, false, false, "unavailable"}, {0, 0, false, true, false, "clear"}, {0, 0, false, false, true, "denied"}, {0, 0, false, false, false, "unavailable"}} {
		if got := fileOperationsState(v.typ, v.size, v.success, v.missing, v.denied); got != v.want {
			t.Fatal(got, v)
		}
	}
}
func TestPatchContextCanonicalFixture(t *testing.T) {
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
		t.Fatal("fixture differs from canonical Go wire", e)
	}
}
