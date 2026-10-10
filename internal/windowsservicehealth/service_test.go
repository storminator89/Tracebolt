package windowsservicehealth

import (
	"encoding/json"
	"fmt"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsmanaged"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

const epoch = "11111111111111111111111111111111"

func input() Input {
	return Input{Input: windowscontact.Input{DeviceID: "agent_" + strings.Repeat("1", 32), InvitationID: "invite_" + strings.Repeat("2", 32), CertificateHash: strings.Repeat("3", 64), Authorized: true, AuthorityUntil: at.Add(2 * time.Hour), ReceivedAt: at, Sequence: 1}, Sample: Sample{CollectedAt: at, Services: windowsmanaged.Section[windowsmanaged.Service]{Quality: "healthy", Complete: true, CountExact: true, ObservedCount: 2, Rows: []windowsmanaged.Service{{Name: "FixtureService", DisplayName: "Fixture service", State: "stopped"}, {Name: "Other", State: "running"}}}}}
}
func configured(t *testing.T) (State, Input) {
	t.Helper()
	s := New()
	in := input()
	if e := s.Configure(in, true, []string{"FixtureService"}, 0, at); e != nil {
		t.Fatal(e)
	}
	return s, in
}
func advance(in *Input, seconds int, state string) {
	in.Sequence++
	in.ReceivedAt = in.ReceivedAt.Add(time.Duration(seconds) * time.Second)
	in.Sample.CollectedAt = in.ReceivedAt
	in.Sample.Services.Rows[0].State = state
}
func evaluate(t *testing.T, s *State, in Input) {
	t.Helper()
	if e := s.Evaluate(in, in.ReceivedAt, epoch); e != nil {
		t.Fatal(e)
	}
}
func openFixture(t *testing.T) (State, Input) {
	t.Helper()
	s, in := configured(t)
	evaluate(t, &s, in)
	for i := 0; i < 4; i++ {
		advance(&in, 30, "stopped")
		evaluate(t, &s, in)
	}
	if len(s.Incidents) != 1 || s.Checks[0].Status != "attention" {
		t.Fatal(s)
	}
	return s, in
}
func TestDefaultOffExactSelectionAndPolicyAuthority(t *testing.T) {
	s := New()
	in := input()
	if e := s.Evaluate(in, at, epoch); e != nil || s.Policy.Enabled || s.DeviceID != "" {
		t.Fatal(e, s)
	}
	for _, names := range [][]string{nil, {}, {"FixtureService", "FixtureService"}, {"fixtureservice"}, {"missing"}, {strings.Repeat("n", 257)}, {"a\x00b"}} {
		copy := s
		if e := copy.Configure(in, true, names, 0, at); e == nil {
			t.Fatal("accepted", names)
		}
	}
	if e := s.Configure(in, true, []string{"Other", "FixtureService"}, 0, at); e != nil || !reflect.DeepEqual(s.Policy.Services, []string{"FixtureService", "Other"}) {
		t.Fatal(e, s)
	}
	before, _ := Encode(s)
	if e := s.Configure(in, false, []string{"FixtureService"}, 0, at); e == nil {
		t.Fatal("stale policy")
	}
	after, _ := Encode(s)
	if string(before) != string(after) {
		t.Fatal("failed change mutated")
	}
	in.Sample.CollectedAt = at.Add(-MaxAge - time.Second)
	if e := s.Configure(in, false, []string{"FixtureService"}, 1, at); e != nil {
		t.Fatal("stale metadata trapped disable", e)
	}
	if e := s.Configure(in, true, []string{"FixtureService"}, 2, at); e == nil {
		t.Fatal("re-enabled stale selection")
	}
	in.Authorized = false
	if e := s.Configure(in, false, []string{}, 2, at); e == nil {
		t.Fatal("lost authority configured")
	}
}
func TestPositiveRowsPartialAndAmbiguousNames(t *testing.T) {
	for _, mode := range []string{"partial-trim", "partial-native", "complete-missing", "duplicate", "case-distinct", "denied", "unavailable", "bad-state", "bad-count", "future", "stale"} {
		t.Run(mode, func(t *testing.T) {
			s, in := configured(t)
			want := "pending"
			switch mode {
			case "partial-trim":
				in.Sample.Services.Quality = "partial"
				in.Sample.Services.Complete = false
				in.Sample.Services.Truncated = true
				in.Sample.Services.ObservedCount = 130
			case "partial-native":
				in.Sample.Services.Quality = "partial"
				in.Sample.Services.Complete = false
				in.Sample.Services.CountExact = false
			case "complete-missing":
				in.Sample.Services.Rows = in.Sample.Services.Rows[1:]
				in.Sample.Services.ObservedCount = 1
				want = "unknown"
			case "duplicate":
				in.Sample.Services.Rows = append(in.Sample.Services.Rows, in.Sample.Services.Rows[0])
				in.Sample.Services.ObservedCount = 3
				want = "unknown"
			case "case-distinct":
				in.Sample.Services.Rows = append(in.Sample.Services.Rows, windowsmanaged.Service{Name: "fixtureservice", State: "running"})
				in.Sample.Services.ObservedCount = 3
			case "denied", "unavailable":
				in.Sample.Services.Quality = mode
				want = "unknown"
			case "bad-state":
				in.Sample.Services.Rows[0].State = "inactive"
				want = "unknown"
			case "bad-count":
				in.Sample.Services.ObservedCount = 3
				want = "unknown"
			case "future":
				in.Sample.CollectedAt = at.Add(time.Second)
				want = "unknown"
			case "stale":
				in.Sample.CollectedAt = at.Add(-MaxAge - time.Second)
				want = "unknown"
			}
			evaluate(t, &s, in)
			if s.Checks[0].Status != want {
				t.Fatal(s.Checks)
			}
			if mode == "duplicate" {
				inv := in.Inventory(at)
				if inv == nil || len(inv.Services) != 1 || inv.Services[0].Name != "Other" {
					t.Fatal(inv)
				}
			}
		})
	}
}
func TestAllReportedStatesAndNoPercentageSemantics(t *testing.T) {
	for _, state := range []string{"running", "stopped", "paused", "start_pending", "stop_pending", "continue_pending", "pause_pending"} {
		t.Run(state, func(t *testing.T) {
			s, in := configured(t)
			in.Sample.Services.Rows[0].State = state
			evaluate(t, &s, in)
			want := "unknown"
			if state == "running" {
				want = "running"
			} else if bad(state) {
				want = "pending"
			}
			if s.Checks[0].Status != want {
				t.Fatal(s.Checks)
			}
			raw, _ := json.Marshal(s.View(in, at, epoch))
			if strings.Contains(string(raw), "percent") || strings.Contains(string(raw), "value") {
				t.Fatal("invented numeric metric")
			}
		})
	}
}
func TestAdvancingSourceConfirmationRecoveryAndUnknown(t *testing.T) {
	s, in := configured(t)
	for _, sec := range []int{0, 30, 60, 90, 120} {
		if e := s.Evaluate(in, at.Add(time.Duration(sec)*time.Second), epoch); e != nil {
			t.Fatal(e)
		}
	}
	if len(s.Incidents) != 0 {
		t.Fatal("same sample confirmed")
	}
	s, in = openFixture(t)
	opened := s.Incidents[0]
	advance(&in, 30, "start_pending")
	evaluate(t, &s, in)
	if s.Checks[0].Status != "unknown" || s.Incidents[0].ResolvedAt != nil {
		t.Fatal("pending recovered")
	}
	for i := 0; i < 3; i++ {
		advance(&in, 30, "running")
		evaluate(t, &s, in)
	}
	if s.Checks[0].Status != "running" || s.Incidents[0].ClosedReason != "running" || s.Incidents[0].RecoveryObservation == nil || s.Incidents[0].ID != opened.ID {
		t.Fatal(s)
	}
}
func TestEpochGapRegressionAndOriginalCaptureFloors(t *testing.T) {
	for _, mode := range []string{"restart", "gap", "capture-regress", "receipt-regress", "sequence-regress", "missing", "authority", "capture-same"} {
		t.Run(mode, func(t *testing.T) {
			s, in := configured(t)
			evaluate(t, &s, in)
			advance(&in, 60, "stopped")
			evaluate(t, &s, in)
			floor := s.CaptureFloor
			seq := s.SequenceFloor
			advance(&in, 60, "stopped")
			ep := epoch
			switch mode {
			case "restart":
				ep = strings.Repeat("2", 32)
			case "gap":
				in.ReceivedAt = in.ReceivedAt.Add(100 * time.Second)
				in.Sample.CollectedAt = in.ReceivedAt
			case "capture-regress":
				in.Sample.CollectedAt = at
			case "receipt-regress":
				in.ReceivedAt = at
			case "sequence-regress":
				in.Sequence = 1
			case "missing":
				in.Sample.Services.Rows = []windowsmanaged.Service{}
				in.Sample.Services.ObservedCount = 0
			case "authority":
				in.Authorized = false
			case "capture-same":
				in.Sample.CollectedAt = *floor
			}
			now := at.Add(120 * time.Second)
			if mode == "gap" {
				now = in.ReceivedAt
			}
			if e := s.Evaluate(in, now, ep); e != nil {
				t.Fatal(e)
			}
			if len(s.Incidents) != 0 {
				t.Fatal("discontinuous source confirmed", mode)
			}
			if s.SequenceFloor < seq || s.CaptureFloor.Before(*floor) {
				t.Fatal("floors erased")
			}
			if mode == "restart" && s.Checks[0].Since == nil {
				t.Fatal("no new wait")
			}
		})
	}
	s, in := openFixture(t)
	before, _ := Encode(s)
	if e := s.Evaluate(in, in.ReceivedAt.Add(-time.Second), epoch); e == nil {
		t.Fatal("rollback accepted")
	}
	after, _ := Encode(s)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("rollback mutated")
	}
}
func TestPolicyCloseIsNotRecoveryAndHistoryIsReadOnly(t *testing.T) {
	s, in := openFixture(t)
	before, _ := Encode(s)
	v := s.View(in, in.ReceivedAt, epoch)
	after, _ := Encode(s)
	if !reflect.DeepEqual(before, after) || v.Status != "attention" {
		t.Fatal("read mutated")
	}
	if e := s.Configure(in, false, []string{"FixtureService"}, 1, in.ReceivedAt); e != nil {
		t.Fatal(e)
	}
	if s.Incidents[0].ClosedReason != "policy-changed" || s.Incidents[0].RecoveryObservation != nil {
		t.Fatal(s)
	}
	if s.View(in, in.ReceivedAt, epoch).Checks[0].Observation != nil {
		t.Fatal("disabled evidence")
	}
	if e := s.Configure(in, true, []string{"FixtureService"}, 2, in.ReceivedAt); e != nil {
		t.Fatal(e)
	}
	evaluate(t, &s, in)
	if s.Checks[0].Status != "pending" {
		t.Fatal("reenable inherited confidence")
	}
}
func TestViewCurrentSourceAuthorityAndCanonicalCorruption(t *testing.T) {
	s, in := openFixture(t)
	for _, mode := range []string{"newer", "missing", "stale", "expiry", "identity", "epoch"} {
		copy := in
		copy.Sample.Services.Rows = append([]windowsmanaged.Service{}, in.Sample.Services.Rows...)
		now := in.ReceivedAt
		ep := epoch
		switch mode {
		case "newer":
			copy.Sequence++
		case "missing":
			copy.Sample.Services.Rows = []windowsmanaged.Service{}
			copy.Sample.Services.ObservedCount = 0
		case "stale":
			now = now.Add(MaxAge + time.Second)
		case "expiry":
			copy.AuthorityUntil = now
		case "identity":
			copy.InvitationID = "invite_" + strings.Repeat("4", 32)
		case "epoch":
			ep = ""
		}
		v := s.View(copy, now, ep)
		if v.Checks[0].Status != "unknown" || v.Checks[0].Observation != nil || v.Incidents[0].ResolvedAt != nil {
			t.Fatal(mode, v)
		}
	}
	raw, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(append(raw, '\n')); e == nil {
		t.Fatal("noncanonical accepted")
	}
	for _, change := range []func(*State){func(c *State) { c.SchemaVersion = "tracebolt.windows-capacity-view.v1" }, func(c *State) { c.Incidents[0].LastBadObservation.State = "running" }, func(c *State) { c.SequenceFloor++ }, func(c *State) { c.Checks[0].Name = "other" }, func(c *State) { c.Incidents[0].ID = "wcapacity_0000000000000001" }} {
		c, _ := Decode(raw)
		change(&c)
		if _, e := Encode(c); e == nil {
			t.Fatal("corruption encoded")
		}
	}
}
func TestWindowsServiceSharedViewFixture(t *testing.T) {
	views := map[string]View{}
	in := input()
	s := New()
	views["disabled"] = s.View(in, at, epoch)
	s, in = configured(t)
	views["unknown"] = s.View(in, at, epoch)
	evaluate(t, &s, in)
	views["pending"] = s.View(in, at, epoch)
	s, in = openFixture(t)
	views["attention"] = s.View(in, in.ReceivedAt, epoch)
	advance(&in, 30, "start_pending")
	evaluate(t, &s, in)
	views["unknownOpen"] = s.View(in, in.ReceivedAt, epoch)
	for i := 0; i < 3; i++ {
		advance(&in, 30, "running")
		evaluate(t, &s, in)
	}
	views["recovered"] = s.View(in, in.ReceivedAt, epoch)
	for i := 0; i < 5; i++ {
		advance(&in, 30, "paused")
		evaluate(t, &s, in)
	}
	if e := s.Configure(in, false, []string{"FixtureService"}, 1, in.ReceivedAt); e != nil {
		t.Fatal(e)
	}
	views["policyChanged"] = s.View(in, in.ReceivedAt, epoch)
	raw, e := json.MarshalIndent(views, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join("..", "..", "tests", "fixtures", "windows-service-health-view.json")
	if os.Getenv("UPDATE_WINDOWS_SERVICE_FIXTURE") == "1" {
		if e = os.WriteFile(path, append(raw, '\n'), 0644); e != nil {
			t.Fatal(e)
		}
	}
	expected, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytesEqualJSON(raw, expected) {
		t.Fatalf("shared fixture differs: %s", fmt.Sprint(path))
	}
}
func bytesEqualJSON(a, b []byte) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}
