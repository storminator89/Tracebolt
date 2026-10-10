package windowscapacity

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"localrmm/internal/model"
	"localrmm/internal/windowscontact"
)

var at = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

const epoch = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func input(v float64, sec int) Input {
	t := at.Add(time.Duration(sec) * time.Second)
	return Input{Input: windowscontact.Input{DeviceID: "agent_" + strings.Repeat("b", 32), InvitationID: "invite_" + strings.Repeat("c", 32), CertificateHash: strings.Repeat("d", 64), Authorized: true, AuthorityUntil: at.Add(24 * time.Hour), ReceivedAt: t, Sequence: uint64(sec + 1)}, Disk: model.Metric{Value: &v, Unit: "%", Quality: "healthy", Source: "fixture quota-aware system volume", CollectedAt: t}}
}
func configured(t *testing.T) State {
	t.Helper()
	s := New()
	if e := s.Configure(input(95, 0), true, 90, 0, at); e != nil {
		t.Fatal(e)
	}
	return s
}
func evaluate(t *testing.T, s *State, in Input, sec int) {
	t.Helper()
	if e := s.Evaluate(in, at.Add(time.Duration(sec)*time.Second), epoch); e != nil {
		t.Fatal(sec, e)
	}
	raw, e := Encode(*s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(raw); e != nil {
		t.Fatal(e)
	}
}
func opened(t *testing.T) State {
	t.Helper()
	s := configured(t)
	for _, sec := range []int{0, 30, 60} {
		evaluate(t, &s, input(95, sec), sec)
	}
	if s.Status != "pressure" || len(s.Incidents) != 1 {
		t.Fatal(s)
	}
	return s
}
func TestWindowsCapacityPolicyDefaultsAndValidation(t *testing.T) {
	s := New()
	if s.Policy.Enabled || s.Policy.ThresholdPercent != 90 || s.Status != "disabled" {
		t.Fatal(s)
	}
	evaluate(t, &s, input(99, 0), 0)
	if s.DeviceID != "" || len(s.Incidents) != 0 {
		t.Fatal("default created state")
	}
	for _, threshold := range []int{-1, 0, 49, 100, 101} {
		copy := s
		if e := copy.Configure(input(99, 0), true, threshold, 0, at); e == nil {
			t.Fatal(threshold)
		}
	}
	for _, threshold := range []int{50, 90, 99} {
		copy := s
		if e := copy.Configure(input(99, 0), true, threshold, 0, at); e != nil {
			t.Fatal(threshold, e)
		}
	}
	s = configured(t)
	if e := s.Configure(input(99, 0), true, 91, 0, at); e == nil {
		t.Fatal("stale revision")
	}
	if e := s.Configure(input(99, 0), true, 90, 1, at); e != nil || s.Policy.Revision != 1 {
		t.Fatal("same policy restarted", e)
	}
	for _, mutate := range []func(*Input){func(i *Input) { i.Authorized = false }, func(i *Input) { i.AuthorityUntil = at }, func(i *Input) { i.InvitationID = "invite_" + strings.Repeat("e", 32) }, func(i *Input) { i.CertificateHash = strings.Repeat("e", 64) }} {
		in := input(99, 0)
		mutate(&in)
		copy := s
		if e := copy.Configure(in, false, 90, 1, at); e == nil {
			t.Fatal("invalid authority/identity changed policy")
		}
	}
}
func TestWindowsCapacityThresholdHysteresisAndOriginalEvidence(t *testing.T) {
	s := configured(t)
	evaluate(t, &s, input(89.999, 0), 0)
	if s.Status != "within-policy" {
		t.Fatal(s.Status)
	}
	for _, sec := range []int{30, 60, 89} {
		evaluate(t, &s, input(90, sec), sec)
		if s.Status != "pending" {
			t.Fatal(s.Status)
		}
	}
	evaluate(t, &s, input(90, 90), 90)
	if s.Status != "pressure" {
		t.Fatal(s.Status)
	}
	opening := s.Incidents[0].OpeningObservation
	if opening.CollectedAt != at.Add(90*time.Second) || opening.Sequence != 91 || opening.Value != 90 {
		t.Fatal(opening)
	}
	evaluate(t, &s, input(86, 120), 120)
	if s.Status != "pressure" || s.RecoverySince != nil {
		t.Fatal("no hysteresis")
	}
	for _, sec := range []int{150, 180} {
		evaluate(t, &s, input(85, sec), sec)
		if s.Status != "pressure" {
			t.Fatal(s.Status)
		}
	}
	evaluate(t, &s, input(85, 210), 210)
	if s.Status != "within-policy" || s.Incidents[0].ClosedReason != "within-policy" || s.Incidents[0].RecoveryObservation.Sequence != 211 {
		t.Fatal(s)
	}
}
func TestWindowsCapacityUnknownNeverRecovers(t *testing.T) {
	cases := map[string]func(*Input){"missing": func(i *Input) { i.Disk.Value = nil }, "partial": func(i *Input) { i.Disk.Quality = "partial" }, "denied": func(i *Input) { i.Disk.Quality = "denied" }, "unavailable": func(i *Input) { i.Disk.Quality = "unavailable" }, "wrong unit": func(i *Input) { i.Disk.Unit = "bytes" }, "future capture": func(i *Input) { i.Disk.CollectedAt = i.ReceivedAt.Add(time.Nanosecond) }, "stale capture": func(i *Input) { i.Disk.CollectedAt = i.ReceivedAt.Add(-MaxAge - time.Nanosecond) }, "future receipt": func(i *Input) { i.ReceivedAt = i.ReceivedAt.Add(time.Nanosecond) }, "stale receipt": func(i *Input) { i.ReceivedAt = i.ReceivedAt.Add(-MaxAge - time.Nanosecond) }, "no receipt": func(i *Input) { i.ReceivedAt = time.Time{}; i.Sequence = 0 }, "revoked": func(i *Input) { i.Authorized = false }, "expired": func(i *Input) { i.AuthorityUntil = i.ReceivedAt }, "nan": func(i *Input) { v := math.NaN(); i.Disk.Value = &v }, "infinity": func(i *Input) { v := math.Inf(1); i.Disk.Value = &v }, "negative": func(i *Input) { v := -1.0; i.Disk.Value = &v }, "over100": func(i *Input) { v := 100.1; i.Disk.Value = &v }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := opened(t)
			in := input(10, 90)
			change(&in)
			evaluate(t, &s, in, 90)
			if s.Status != "unknown" || s.Observation != nil || s.Incidents[0].ResolvedAt != nil {
				t.Fatal(s)
			}
			evaluate(t, &s, input(10, 120), 120)
			if s.Incidents[0].ResolvedAt != nil {
				t.Fatal("unknown counted toward recovery")
			}
		})
	}
}
func TestWindowsCapacityExpiryEdgesAndViewsDoNotMutate(t *testing.T) {
	s := configured(t)
	in := input(40, 0)
	evaluate(t, &s, in, 0)
	before, _ := Encode(s)
	if v := s.View(in, at.Add(MaxAge), epoch); v.Status != "within-policy" {
		t.Fatal(v.Status)
	}
	for _, now := range []time.Time{at.Add(MaxAge + time.Nanosecond), at.Add(-time.Nanosecond)} {
		if v := s.View(in, now, epoch); v.Status != "unknown" || v.Observation != nil {
			t.Fatal(v)
		}
	}
	for _, e := range []string{"", strings.Repeat("e", 32)} {
		if s.View(in, at, e).Status != "unknown" {
			t.Fatal("restart lent continuity")
		}
	}
	fresh := input(41, 1)
	if s.View(fresh, at.Add(time.Second), epoch).Status != "unknown" {
		t.Fatal("unevaluated new report inherited decision")
	}
	after, _ := Encode(s)
	if !bytes.Equal(before, after) {
		t.Fatal("view mutates")
	}
}
func TestWindowsCapacityRestartsGapsAndRollback(t *testing.T) {
	for _, scenario := range []string{"restart", "gap", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			s := configured(t)
			evaluate(t, &s, input(95, 0), 0)
			evaluate(t, &s, input(95, 30), 30)
			switch scenario {
			case "restart":
				if e := s.Evaluate(input(95, 60), at.Add(time.Minute), strings.Repeat("e", 32)); e != nil {
					t.Fatal(e)
				}
			case "gap":
				evaluate(t, &s, input(95, 121), 121)
			case "unknown":
				in := input(95, 45)
				in.Disk.Value = nil
				evaluate(t, &s, in, 45)
				evaluate(t, &s, input(95, 60), 60)
			}
			if s.Status != "pending" || len(s.Incidents) != 0 {
				t.Fatal("borrowed continuity", s)
			}
		})
	}
	s := opened(t)
	before, _ := Encode(s)
	if e := s.Evaluate(input(10, 0), at, epoch); e == nil {
		t.Fatal("rollback accepted invalid chronology")
	}
	after, _ := Encode(s)
	_ = before
	_ = after
}
func TestWindowsCapacityDisableReenableNeverClaimsRecovery(t *testing.T) {
	s := opened(t)
	if e := s.Configure(input(95, 90), false, 90, 1, at.Add(90*time.Second)); e != nil {
		t.Fatal(e)
	}
	if s.Status != "disabled" || s.Incidents[0].ClosedReason != "policy-changed" || s.Incidents[0].RecoveryObservation != nil {
		t.Fatal(s)
	}
	if e := s.Configure(input(95, 120), true, 95, 2, at.Add(120*time.Second)); e != nil {
		t.Fatal(e)
	}
	evaluate(t, &s, input(95, 120), 120)
	if s.Status != "pending" || s.Policy.Revision != 3 || len(s.Incidents) != 1 {
		t.Fatal(s)
	}
	evaluate(t, &s, input(95, 150), 150)
	evaluate(t, &s, input(95, 180), 180)
	if len(s.Incidents) != 2 || s.Incidents[0].PolicyRevision != 3 || s.Incidents[1].ThresholdPercent != 90 {
		t.Fatal(s)
	}
}
func TestWindowsCapacityCanonicalCorruptionAndBounds(t *testing.T) {
	s := opened(t)
	raw, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), '\n'), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"surprise":1`), 1), []byte(`{}`)} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("noncanonical accepted")
		}
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("fixture")
	}
	for key, v := range map[string]any{"status": "within-policy", "nextId": 0, "policy": map[string]any{"enabled": true, "thresholdPercent": 100, "revision": 1}, "deviceId": "agent_" + strings.Repeat("0", 32)} {
		copy := map[string]any{}
		for k, v := range value {
			copy[k] = v
		}
		copy[key] = v
		b, _ := json.Marshal(copy)
		if _, e := Decode(b); e == nil {
			t.Fatal(key)
		}
	}
}

func TestWindowsCapacityRepeatedSamplesCannotConfirmOrRecover(t *testing.T) {
	s := configured(t)
	same := input(95, 0)
	for _, sec := range []int{0, 30, 60, 90, 120} {
		evaluate(t, &s, same, sec)
		if s.Status != "pending" || len(s.Incidents) != 0 {
			t.Fatal("same sample opened incident", sec, s)
		}
	}
	evaluate(t, &s, same, 121)
	if s.Status != "unknown" {
		t.Fatal("stale sample")
	}
	s = opened(t)
	last := s.Incidents[0].LastConfirmedAt
	evaluate(t, &s, input(95, 60), 90)
	if s.Incidents[0].LastConfirmedAt != last {
		t.Fatal("same high sample renewed confirmation")
	}
	low := input(80, 120)
	for _, sec := range []int{120, 150, 180, 210, 240} {
		evaluate(t, &s, low, sec)
		if s.Incidents[0].ResolvedAt != nil {
			t.Fatal("same low sample recovered", sec)
		}
	}
	evaluate(t, &s, low, 241)
	if s.Status != "unknown" || s.Incidents[0].ResolvedAt != nil {
		t.Fatal("stale low recovered")
	}
	// New sequence alone is insufficient when capture time does not advance.
	fresh := input(80, 270)
	fresh.Disk.CollectedAt = low.Disk.CollectedAt
	evaluate(t, &s, fresh, 270)
	if s.Incidents[0].ResolvedAt != nil {
		t.Fatal("capture time did not advance")
	}
}
func TestWindowsCapacityUnknownPreservesReceiptAndCaptureFloors(t *testing.T) {
	s := opened(t)
	in := input(80, 90)
	in.Disk.Quality = "partial"
	evaluate(t, &s, in, 90)
	if s.SequenceFloor != 91 || s.CaptureFloor == nil || !s.CaptureFloor.Equal(in.Disk.CollectedAt) {
		t.Fatal("unknown erased floors")
	}
	old := input(80, 60)
	for _, sec := range []int{120, 150} {
		evaluate(t, &s, old, sec)
		if s.Status != "unknown" || s.SequenceFloor != 91 {
			t.Fatal("old frame recovered after unknown")
		}
	}
	fresh := input(80, 180)
	fresh.Disk.CollectedAt = at.Add(60 * time.Second)
	evaluate(t, &s, fresh, 180)
	if s.Status != "unknown" || !s.CaptureFloor.Equal(in.Disk.CollectedAt) {
		t.Fatal("old capture recovered after unknown")
	}
	before, _ := Encode(s)
	if e := s.Evaluate(input(80, 0), at, epoch); e == nil {
		t.Fatal("clock rollback")
	}
	after, _ := Encode(s)
	if !bytes.Equal(before, after) {
		t.Fatal("error mutated floors")
	}
	if e := s.Configure(input(80, 210), false, 90, 1, at.Add(210*time.Second)); e != nil {
		t.Fatal(e)
	}
	if s.SequenceFloor != 181 || s.CaptureFloor == nil {
		t.Fatal("disable erased floors")
	}
}

func TestWindowsCapacityRetentionAndHistoryLimit(t *testing.T) {
	s := configured(t)
	sec := 0
	for n := 0; n < 105; n++ {
		for i := 0; i < 3; i++ {
			evaluate(t, &s, input(95, sec), sec)
			sec += 30
		}
		if s.Status != "pressure" {
			t.Fatal("episode did not open")
		}
		if e := s.Configure(input(95, sec), false, 90, s.Policy.Revision, at.Add(time.Duration(sec)*time.Second)); e != nil {
			t.Fatal(e)
		}
		if n < 104 {
			sec++
			if e := s.Configure(input(95, sec), true, 90, s.Policy.Revision, at.Add(time.Duration(sec)*time.Second)); e != nil {
				t.Fatal(e)
			}
		}
	}
	if len(s.Incidents) != MaxIncidents || s.NextID != 105 {
		t.Fatal("unbounded history", len(s.Incidents), s.NextID)
	}
	future := at.Add(31 * 24 * time.Hour)
	in := input(95, sec)
	in.AuthorityUntil = future.Add(time.Hour)
	if e := s.Configure(in, true, 90, s.Policy.Revision, future); e != nil {
		t.Fatal(e)
	}
	if len(s.Incidents) != 0 {
		t.Fatal("old closed history retained after policy update")
	}
	s = opened(t)
	in = input(0, 0)
	in.Authorized = false
	in.ReceivedAt = time.Time{}
	in.Sequence = 0
	in.Disk = model.Metric{}
	if e := s.Evaluate(in, future, epoch); e != nil {
		t.Fatal(e)
	}
	if len(s.Incidents) != 1 || s.Incidents[0].ResolvedAt != nil || s.Status != "unknown" {
		t.Fatal("unknown pruned open incident")
	}
}
