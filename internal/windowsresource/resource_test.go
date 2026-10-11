package windowsresource

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"localrmm/internal/model"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
)

var at = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

const epoch = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func input(cpu, memory float64, sec int) windowscapacity.Input {
	stamp := at.Add(time.Duration(sec) * time.Second)
	disk := 12.0
	metric := func(v *float64) model.Metric {
		return model.Metric{Value: v, Unit: "%", Quality: "healthy", CollectedAt: stamp}
	}
	return windowscapacity.Input{Input: windowscontact.Input{DeviceID: "agent_" + strings.Repeat("b", 32), InvitationID: "invite_" + strings.Repeat("c", 32), CertificateHash: strings.Repeat("d", 64), Authorized: true, AuthorityUntil: at.Add(24 * time.Hour), ReceivedAt: stamp, Sequence: uint64(sec + 1)}, Disk: metric(&disk), CPU: metric(&cpu), Memory: metric(&memory)}
}
func configured(t *testing.T, kind Kind) State {
	t.Helper()
	s := New(kind)
	if err := s.Configure(input(95, 95, 0), kind, true, 90, 0, at); err != nil {
		t.Fatal(err)
	}
	return s
}
func evaluate(t *testing.T, s *State, in windowscapacity.Input, sec int) {
	t.Helper()
	if err := s.Evaluate(in, s.Metric, at.Add(time.Duration(sec)*time.Second), epoch); err != nil {
		t.Fatal(err)
	}
	raw, err := Encode(*s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(raw, s.Metric); err != nil {
		t.Fatal(err)
	}
}
func opened(t *testing.T, kind Kind) State {
	t.Helper()
	s := configured(t, kind)
	for _, sec := range []int{0, 30, 60} {
		evaluate(t, &s, input(95, 95, sec), sec)
	}
	if s.Assessment.Status != "pressure" || len(s.Assessment.Incidents) != 1 {
		t.Fatal(s)
	}
	return s
}
func TestResourceTagDefaultOffAndSelection(t *testing.T) {
	for _, kind := range []Kind{CPU, Memory} {
		s := New(kind)
		if s.Validate(kind) != nil || s.Assessment.Policy.Enabled || s.Assessment.Policy.Revision != 0 || s.Assessment.Policy.ThresholdPercent != 90 {
			t.Fatal(s)
		}
		in := input(95, 20, 0)
		evaluate(t, &s, in, 0)
		if s.Assessment.DeviceID != "" {
			t.Fatal("disabled state bound itself")
		}
		if err := s.Configure(in, kind, true, 90, 0, at); err != nil {
			t.Fatal(err)
		}
		evaluate(t, &s, in, 0)
		want := "pending"
		if kind == Memory {
			want = "within-policy"
		}
		if s.Assessment.Status != want {
			t.Fatal("wrong basic metric selected", kind, s.Assessment.Status)
		}
		other := CPU
		if kind == CPU {
			other = Memory
		}
		before, _ := Encode(s)
		if s.Configure(in, other, false, 90, 1, at) == nil || s.Evaluate(in, other, at, epoch) == nil {
			t.Fatal("metric tag mutable")
		}
		after, _ := Encode(s)
		if !bytes.Equal(before, after) {
			t.Fatal("rejected tag modified state")
		}
		if _, err := Decode(before, other); err == nil {
			t.Fatal("cross-metric persisted state accepted")
		}
		disk, _ := windowscapacity.Encode(s.Assessment)
		if _, err := Decode(disk, kind); err == nil {
			t.Fatal("disk state became resource opt-in")
		}
	}
	if _, err := Select(input(95, 95, 0), Kind("disk")); err == nil {
		t.Fatal("arbitrary metric accepted")
	}
}
func TestResourceDistinctSamplesAndHysteresis(t *testing.T) {
	for _, kind := range []Kind{CPU, Memory} {
		t.Run(string(kind), func(t *testing.T) {
			s := configured(t, kind)
			same := input(95, 95, 0)
			for _, sec := range []int{0, 30, 60, 90, 120} {
				evaluate(t, &s, same, sec)
				if len(s.Assessment.Incidents) != 0 {
					t.Fatal("same sample opened")
				}
			}
			evaluate(t, &s, same, 121)
			if s.Assessment.Status != "unknown" {
				t.Fatal("stale became success")
			}
			s = opened(t, kind)
			for _, sec := range []int{90, 120, 150} {
				evaluate(t, &s, input(85.01, 85.01, sec), sec)
			}
			if s.Assessment.RecoverySince != nil || s.Assessment.Incidents[0].ResolvedAt != nil {
				t.Fatal("hysteresis band recovered")
			}
			low := input(85, 85, 180)
			for _, sec := range []int{180, 210, 240} {
				evaluate(t, &s, low, sec)
				if s.Assessment.Incidents[0].ResolvedAt != nil {
					t.Fatal("same low recovered")
				}
			}
			evaluate(t, &s, input(85, 85, 270), 270)
			if s.Assessment.Status != "within-policy" || s.Assessment.Incidents[0].RecoveryObservation.Sequence != 271 {
				t.Fatal("distinct source recovery failed")
			}
		})
	}
}
func TestResourceUnknownFloorsAndIndependentCaptureTimes(t *testing.T) {
	for _, kind := range []Kind{CPU, Memory} {
		for _, quality := range []string{"missing", "partial", "denied", "stale", "future", "nan"} {
			t.Run(string(kind)+"/"+quality, func(t *testing.T) {
				s := opened(t, kind)
				in := input(10, 10, 90)
				metric := &in.CPU
				if kind == Memory {
					metric = &in.Memory
				}
				switch quality {
				case "missing":
					metric.Value = nil
				case "partial", "denied":
					metric.Quality = quality
				case "stale":
					metric.CollectedAt = at.Add(-time.Minute)
				case "future":
					metric.CollectedAt = in.ReceivedAt.Add(time.Nanosecond)
				case "nan":
					v := math.NaN()
					metric.Value = &v
				}
				evaluate(t, &s, in, 90)
				if s.Assessment.Status != "unknown" || s.Assessment.Incidents[0].ResolvedAt != nil || s.Assessment.SequenceFloor != 91 {
					t.Fatal("unknown recovered or erased receipt floor")
				}
				evaluate(t, &s, input(10, 10, 60), 120)
				if s.Assessment.Status != "unknown" || s.Assessment.SequenceFloor != 91 {
					t.Fatal("older source reused")
				}
			})
		}
	}
	cpu := configured(t, CPU)
	memory := configured(t, Memory)
	in := input(95, 95, 60)
	in.Memory.CollectedAt = at.Add(30 * time.Second)
	evaluate(t, &cpu, in, 60)
	evaluate(t, &memory, in, 60)
	if !cpu.Assessment.CaptureFloor.Equal(in.CPU.CollectedAt) || !memory.Assessment.CaptureFloor.Equal(in.Memory.CollectedAt) {
		t.Fatal("metric capture floors conflated")
	}
}
func TestResourceDisableRestartAndPolicyRevision(t *testing.T) {
	for _, kind := range []Kind{CPU, Memory} {
		t.Run(string(kind), func(t *testing.T) {
			s := opened(t, kind)
			in := input(95, 95, 90)
			if err := s.Configure(in, kind, false, 90, 1, in.ReceivedAt); err != nil {
				t.Fatal(err)
			}
			if s.Assessment.Incidents[0].ClosedReason != "policy-changed" || s.Assessment.Incidents[0].RecoveryObservation != nil || s.Assessment.SequenceFloor != 61 {
				t.Fatal("disable lost semantics")
			}
			if s.Configure(in, kind, true, 90, 1, in.ReceivedAt) == nil {
				t.Fatal("stale revision")
			}
			if err := s.Configure(in, kind, true, 90, 2, in.ReceivedAt); err != nil {
				t.Fatal(err)
			}
			evaluate(t, &s, in, 90)
			evaluate(t, &s, input(95, 95, 120), 120)
			if err := s.Evaluate(input(95, 95, 150), kind, at.Add(150*time.Second), strings.Repeat("e", 32)); err != nil {
				t.Fatal(err)
			}
			if s.Assessment.Status != "pending" || len(s.Assessment.Incidents) != 1 {
				t.Fatal("restart borrowed continuity")
			}
			before, _ := Encode(s)
			if s.Evaluate(input(95, 95, 0), kind, at, epoch) == nil {
				t.Fatal("rollback accepted")
			}
			after, _ := Encode(s)
			if !bytes.Equal(before, after) {
				t.Fatal("rollback changed state")
			}
		})
	}
}
func TestResourceCanonicalEnvelopeAndFixture(t *testing.T) {
	views := map[Kind]View{}
	for _, kind := range []Kind{CPU, Memory} {
		s := opened(t, kind)
		raw, err := Encode(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range [][]byte{append(append([]byte{}, raw...), '\n'), bytes.Replace(raw, []byte(`"metric":`), []byte(`"unknown":0,"metric":`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)} {
			if _, err = Decode(bad, kind); err == nil {
				t.Fatal("noncanonical state accepted")
			}
		}
		view, err := MakeView(s.Assessment, input(95, 95, 60), kind, at.Add(time.Minute), epoch)
		if err != nil {
			t.Fatal(err)
		}
		views[kind] = view
	}
	raw, err := json.MarshalIndent(views, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := "../../tests/fixtures/windows-resource-view.json"
	if os.Getenv("UPDATE_WINDOWS_RESOURCE_FIXTURE") == "1" {
		if err = os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, raw) {
		t.Fatal("shared Go/TypeScript resource fixture differs")
	}
}
