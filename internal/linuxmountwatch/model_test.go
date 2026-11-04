package linuxmountwatch

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

var testAt = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func fixture() (*State, Input, Command) {
	target := Target{"/var", "ext4", "fs_8_1"}
	in := Input{DeviceID: "agent_" + strings.Repeat("a", 32), Identity: strings.Repeat("b", 64), SourceToken: "mountsource_" + strings.Repeat("c", 32), AuthorityUntil: testAt.Add(time.Hour), Available: true, Reason: "none", Generation: &Generation{1, "sample_" + strings.Repeat("d", 32), testAt, testAt}, Options: []Target{target}, Sample: &Sample{target, "mount_3", 95, 1000, 50}}
	c := Command{RequestID: "mountrequest_" + strings.Repeat("e", 32), SourceToken: in.SourceToken, Operation: "enable", Target: &target, Threshold: 90, Recovery: 80, RetentionAcknowledged: true}
	return New(in.DeviceID), in, c
}
func feed(t *testing.T, s *State, in Input, seq uint64, second int, used float64) Input {
	t.Helper()
	at := testAt.Add(time.Duration(second) * time.Second)
	in.Generation = &Generation{seq, fmt.Sprintf("sample_%032x", seq), at, at}
	v := *in.Sample
	v.UsedPercent = used
	v.AvailableBytes = uint64(1000 - used*10)
	in.Sample = &v
	if e := Evaluate(s, in, at); e != nil {
		t.Fatal(e)
	}
	if e := Validate(s); e != nil {
		t.Fatalf("invalid state: %+v", s)
	}
	return in
}
func TestMountWatchOptInAdvancingAndHysteresis(t *testing.T) {
	s, in, c := fixture()
	before := clone(s)
	if e := Evaluate(s, in, testAt); e != nil || !reflect.DeepEqual(s, before) {
		t.Fatal("default off changed")
	}
	if e := Apply(s, in, c, testAt); e != nil {
		t.Fatal(e)
	}
	if e := Apply(s, in, c, testAt.Add(time.Second)); e != nil || s.Revision != 1 {
		t.Fatal("exact replay changed revision")
	}
	if e := Evaluate(s, in, testAt.Add(time.Second)); e != nil || s.Check.Bad != 0 {
		t.Fatal("enable counted old generation")
	}
	in = feed(t, s, in, 2, 60, 95)
	if s.Check.Condition != "pending" || len(s.Incidents) != 0 {
		t.Fatal(s)
	}
	if e := Evaluate(s, in, testAt.Add(70*time.Second)); e != nil || s.Check.Bad != 1 {
		t.Fatal("repeat counted")
	}
	in = feed(t, s, in, 3, 120, 95)
	if len(s.Incidents) != 1 || s.Incidents[0].State != "open" {
		t.Fatal(s)
	}
	in = feed(t, s, in, 4, 180, 85)
	if s.Check.Condition != "open" {
		t.Fatal("hysteresis recovered")
	}
	in = feed(t, s, in, 5, 240, 75)
	if s.Check.Condition != "recovering" {
		t.Fatal(s)
	}
	feed(t, s, in, 6, 300, 75)
	if s.Incidents[0].State != "recovered" || s.Check.Condition != "clear" {
		t.Fatal(s)
	}
}
func TestMountWatchUnknownCannotRecover(t *testing.T) {
	for _, mode := range []string{"missing", "stale", "future", "identity", "source", "clock", "duplicate-location"} {
		t.Run(mode, func(t *testing.T) {
			s, in, c := fixture()
			_ = Apply(s, in, c, testAt)
			in = feed(t, s, in, 2, 60, 95)
			in = feed(t, s, in, 3, 120, 95)
			now := testAt.Add(130 * time.Second)
			switch mode {
			case "missing", "duplicate-location":
				in.Sample = nil
			case "stale":
				now = testAt.Add(300 * time.Second)
			case "future":
				in.Generation.ReceivedAt = now.Add(time.Second)
			case "identity":
				in.Identity = strings.Repeat("f", 64)
			case "source":
				in.Available = false
			case "clock":
				now = testAt
			}
			if e := Evaluate(s, in, now); e != nil {
				t.Fatal(e)
			}
			if s.Check.Condition != "unknown" || s.Incidents[0].State != "open" {
				t.Fatal(s)
			}
		})
	}
}
func TestMountWatchGapsAndReplacementResetConfirmation(t *testing.T) {
	for _, mode := range []string{"gap", "mount", "capture", "sequence"} {
		t.Run(mode, func(t *testing.T) {
			s, in, c := fixture()
			_ = Apply(s, in, c, testAt)
			in = feed(t, s, in, 2, 60, 95)
			switch mode {
			case "gap":
				in = feed(t, s, in, 3, 300, 95)
			case "mount":
				in.Sample.MountID = "mount_99"
				in = feed(t, s, in, 3, 120, 95)
			case "capture":
				in.Generation = &Generation{3, fmt.Sprintf("sample_%032x", 3), testAt.Add(60 * time.Second), testAt.Add(120 * time.Second)}
				_ = Evaluate(s, in, testAt.Add(120*time.Second))
			case "sequence":
				in.Generation.Sequence = 1
				_ = Evaluate(s, in, testAt.Add(120*time.Second))
			}
			if len(s.Incidents) != 0 || s.Check.Bad > 1 {
				t.Fatal(s)
			}
		})
	}
}
func TestMountWatchDisableAndAcknowledgeNeverRecover(t *testing.T) {
	s, in, c := fixture()
	_ = Apply(s, in, c, testAt)
	in = feed(t, s, in, 2, 60, 95)
	in = feed(t, s, in, 3, 120, 95)
	ack := Command{RequestID: "mountrequest_" + strings.Repeat("1", 32), ExpectedRevision: 1, SourceToken: in.SourceToken, Operation: "acknowledge", IncidentID: s.Incidents[0].ID}
	if e := Apply(s, in, ack, testAt.Add(130*time.Second)); e != nil || s.Incidents[0].State != "open" || s.Incidents[0].AcknowledgedAt == nil {
		t.Fatal(e)
	}
	stop := Command{RequestID: "mountrequest_" + strings.Repeat("2", 32), ExpectedRevision: 2, SourceToken: in.SourceToken, Operation: "disable"}
	if e := Apply(s, in, stop, testAt.Add(140*time.Second)); e != nil || s.Incidents[0].State != "monitoring_stopped" || s.Policy.Enabled {
		t.Fatal(e)
	}
	if e := Validate(s); e != nil {
		t.Fatal(e)
	}
}
func TestMountWatchRejectsTargetsAndMalformedState(t *testing.T) {
	for _, p := range []string{"/", "var", "/var/../data", "/home/[redacted]", "/var\n"} {
		if ValidTarget(Target{p, "ext4", "fs_8_1"}) {
			t.Fatal(p)
		}
	}
	s, in, c := fixture()
	c.RetentionAcknowledged = false
	if Apply(s, in, c, testAt) == nil {
		t.Fatal("implicit retention")
	}
	c.RetentionAcknowledged = true
	_ = Apply(s, in, c, testAt)
	raw, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(raw); e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(append(raw, ' ')); e == nil {
		t.Fatal("noncanonical accepted")
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["unknown"] = true
	raw, _ = json.Marshal(m)
	if _, e = Decode(raw); e == nil {
		t.Fatal("extra field accepted")
	}
}

func TestMountWatchNonadvancingCaptureCannotBecomeFirstConfirmation(t *testing.T) {
	s, in, c := fixture()
	_ = Apply(s, in, c, testAt)
	in = feed(t, s, in, 2, 60, 95)
	in.Generation = &Generation{3, fmt.Sprintf("sample_%032x", 3), testAt.Add(60 * time.Second), testAt.Add(120 * time.Second)}
	if e := Evaluate(s, in, testAt.Add(120*time.Second)); e != nil || s.Check.Bad != 0 {
		t.Fatal("nonadvancing capture counted", e, s.Check)
	}
	in = feed(t, s, in, 4, 180, 95)
	if len(s.Incidents) != 0 || s.Check.Bad != 1 {
		t.Fatal("old capture formed pair")
	}
}
func TestMountWatchStoppedHistoryEligibleCleanup(t *testing.T) {
	s, in, c := fixture()
	_ = Apply(s, in, c, testAt)
	in = feed(t, s, in, 2, 60, 95)
	in = feed(t, s, in, 3, 120, 95)
	stop := Command{RequestID: "mountrequest_" + strings.Repeat("2", 32), ExpectedRevision: 1, SourceToken: in.SourceToken, Operation: "disable"}
	_ = Apply(s, in, stop, testAt.Add(130*time.Second))
	now := testAt.Add(Retention + time.Hour)
	in.AuthorityUntil = now.Add(time.Hour)
	if e := Evaluate(s, in, now); e != nil || len(s.Incidents) != 0 || s.EarlierOmitted != 1 {
		t.Fatal("disabled retention did not clean", e)
	}
}

func TestMountWatchLongTargetsKeepHistoryWithinBudget(t *testing.T) {
	s, in, c := fixture()
	c.Target.MountPoint = "/" + strings.Repeat("x", 4000)
	in.Sample.Target = *c.Target
	in.Options = []Target{*c.Target}
	_ = Apply(s, in, c, testAt)
	seq := uint64(1)
	second := 0
	for n := 0; n < 140; n++ {
		for _, used := range []float64{95, 95, 75, 75} {
			seq++
			second += 30
			in.AuthorityUntil = testAt.Add(48 * time.Hour)
			in = feed(t, s, in, seq, second, used)
		}
	}
	raw, e := Encode(s)
	if e != nil || len(raw) > MaxStateBytes || s.EarlierOmitted == 0 {
		t.Fatal("history exceeded budget", len(raw), e)
	}
}

func TestMountWatchPublicRequiresCurrentEvaluatedTarget(t *testing.T) {
	for _, mode := range []string{"missing", "replacement", "new_generation"} {
		t.Run(mode, func(t *testing.T) {
			s, in, c := fixture()
			_ = Apply(s, in, c, testAt)
			in = feed(t, s, in, 2, 60, 75)
			if Public(s, in, testAt.Add(time.Second*61), true).Check.Condition != "clear" {
				t.Fatal("missing fixture check")
			}
			switch mode {
			case "missing":
				in.Sample = nil
			case "replacement":
				v := *in.Sample
				v.MountID = "mount_99"
				in.Sample = &v
			case "new_generation":
				g := *in.Generation
				g.Sequence++
				g.ID = fmt.Sprintf("sample_%032x", g.Sequence)
				in.Generation = &g
			}
			if Public(s, in, testAt.Add(time.Second*61), true).Check.Condition != "unknown" {
				t.Fatal("old result described new source")
			}
		})
	}
}
func TestMountWatchUnavailableEnabledSourceStillPrunesClosedHistory(t *testing.T) {
	s, in, c := fixture()
	_ = Apply(s, in, c, testAt)
	for seq, used := range []float64{95, 95, 75, 75} {
		in = feed(t, s, in, uint64(seq+2), (seq+1)*60, used)
	}
	now := testAt.Add(Retention + time.Hour)
	in.AuthorityUntil = now.Add(time.Hour)
	in.Available = false
	in.Reason = "stale"
	if e := Evaluate(s, in, now); e != nil || len(s.Incidents) != 0 || s.EarlierOmitted != 1 {
		t.Fatal("missing source prevented retention", e)
	}
}

func TestMountWatchPublicDiagnosticsWithholdCurrentSource(t *testing.T) {
	for _, mode := range []string{"identity_changed", "clock_uncertain", "clock_future_generation"} {
		t.Run(mode, func(t *testing.T) {
			s, in, c := fixture()
			if e := Apply(s, in, c, testAt); e != nil {
				t.Fatal(e)
			}
			in = feed(t, s, in, 2, 60, 95)
			in = feed(t, s, in, 3, 120, 95)
			in.MoreOptions = true
			now := testAt.Add(121 * time.Second)
			status := mode
			switch mode {
			case "identity_changed":
				in.Identity = strings.Repeat("f", 64)
			case "clock_uncertain":
				s.ClockFloor = now.Add(time.Second)
			case "clock_future_generation":
				now = testAt.Add(119 * time.Second)
				status = "clock_uncertain"
			}
			before := clone(s)
			v := Public(s, in, now, true)
			if v.SourceStatus != status || v.CanManage || v.Check.Condition != "unknown" || len(v.Options) != 0 || v.MoreOptions || v.Generation != nil {
				t.Fatalf("invalid diagnostic: %+v", v)
			}
			if mode == "identity_changed" {
				if v.Policy.Enabled || len(v.Incidents) != 0 || v.Revision != 0 || v.LastRequest != nil {
					t.Fatal("old identity state disclosed")
				}
			} else if !v.Policy.Enabled || len(v.Incidents) != 1 || v.Incidents[0].State != "open" {
				t.Fatal("clock diagnostic lost unresolved history")
			}
			if !reflect.DeepEqual(s, before) {
				t.Fatal("diagnostic read changed state")
			}
		})
	}
}
