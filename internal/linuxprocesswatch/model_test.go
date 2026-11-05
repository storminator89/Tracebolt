package linuxprocesswatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

var start = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func fixture() (*State, Input) {
	s := New("agent_" + strings.Repeat("a", 32))
	in := Input{DeviceID: s.DeviceID, Identity: strings.Repeat("b", 64), Epoch: strings.Repeat("c", 32), SourceToken: "processsource_" + strings.Repeat("d", 32), AuthorityUntil: start.Add(24 * time.Hour), Authorized: true, Available: true, Reason: "none"}
	generation(&in, 1, 0, 0)
	return s, in
}
func generation(in *Input, seq int, active, unidentified uint32) time.Time {
	t := start.Add(time.Duration(seq) * 10 * time.Second)
	in.Sample = &Generation{Sequence: fmt.Sprint(seq), GenerationID: fmt.Sprintf("sample_%032x", seq), ManifestHash: strings.Repeat("e", 64), CaptureStartedAt: t, CaptureFinishedAt: t.Add(time.Second), ReceivedAt: t.Add(2 * time.Second), TotalRows: 10, UnidentifiedRows: unidentified}
	in.Counts = []Count{{Name: "daemon", ActiveCount: active}}
	return t.Add(3 * time.Second)
}
func enable(t *testing.T, s *State, in Input) {
	t.Helper()
	err := Configure(s, in, ConfigureRequest{ExpectedRevision: s.Revision, RequestID: fmt.Sprintf("processrequest_%032x", s.Revision+1), SourceToken: in.SourceToken, Enabled: true, Names: []string{"daemon"}, ConsecutiveFailures: 2, RetentionAcknowledged: true}, in.Sample.ReceivedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, s)
}
func eval(t *testing.T, s *State, in Input, now time.Time) {
	t.Helper()
	if err := Evaluate(s, in, now); err != nil {
		t.Fatal(err)
	}
	roundtrip(t, s)
}
func roundtrip(t *testing.T, s *State) {
	t.Helper()
	b, e := Encode(s)
	if e != nil {
		t.Fatalf("encode: %v state=%+v", e, s)
	}
	n, e := Decode(b)
	if e != nil || !reflect.DeepEqual(s, n) {
		t.Fatalf("roundtrip: %v", e)
	}
}
func TestConfirmationRecoveryAndReplay(t *testing.T) {
	s, in := fixture()
	enable(t, s, in)
	eval(t, s, in, in.Sample.ReceivedAt.Add(time.Second))
	if s.Progress[0].FailureCount != 0 {
		t.Fatal("pre-policy generation counted")
	}
	now := generation(&in, 2, 0, 0)
	eval(t, s, in, now)
	eval(t, s, in, now.Add(time.Second))
	if s.Progress[0].FailureCount != 1 {
		t.Fatal("repeated generation counted")
	}
	now = generation(&in, 3, 0, 0)
	eval(t, s, in, now)
	if len(s.Incidents) != 1 || s.Incidents[0].State != "open" || !s.Incidents[0].OpenedAt.Equal(now) {
		t.Fatal("not confirmed")
	}
	r := AcknowledgeRequest{ExpectedRevision: s.Revision, RequestID: "processrequest_" + strings.Repeat("f", 32), SourceToken: in.SourceToken, IncidentID: s.Incidents[0].ID}
	if e := Acknowledge(s, in, r, now); e != nil {
		t.Fatal(e)
	}
	rev := s.Revision
	if e := Acknowledge(s, in, r, now.Add(time.Second)); e != nil || s.Revision != rev {
		t.Fatal("exact replay")
	}
	roundtrip(t, s)
	now = generation(&in, 4, 1, 0)
	eval(t, s, in, now)
	if s.Incidents[0].State != "open" {
		t.Fatal("early recovery")
	}
	now = generation(&in, 5, 1, 0)
	eval(t, s, in, now)
	if s.Incidents[0].State != "recovered" || s.Incidents[0].Recovery.Samples != 2 {
		t.Fatal("no recovery")
	}
}
func TestUnknownBreaksStreakAndPositivePartial(t *testing.T) {
	s, in := fixture()
	enable(t, s, in)
	now := generation(&in, 2, 0, 0)
	eval(t, s, in, now)
	now = generation(&in, 3, 0, 1)
	eval(t, s, in, now)
	if s.Progress[0].Condition != "unknown" {
		t.Fatal("unknown row proved missing")
	}
	now = generation(&in, 4, 0, 0)
	eval(t, s, in, now)
	if len(s.Incidents) != 0 || s.Progress[0].FailureCount != 1 {
		t.Fatal("unknown did not reset")
	}
	now = generation(&in, 5, 1, 1)
	eval(t, s, in, now)
	if s.Progress[0].Condition != "present" {
		t.Fatal("positive partial was hidden")
	}
}
func TestEpochConsumesSampleAndIdentityRetires(t *testing.T) {
	s, in := fixture()
	enable(t, s, in)
	for seq := 2; seq <= 3; seq++ {
		now := generation(&in, seq, 0, 0)
		eval(t, s, in, now)
	}
	in.Epoch = strings.Repeat("1", 32)
	now := generation(&in, 4, 1, 0)
	eval(t, s, in, now)
	eval(t, s, in, now)
	if s.Progress[0].SuccessCount != 0 || s.Incidents[0].State != "open" {
		t.Fatal("restart counted existing sample")
	}
	now = generation(&in, 5, 1, 0)
	eval(t, s, in, now)
	if s.Progress[0].SuccessCount != 1 {
		t.Fatal("fresh restart sample not counted")
	}
	in.Identity = strings.Repeat("2", 64)
	eval(t, s, in, now)
	if s.Policy.Enabled || s.Incidents[0].State != "monitoring_stopped" {
		t.Fatal("identity reused policy")
	}
}
func TestFreshnessViewIsPure(t *testing.T) {
	s, in := fixture()
	enable(t, s, in)
	now := generation(&in, 2, 0, 0)
	eval(t, s, in, now)
	before, _ := Encode(s)
	v := View(s, in, in.Sample.CaptureStartedAt.Add(MaxAge), true)
	if v.Source.Status != "unknown" || v.Source.Generation != nil || v.Checks[0].ActiveCount != nil || v.Checks[0].FailureCount != 0 {
		t.Fatal("stale view evidence")
	}
	after, _ := Encode(s)
	if !bytes.Equal(before, after) {
		t.Fatal("view mutated state")
	}
	v = View(s, in, in.Sample.CaptureStartedAt.Add(MaxAge-time.Second), true)
	if !v.ValidUntil.Equal(in.Sample.CaptureStartedAt.Add(MaxAge)) {
		t.Fatal("view expiry extended evidence")
	}
	raw, _ := json.Marshal(v)
	if bytes.Contains(raw, []byte(in.Identity)) || bytes.Contains(raw, []byte(in.Epoch)) {
		t.Fatal("private identity leak")
	}
}
func TestInvalidAndFrozenGenerations(t *testing.T) {
	for _, mode := range []string{"frozen", "sequence", "unknown", "counts", "future", "unauthorized"} {
		t.Run(mode, func(t *testing.T) {
			s, in := fixture()
			enable(t, s, in)
			now := generation(&in, 2, 0, 0)
			eval(t, s, in, now)
			old := *in.Sample
			now = generation(&in, 3, 0, 0)
			switch mode {
			case "frozen":
				in.Sample.CaptureStartedAt = old.CaptureStartedAt
			case "sequence":
				in.Sample.Sequence = old.Sequence
			case "unknown":
				in.Available = false
				in.Reason = "newer_attempt"
			case "counts":
				in.Counts = nil
			case "future":
				now = in.Sample.CaptureStartedAt
			case "unauthorized":
				in.Authorized = false
			}
			eval(t, s, in, now)
			if len(s.Incidents) != 0 || s.Progress[0].FailureCount != 0 {
				t.Fatal("invalid evidence counted")
			}
		})
	}
}
func TestControlCASDisableRollback(t *testing.T) {
	s, in := fixture()
	enable(t, s, in)
	for seq := 2; seq <= 3; seq++ {
		now := generation(&in, seq, 0, 0)
		eval(t, s, in, now)
	}
	r := ConfigureRequest{ExpectedRevision: s.Revision, RequestID: fmt.Sprintf("processrequest_%032x", 20), SourceToken: in.SourceToken}
	if err := Configure(s, in, r, start); err != nil {
		t.Fatal(err)
	}
	if s.Policy.Enabled || s.Incidents[0].ClosedAt != nil || s.Incidents[0].State != "monitoring_stopped" {
		t.Fatal("unsafe rollback close")
	}
	roundtrip(t, s)
	if err := Evaluate(s, in, start); err != nil {
		t.Fatal(err)
	}
	r.RequestID = fmt.Sprintf("processrequest_%032x", 21)
	if err := Configure(s, in, r, s.ClockFloor); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision accepted")
	}
}
func TestStrictEncodingNames(t *testing.T) {
	s, _ := fixture()
	roundtrip(t, s)
	b, _ := Encode(s)
	for _, bad := range [][]byte{append(b, ' '), append(b, []byte("{}")...), bytes.Replace(b, []byte(`"revision":0`), []byte(`"revision":0,"revision":0`), 1), bytes.Replace(b, []byte(`"revision":0`), []byte(`"revision":0,"extra":0`), 1)} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("noncanonical accepted")
		}
	}
	for _, n := range []string{"", "a\n", "a\u200d", "a\u2028", "�", strings.Repeat("x", 65)} {
		if ValidName(n) {
			t.Fatalf("invalid name accepted %q", n)
		}
	}
	if !ValidName(" daemon.服务 ") {
		t.Fatal("name normalized")
	}
}
func TestRetentionNeverDropsOpen(t *testing.T) {
	s, in := fixture()
	enable(t, s, in)
	for seq := 2; seq <= 3; seq++ {
		now := generation(&in, seq, 0, 0)
		eval(t, s, in, now)
	}
	now := start.Add(Retention + time.Hour)
	in.AuthorityUntil = now.Add(time.Hour)
	in.Available = false
	in.Reason = "stale"
	eval(t, s, in, now)
	if len(s.Incidents) != 1 || s.Incidents[0].State != "open" {
		t.Fatal("open aged out")
	}
}
func TestRollbackResetsWithoutDecreasingFloors(t *testing.T) {
	s, in := fixture()
	enable(t, s, in)
	now := generation(&in, 2, 0, 0)
	eval(t, s, in, now)
	floor := s.ClockFloor
	eval(t, s, in, start)
	if !s.ClockFloor.Equal(floor) || s.Progress[0].FailureCount != 0 {
		t.Fatal("rollback reset/floor")
	}
	eval(t, s, in, now)
	if s.Progress[0].FailureCount != 0 {
		t.Fatal("rollback replay earned credit")
	}
	now = generation(&in, 3, 0, 0)
	eval(t, s, in, now)
	if s.Progress[0].FailureCount != 1 {
		t.Fatal("fresh sample must restart confirmation")
	}
}
func TestCapacityAndReadRetention(t *testing.T) {
	s, in := fixture()
	enable(t, s, in)
	seq := 2
	for episode := 0; episode < MaxIncidents+2; episode++ {
		for _, active := range []uint32{0, 0, 1, 1} {
			now := generation(&in, seq, active, 0)
			eval(t, s, in, now)
			seq++
		}
	}
	if len(s.Incidents) > MaxIncidents || len(s.Incidents) < 8 || uint64(len(s.Incidents))+s.EarlierOmitted != MaxIncidents+2 {
		t.Fatalf("unbounded history %d %d", len(s.Incidents), s.EarlierOmitted)
	}
	before, _ := Encode(s)
	v := View(s, in, s.ClockFloor.Add(Retention+time.Second), true)
	after, _ := Encode(s)
	if len(v.Incidents) != 0 || v.EarlierOmitted != MaxIncidents+2 || !bytes.Equal(before, after) {
		t.Fatal("read retention mutation or stale history")
	}
}
func TestThreeFailurePolicyAndReplacement(t *testing.T) {
	s, in := fixture()
	r := ConfigureRequest{RequestID: fmt.Sprintf("processrequest_%032x", 1), SourceToken: in.SourceToken, Enabled: true, Names: []string{"daemon"}, ConsecutiveFailures: 3, RetentionAcknowledged: true}
	if e := Configure(s, in, r, in.Sample.ReceivedAt.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	for seq := 2; seq <= 4; seq++ {
		now := generation(&in, seq, 0, 0)
		eval(t, s, in, now)
		if seq < 4 && len(s.Incidents) != 0 {
			t.Fatal("early 3-sample incident")
		}
	}
	if s.Incidents[0].Opening.Samples != 3 {
		t.Fatal("proof count")
	}
	enable(t, s, in)
	if s.Incidents[0].State != "monitoring_stopped" || s.Progress[0].FailureCount != 0 {
		t.Fatal("replacement did not retire")
	}
}
func TestNonAdvancingFloorCannotBeReplayed(t *testing.T) {
	s, in := fixture()
	enable(t, s, in)
	now := generation(&in, 2, 0, 0)
	eval(t, s, in, now)
	old := *in.Sample
	now = generation(&in, 3, 0, 0)
	in.Sample.CaptureStartedAt = old.CaptureStartedAt
	eval(t, s, in, now)
	now = generation(&in, 3, 0, 0)
	eval(t, s, in, now)
	if s.Progress[0].FailureCount != 0 {
		t.Fatal("same higher sequence repaired into count")
	}
	now = generation(&in, 4, 0, 0)
	eval(t, s, in, now)
	if s.Progress[0].FailureCount != 1 {
		t.Fatal("new advancing generation not counted")
	}
}
func FuzzStrictDecode(f *testing.F) {
	s, _ := fixture()
	b, _ := Encode(s)
	f.Add(b)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, e := Decode(b)
		if e != nil {
			return
		}
		encoded, e := Encode(s)
		if e != nil || !bytes.Equal(encoded, b) {
			t.Fatal("accepted noncanonical bytes")
		}
	})
}

func TestPrePolicyCaptureNeverCounts(t *testing.T) {
	s, in := fixture()
	enable(t, s, in)
	for seq := 2; seq <= 3; seq++ {
		generation(&in, seq, 0, 0)
		in.Sample.CaptureStartedAt = start.Add(time.Duration(seq+9) * time.Second)
		in.Sample.CaptureFinishedAt = in.Sample.CaptureStartedAt.Add(time.Millisecond)
		eval(t, s, in, in.Sample.ReceivedAt.Add(time.Second))
	}
	if len(s.Incidents) != 0 || s.Progress[0].FailureCount != 0 {
		t.Fatal("pre-consent capture counted")
	}
	now := generation(&in, 4, 0, 0)
	eval(t, s, in, now)
	if s.Progress[0].FailureCount != 1 {
		t.Fatal("fresh evidence did not restart")
	}
}
func TestInconsistentProofCannotBeStored(t *testing.T) {
	s, in := fixture()
	enable(t, s, in)
	now := generation(&in, 2, 0, 0)
	eval(t, s, in, now)
	s.Progress[0].FailureFirst.Generation.Sequence = "1"
	if _, e := Encode(s); e == nil {
		t.Fatal("inconsistent single-sample proof accepted")
	}
	s, in = fixture()
	enable(t, s, in)
	for seq := 2; seq <= 3; seq++ {
		now = generation(&in, seq, 0, 0)
		eval(t, s, in, now)
	}
	later := s.ClockFloor.Add(time.Second)
	s.Policy.EnabledAt = &later
	s.ClockFloor = later
	if _, e := Encode(s); e == nil {
		t.Fatal("pre-policy opening accepted")
	}
}

func TestSequenceGapsBreakFailureAndRecoveryStreaks(t *testing.T) {
	s, in := fixture()
	enable(t, s, in)
	now := generation(&in, 2, 0, 0)
	eval(t, s, in, now)
	now = generation(&in, 4, 0, 0)
	eval(t, s, in, now)
	if len(s.Incidents) != 0 || s.Progress[0].FailureCount != 1 {
		t.Fatal("unseen source attempt bridged failure streak")
	}
	now = generation(&in, 5, 0, 0)
	eval(t, s, in, now)
	if len(s.Incidents) != 1 {
		t.Fatal("consecutive failures did not open")
	}
	now = generation(&in, 6, 1, 0)
	eval(t, s, in, now)
	now = generation(&in, 8, 1, 0)
	eval(t, s, in, now)
	if s.Incidents[0].State != "open" || s.Progress[0].SuccessCount != 1 {
		t.Fatal("unseen source attempt bridged recovery streak")
	}
	now = generation(&in, 9, 1, 0)
	eval(t, s, in, now)
	if s.Incidents[0].State != "recovered" {
		t.Fatal("consecutive successes did not recover")
	}
	s.Incidents[0].Recovery.First.Generation.Sequence = "7"
	if _, e := Encode(s); e == nil {
		t.Fatal("gapped recovery proof accepted")
	}
}

func TestByteBudgetIncludesRestartBaselineMetadata(t *testing.T) {
	s, in := fixture()
	enable(t, s, in)
	for i, active := range []uint32{0, 0, 1, 1} {
		now := generation(&in, i+2, active, 0)
		eval(t, s, in, now)
	}
	terminal := s.Incidents[0]
	reset(s)
	s.LastRequest = nil
	for len(s.Incidents) < MaxIncidents {
		c := terminal
		c.ID = fmt.Sprintf("processincident_%016x", s.NextID)
		s.NextID++
		s.Incidents = append(s.Incidents, c)
		if stateBytes(s) > MaxBytes {
			s.Incidents = s.Incidents[:len(s.Incidents)-1]
			break
		}
	}
	// Fill remaining legal name bytes so longer fresh timestamp metadata, rather
	// than the row limit, exercises the ledger byte boundary on an early return.
	for i := range s.Incidents {
		room := MaxBytes - 5 - stateBytes(s)
		if room <= 0 {
			break
		}
		if room > 64-len(s.Incidents[i].Name) {
			room = 64 - len(s.Incidents[i].Name)
		}
		s.Incidents[i].Name += strings.Repeat("x", room)
	}
	if stateBytes(s) != MaxBytes-5 {
		t.Fatal("fixture did not reach byte boundary", stateBytes(s))
	}
	roundtrip(t, s)
	in.Epoch = strings.Repeat("f", 32)
	now := generation(&in, 6, 0, 0)
	in.Sample.CaptureStartedAt = in.Sample.CaptureStartedAt.Add(time.Nanosecond)
	in.Sample.CaptureFinishedAt = in.Sample.CaptureFinishedAt.Add(time.Nanosecond)
	in.Sample.ReceivedAt = in.Sample.ReceivedAt.Add(time.Nanosecond)
	eval(t, s, in, now)
	if stateBytes(s) > MaxBytes || s.EarlierOmitted == 0 {
		t.Fatal("restart baseline exceeded bounded storage")
	}
}
