package windowsservicehealth

import (
	"encoding/json"
	"localrmm/internal/windowsfullservices"
	"os"
	"strings"
	"testing"
	"time"
)

func completeInput() Input {
	in := input()
	in.Complete = true
	state, display := "stopped", "Fixture service beyond the preview"
	p := Provenance{Kind: CompleteSourceKind, GrantID: strings.Repeat("a", 32), GrantRevision: 1, ManifestSHA256: strings.Repeat("b", 64), Sequence: 1, CapturedAt: at, CaptureFinishedAt: at, ReceivedAt: at, ExpiresAt: at.Add(24 * time.Hour), RowCount: 2050}
	p.GenerationID, _ = windowsfullservices.GenerationID(in.DeviceID, p.GrantID, p.Sequence)
	in.Sample.Complete = &CompleteSample{Source: p, Rows: []windowsfullservices.Row{{Name: "FixtureService", DisplayName: &display, DisplayNameQuality: "observed", State: &state, StateQuality: "observed", PIDQuality: "unavailable"}}}
	in.Selection = &p
	return in
}
func nextComplete(in Input, seconds int, state string) Input {
	in.Sample.Complete = &CompleteSample{Source: in.Sample.Complete.Source, Rows: append([]windowsfullservices.Row{}, in.Sample.Complete.Rows...)}
	p := &in.Sample.Complete.Source
	p.Sequence++
	p.CapturedAt = p.CapturedAt.Add(time.Duration(seconds) * time.Second)
	p.CaptureFinishedAt = p.CapturedAt
	p.ReceivedAt = p.CapturedAt.Add(3 * time.Second)
	p.ExpiresAt = p.CapturedAt.Add(24 * time.Hour)
	p.GenerationID, _ = windowsfullservices.GenerationID(in.DeviceID, p.GrantID, p.Sequence)
	in.Sample.Complete.Rows[0].State = &state
	in.Selection = p
	return in
}
func TestCompleteSourceIndependentCadenceAndCachedEvidence(t *testing.T) {
	in := completeInput()
	s := NewComplete()
	if err := s.Configure(in, true, []string{"FixtureService"}, 0, at); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= 5; i++ {
		in.Sequence += 500
		in.ReceivedAt = at.Add(time.Duration(i) * 30 * time.Second)
		if err := s.Evaluate(in, in.ReceivedAt, epoch); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.Incidents) != 0 || s.SequenceFloor != 1 || s.Checks[0].Status != "pending" {
		t.Fatal("cached complete data counted as fresh evidence", s)
	}
	in = nextComplete(in, 180, "stopped")
	if err := s.Evaluate(in, at.Add(183*time.Second), epoch); err != nil {
		t.Fatal(err)
	}
	if len(s.Incidents) != 1 || s.Checks[0].Status != "attention" || s.SequenceFloor != 2 || s.SourceFloor.GenerationID != in.Sample.Complete.Source.GenerationID {
		t.Fatal("three-minute source cadence did not confirm", s)
	}
	// Unknown never resolves; new same-grant running captures, not frames, recover.
	gone := in
	gone.Sample.Complete = nil
	if err := s.Evaluate(gone, at.Add(210*time.Second), epoch); err != nil {
		t.Fatal(err)
	}
	if s.Checks[0].Status != "unknown" || s.Incidents[0].ResolvedAt != nil {
		t.Fatal(s)
	}
	in = nextComplete(in, 60, "running")
	if err := s.Evaluate(in, at.Add(243*time.Second), epoch); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := s.Evaluate(in, at.Add(time.Duration(243+30*i)*time.Second), epoch); err != nil {
			t.Fatal(err)
		}
	}
	if s.Incidents[0].ResolvedAt != nil {
		t.Fatal("cached running recovered")
	}
	in = nextComplete(in, 180, "running")
	if err := s.Evaluate(in, at.Add(423*time.Second), epoch); err != nil {
		t.Fatal(err)
	}
	if s.Incidents[0].ClosedReason != "running" {
		t.Fatal(s)
	}
}
func TestCompleteSourceGrantGenerationAndStrictLegacyIsolation(t *testing.T) {
	in := completeInput()
	s := NewComplete()
	if e := s.Configure(in, true, []string{"FixtureService"}, 0, at); e != nil {
		t.Fatal(e)
	}
	if e := s.Evaluate(in, at, epoch); e != nil {
		t.Fatal(e)
	}
	raw, _ := Encode(s)
	alias := in
	alias.Sample.Complete = &CompleteSample{Source: in.Sample.Complete.Source, Rows: in.Sample.Complete.Rows}
	alias.Sample.Complete.Source.ManifestSHA256 = strings.Repeat("c", 64)
	if e := s.Evaluate(alias, at.Add(30*time.Second), epoch); e != nil {
		t.Fatal(e)
	}
	if s.Checks[0].Status != "unknown" {
		t.Fatal("same sequence alias accepted")
	}
	if e := s.Configure(input(), false, []string{}, 1, at.Add(30*time.Second)); e == nil {
		t.Fatal("v1 changed v2 policy")
	}
	old := New()
	legacy := input()
	if e := old.Configure(legacy, true, []string{"FixtureService"}, 0, at); e != nil {
		t.Fatal(e)
	}
	if e := old.Configure(in, true, []string{"FixtureService"}, 1, at); e == nil {
		t.Fatal("legacy used state automatically promoted")
	}
	changed := nextComplete(in, 60, "running")
	changed.Sample.Complete.Source.GrantID = strings.Repeat("d", 32)
	changed.Sample.Complete.Source.GrantRevision = 3
	changed.Sample.Complete.Source.GenerationID, _ = windowsfullservices.GenerationID(in.DeviceID, changed.Sample.Complete.Source.GrantID, changed.Sample.Complete.Source.Sequence)
	if e := s.Evaluate(changed, at.Add(63*time.Second), epoch); e != nil {
		t.Fatal(e)
	}
	if s.Checks[0].Status != "unknown" {
		t.Fatal("new grant inherited policy")
	}
	changed.Selection = nil
	changed.Sample.Complete.Rows = append(changed.Sample.Complete.Rows, windowsfullservices.Row{Name: "NewService", DisplayNameQuality: "unavailable", StateQuality: "unavailable", PIDQuality: "unavailable"})
	if e := s.Configure(changed, true, []string{"FixtureService", "NewService"}, 1, at.Add(63*time.Second)); e == nil {
		t.Fatal("selection without explicit provenance")
	}
	if decoded, e := Decode(raw); e != nil || decoded.SchemaVersion != CompleteStateSchema {
		t.Fatal(e)
	}
}
func TestCompleteSourceLongIdentityUnavailableAndOriginalExpiry(t *testing.T) {
	in := completeInput()
	name := strings.Repeat("界", 256)
	in.Sample.Complete.Rows[0].Name = name
	in.Sample.Complete.Rows[0].State = nil
	in.Sample.Complete.Rows[0].StateQuality = "unavailable"
	s := NewComplete()
	if e := s.Configure(in, true, []string{name}, 0, at); e != nil {
		t.Fatal(e)
	}
	if e := s.Evaluate(in, at, epoch); e != nil {
		t.Fatal(e)
	}
	if s.Checks[0].Status != "unknown" {
		t.Fatal(s)
	}
	if in.Inventory(at.Add(301*time.Second)) != nil {
		t.Fatal("stale generation in chooser")
	}
	if _, e := Services([]string{name}); e == nil {
		t.Fatal("legacy name bound widened")
	}
}
func TestCompleteServiceHealthSharedFixture(t *testing.T) {
	in := completeInput()
	s := NewComplete()
	disabled := s.View(in, at, epoch)
	if e := s.Configure(in, true, []string{"FixtureService"}, 0, at); e != nil {
		t.Fatal(e)
	}
	for i := 0; i <= 5; i++ {
		if e := s.Evaluate(in, at.Add(time.Duration(i)*30*time.Second), epoch); e != nil {
			t.Fatal(e)
		}
	}
	in = nextComplete(in, 180, "stopped")
	now := at.Add(183 * time.Second)
	if e := s.Evaluate(in, now, epoch); e != nil {
		t.Fatal(e)
	}
	attention := s.View(in, now, epoch)
	fixture := map[string]any{"disabled": disabled, "attention": attention, "source": in.Sample.Complete.Source}
	raw, e := json.MarshalIndent(fixture, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if os.Getenv("TRACEBOLT_WRITE_COMPLETE_SERVICE_FIXTURE") == "1" {
		if e := os.WriteFile("../../web/src/windows-complete-service-health-go-fixture.json", append(raw, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
}

func TestCompleteSourceHistoryByteBoundPreservesOpenAndFloors(t *testing.T) {
	in := completeInput()
	in.AuthorityUntil = at.Add(24 * time.Hour)
	name := strings.Repeat("&", 256)
	in.Sample.Complete.Rows[0].Name = name
	s := NewComplete()
	if e := s.Configure(in, true, []string{name}, 0, at); e != nil {
		t.Fatal(e)
	}
	current := at
	tick := func(state string) {
		in = nextComplete(in, 60, state)
		current = in.Sample.Complete.Source.ReceivedAt
		if e := s.Evaluate(in, current, epoch); e != nil {
			t.Fatal(e)
		}
	}
	// Bounded history pressure, not a performance test. Each observation is a new
	// independent generation; ongoing manager evaluations never have a >90s gap.
	for i := 0; i < 105; i++ {
		for n := 0; n < 3; n++ {
			tick("stopped")
		}
		for n := 0; n < 2; n++ {
			tick("running")
		}
	}
	if len(s.Incidents) > MaxIncidents || s.NextID != 105 {
		t.Fatal(len(s.Incidents), s.NextID)
	}
	for n := 0; n < 3; n++ {
		tick("stopped")
	}
	raw, e := Encode(s)
	if e != nil || len(raw) > MaxStateBytes || s.open(name) == nil || s.SourceFloor.Sequence != in.Sample.Complete.Source.Sequence {
		t.Fatal("bounded retention lost active state/floor", len(raw), e)
	}
}
