package windowseventwatch

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowseventhealth"
	"strconv"
	"strings"
	"testing"
	"time"
)

var start = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func selector() Selector { return Selector{"Application", "Fixture", 42, 2} }
func source(at time.Time, seq uint64, ids ...uint64) Input {
	rows := []windowseventhealth.Event{}
	for _, id := range ids {
		rows = append(rows, windowseventhealth.Event{RecordID: strconv.FormatUint(id, 10), EventID: 42, Level: 2, Provider: "Fixture", Timestamp: at})
	}
	return Input{Source: windowscontact.Input{DeviceID: "agent_" + strings.Repeat("a", 32), InvitationID: "invite_" + strings.Repeat("b", 32), CertificateHash: strings.Repeat("c", 64), Authorized: true, AuthorityUntil: start.Add(30 * 24 * time.Hour), ReceivedAt: at, Sequence: seq}, Events: &windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("d", 32), GenerationID: "sample_" + strings.Repeat("e", 32), CollectedAt: at, Channels: []windowseventhealth.Channel{{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: uint32(len(rows)), Rows: rows}, {Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}}}}
}
func enabled(t *testing.T) State {
	t.Helper()
	s := New()
	if e := s.SetPolicy(Policy{Enabled: true, Revision: 1, Selectors: []Selector{selector()}, EnabledAt: start, RetentionAcknowledged: true}, start); e != nil {
		t.Fatal(e)
	}
	return s
}
func eval(t *testing.T, s *State, in Input, now time.Time) {
	t.Helper()
	if e := s.Evaluate(in, now); e != nil {
		t.Fatal(e)
	}
}
func matched(t *testing.T) State {
	t.Helper()
	s := enabled(t)
	eval(t, &s, source(start, 1, 10), start)
	eval(t, &s, source(start.Add(time.Second), 2, 11, 10), start.Add(time.Second))
	if len(s.Incidents) != 1 {
		t.Fatal("missing match")
	}
	return s
}
func TestDefaultOffAndExplicitRetention(t *testing.T) {
	s := New()
	eval(t, &s, source(start, 1, 1), start)
	if s.Status != "disabled" || s.DeviceID != "" || len(s.Incidents) != 0 {
		t.Fatal(s)
	}
	p := Policy{Enabled: true, Revision: 1, EnabledAt: start, Selectors: []Selector{selector()}}
	if s.SetPolicy(p, start) == nil {
		t.Fatal("implicit derived retention")
	}
	p.RetentionAcknowledged = true
	p.Selectors = append(p.Selectors, p.Selectors[0])
	if s.SetPolicy(p, start) == nil {
		t.Fatal("duplicate selector")
	}
}
func TestBaselineDedupCountReviewNeverRecovery(t *testing.T) {
	s := enabled(t)
	eval(t, &s, source(start.Add(-time.Second), 1, 10, 9), start)
	if len(s.Incidents) != 0 || !s.Floors[0].Ready {
		t.Fatal("baseline/backfill")
	}
	in := source(start.Add(time.Second), 2, 12, 11, 10)
	eval(t, &s, in, in.Source.ReceivedAt)
	if len(s.Incidents) != 1 || s.Incidents[0].CountLowerBound != 2 {
		t.Fatal(s)
	}
	eval(t, &s, in, start.Add(2*time.Second))
	if s.Incidents[0].CountLowerBound != 2 {
		t.Fatal("duplicate count")
	}
	empty := source(start.Add(3*time.Second), 3)
	eval(t, &s, empty, empty.Source.ReceivedAt)
	if s.Incidents[0].ReviewedAt != nil || s.Status != "matched" {
		t.Fatal("absence recovered incident")
	}
	id := s.Incidents[0].ID
	if e := s.Review(id, start.Add(4*time.Second)); e != nil {
		t.Fatal(e)
	}
	eval(t, &s, source(start.Add(5*time.Second), 4, 12), start.Add(5*time.Second))
	if len(s.Incidents) != 1 {
		t.Fatal("review replay opened")
	}
	eval(t, &s, source(start.Add(6*time.Second), 5, 13), start.Add(6*time.Second))
	if len(s.Incidents) != 2 || s.Incidents[1].ReviewedAt != nil {
		t.Fatal("new record failed")
	}
}
func TestInvalidAndUntrustedEvidencePreservesHistory(t *testing.T) {
	for name, mutate := range map[string]func(*Input){"receipt stale": func(in *Input) { in.Source.ReceivedAt = start.Add(-3 * time.Minute) }, "capture stale": func(in *Input) { in.Events.CollectedAt = start.Add(-3 * time.Minute) }, "future": func(in *Input) { in.Events.CollectedAt = start.Add(time.Hour) }, "authority": func(in *Input) { in.Source.Authorized = false }, "expired": func(in *Input) { in.Source.AuthorityUntil = start }, "identity": func(in *Input) { in.Source.CertificateHash = strings.Repeat("f", 64) }, "sequence rollback": func(in *Input) { in.Source.Sequence = 1 }, "capture reuse": func(in *Input) { in.Events.CollectedAt = start.Add(time.Second) }, "missing": func(in *Input) { in.Events = nil }} {
		t.Run(name, func(t *testing.T) {
			s := matched(t)
			in := source(start.Add(2*time.Second), 3, 12)
			mutate(&in)
			eval(t, &s, in, start.Add(2*time.Second))
			if s.Status != "unknown" || s.Incidents[0].CountLowerBound != 1 || s.Sequence != 2 {
				t.Fatal(s)
			}
		})
	}
}
func TestGrantAndLogRegressionNeedExplicitRearm(t *testing.T) {
	s := matched(t)
	in := source(start.Add(2*time.Second), 3, 2)
	eval(t, &s, in, in.Source.ReceivedAt)
	if !s.RearmRequired || s.Status != "continuity-unknown" || s.Incidents[0].CountLowerBound != 1 {
		t.Fatal(s)
	}
	eval(t, &s, source(start.Add(3*time.Second), 4, 15), start.Add(3*time.Second))
	if s.Incidents[0].CountLowerBound != 1 {
		t.Fatal("silently resumed")
	}
	p := s.Policy
	p.Revision++
	p.EnabledAt = start.Add(4 * time.Second)
	if e := s.SetPolicy(p, p.EnabledAt); e != nil {
		t.Fatal(e)
	}
	eval(t, &s, source(p.EnabledAt, 5, 15), p.EnabledAt)
	if s.Incidents[0].CountLowerBound != 1 {
		t.Fatal("rearm backfilled")
	}
	in = source(start.Add(5*time.Second), 6, 16)
	in.Events.GrantID = strings.Repeat("f", 32)
	eval(t, &s, in, in.Source.ReceivedAt)
	if !s.RearmRequired || len(s.Public(in, in.Source.ReceivedAt).Incidents) != 0 {
		t.Fatal("grant replacement adopted")
	}
}
func TestPartialAndDeniedNotHealthy(t *testing.T) {
	s := matched(t)
	in := source(start.Add(2*time.Second), 3)
	c := &in.Events.Channels[0]
	c.Quality = "denied"
	c.Complete = false
	c.Reason = "windows_events_access_denied"
	eval(t, &s, in, in.Source.ReceivedAt)
	if s.Status != "unknown" || len(s.Incidents) != 1 || s.Incidents[0].ReviewedAt != nil {
		t.Fatal(s)
	}
	eval(t, &s, in, start.Add(3*time.Second))
	if s.Status != "unknown" {
		t.Fatal("duplicate made unknown healthy")
	}
	in = source(start.Add(4*time.Second), 4, 12)
	c = &in.Events.Channels[0]
	c.Quality = "partial"
	c.Complete = false
	c.Reason = "windows_events_read_failed"
	eval(t, &s, in, in.Source.ReceivedAt)
	if s.Status != "unknown" || s.Incidents[0].CountLowerBound != 2 {
		t.Fatal("positive partial lost or marked healthy")
	}
}
func TestDisableHiddenGrantAndIndependentHardRetention(t *testing.T) {
	s := matched(t)
	if e := s.SetPolicy(Policy{Revision: 2, Selectors: []Selector{}}, start.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	if s.Policy.Enabled || len(s.Policy.Selectors) != 0 || s.Policy.RetentionAcknowledged || s.GrantID == "" || s.Floors[0].Ready {
		t.Fatal(s)
	}
	in := source(start.Add(2*time.Second), 3, 11)
	v := s.Public(in, in.Source.ReceivedAt)
	if len(v.Incidents) != 1 || v.Status != "disabled" {
		t.Fatal(v)
	}
	in.Events.GrantID = strings.Repeat("f", 32)
	if len(s.Public(in, in.Source.ReceivedAt).Incidents) != 0 {
		t.Fatal("disabled grant history leaked")
	}
	in = source(start.Add(Retention+time.Minute), 4, 11)
	if len(s.Public(in, in.Source.ReceivedAt).Incidents) != 0 {
		t.Fatal("expired open retained in view")
	}
	if e := s.Cleanup(in.Source.ReceivedAt); e != nil {
		t.Fatal(e)
	}
	if len(s.Incidents) != 0 {
		t.Fatal("source independent prune failed")
	}
}
func TestStrictDurableCodec(t *testing.T) {
	s := matched(t)
	b, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append([]byte(" "), b...), []byte(strings.Replace(string(b), `"version":1`, `"version":1,"version":1`, 1)), []byte(strings.Replace(string(b), `"version":1`, `"version":1,"raw":"private"`, 1)), bytes.Repeat([]byte("x"), MaxStateBytes+1)} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("noncanonical input accepted")
		}
	}
	for name, change := range map[string]func(*State){"duplicate open": func(s *State) {
		x := s.Incidents[0]
		s.NextID++
		x.ID = "wevent_0000000000000002"
		s.Incidents = append(s.Incidents, x)
	}, "bad floor": func(s *State) { s.Floors[0].RecordID = "0011" }, "missing captured": func(s *State) { s.CapturedAt = nil }, "unacknowledged": func(s *State) { s.Policy.RetentionAcknowledged = false }, "private selector": func(s *State) { s.Policy.Selectors[0].Provider = "bad\n" }, "bad count": func(s *State) { s.Incidents[0].CountLowerBound = MaxCounter + 1 }} {
		t.Run(name, func(t *testing.T) {
			copy, _ := Decode(b)
			change(&copy)
			if _, e := Encode(copy); e == nil {
				t.Fatal("bad state accepted")
			}
		})
	}
	history, _ := json.Marshal(s.Incidents)
	for _, word := range []string{"recordId", "timestamp", "message", "generationId"} {
		if bytes.Contains(history, []byte(word)) {
			t.Fatal("raw data in incident", word)
		}
	}
}
func TestSourceTokenAndFresh(t *testing.T) {
	in := source(start, 1, 1)
	a := SourceToken(in)
	in.Events.CollectedAt = start.Add(time.Second)
	in.Source.Sequence++
	if SourceToken(in) != a {
		t.Fatal("token depends on observation")
	}
	in.Events.GrantID = strings.Repeat("f", 32)
	if SourceToken(in) == a {
		t.Fatal("grant not bound")
	}
	in = source(start, 1, 1)
	if !Fresh(in, start) {
		t.Fatal("fresh rejected")
	}
	in.Events.CollectedAt = start.Add(-3 * time.Minute)
	if Fresh(in, start) {
		t.Fatal("capture laundered")
	}
}
func TestHistoryBoundFailsClosedAndCountSaturates(t *testing.T) {
	s := matched(t)
	s.Incidents[0].CountLowerBound = MaxCounter
	eval(t, &s, source(start.Add(2*time.Second), 3, 12), start.Add(2*time.Second))
	if s.Incidents[0].CountLowerBound != MaxCounter {
		t.Fatal("overflow")
	}
	for n := 1; n < MaxIncidents; n++ {
		at := start.Add(time.Duration(n+2) * time.Second)
		if e := s.Review(s.Incidents[len(s.Incidents)-1].ID, at); e != nil {
			t.Fatal(e)
		}
		eval(t, &s, source(at.Add(time.Millisecond), uint64(n+3), uint64(n+12)), at.Add(time.Millisecond))
	}
	at := start.Add(110 * time.Second)
	if e := s.Review(s.Incidents[len(s.Incidents)-1].ID, at); e != nil {
		t.Fatal(e)
	}
	eval(t, &s, source(at.Add(time.Second), 999, 999), at.Add(time.Second))
	if len(s.Incidents) != MaxIncidents || s.Status != "history-full" || !s.RearmRequired {
		t.Fatal(s.Status, len(s.Incidents))
	}
}

func TestUint64RecordFloorsExactAndSelectorIsolation(t *testing.T) {
	s := enabled(t)
	base := ^uint64(0) - 2
	eval(t, &s, source(start, 1, base), start)
	in := source(start.Add(time.Second), 2, base+1, base+2)
	in.Events.Channels[0].Rows[0].Provider = "Other"
	eval(t, &s, in, in.Source.ReceivedAt)
	if s.Floors[0].RecordID != "18446744073709551615" || len(s.Incidents) != 1 || s.Incidents[0].CountLowerBound != 1 {
		t.Fatal("precision loss or selector mismatch", s)
	}
	eval(t, &s, source(start.Add(2*time.Second), 3, base+2), start.Add(2*time.Second))
	if s.Incidents[0].CountLowerBound != 1 {
		t.Fatal("max record counted twice")
	}
}
func TestFailedMutationIsAtomicAndViewsDoNotAlias(t *testing.T) {
	s := matched(t)
	before, _ := Encode(s)
	bad := source(start.Add(2*time.Second), 3, 12)
	bad.Events.Channels[0].Rows[0].RecordID = "012"
	if s.Evaluate(bad, bad.Source.ReceivedAt) == nil {
		t.Fatal("invalid source accepted")
	}
	after, _ := Encode(s)
	if !bytes.Equal(before, after) {
		t.Fatal("failed mutation changed state")
	}
	p := s.Policy
	p.Revision = 1
	if s.SetPolicy(p, start.Add(2*time.Second)) == nil {
		t.Fatal("revision replay")
	}
	if e := s.Review(s.Incidents[0].ID, start.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	in := source(start.Add(2*time.Second), 3, 12)
	v := s.Public(in, in.Source.ReceivedAt)
	v.Policy.Selectors[0].Provider = "Altered"
	*v.Incidents[0].ReviewedAt = start.Add(time.Hour)
	if s.Policy.Selectors[0].Provider != "Fixture" || s.Incidents[0].ReviewedAt.Equal(start.Add(time.Hour)) {
		t.Fatal("view aliases private state")
	}
	for _, change := range []func(*Input){func(in *Input) { in.Source.Authorized = false }, func(in *Input) { in.Source.DeviceID = "agent_" + strings.Repeat("f", 32) }, func(in *Input) { in.Events = nil }} {
		in := source(start.Add(2*time.Second), 3, 12)
		change(&in)
		v := s.Public(in, start.Add(2*time.Second))
		if len(v.Incidents) > 0 || len(v.Policy.Selectors) > 0 {
			t.Fatal("private view leaked")
		}
	}
}
func TestPerChannelBaselineAndReconfigureNoBackfill(t *testing.T) {
	s := enabled(t)
	in := source(start, 1)
	in.Events.Channels[0].Quality = "unavailable"
	in.Events.Channels[0].Reason = "windows_events_source_unavailable"
	in.Events.Channels[0].Complete = false
	eval(t, &s, in, start)
	if s.Floors[0].Ready {
		t.Fatal("unknown baselined as zero")
	}
	eval(t, &s, source(start.Add(time.Second), 2, 100), start.Add(time.Second))
	if len(s.Incidents) != 0 {
		t.Fatal("first available sample backfilled")
	}
	p := s.Policy
	p.Revision = 2
	p.EnabledAt = start.Add(2 * time.Second)
	if e := s.SetPolicy(p, p.EnabledAt); e != nil {
		t.Fatal(e)
	}
	eval(t, &s, source(p.EnabledAt, 3, 101), p.EnabledAt)
	if len(s.Incidents) != 0 {
		t.Fatal("policy change backfilled")
	}
	eval(t, &s, source(start.Add(3*time.Second), 4, 102), start.Add(3*time.Second))
	if len(s.Incidents) != 1 {
		t.Fatal("post baseline missed")
	}
}
func TestBoundsAndRetentionBoundary(t *testing.T) {
	s := matched(t)
	at := s.Incidents[0].LastReceivedAt.Add(Retention)
	if e := s.Cleanup(at.Add(-time.Nanosecond)); e != nil || len(s.Incidents) != 1 {
		t.Fatal("boundary pruned", e)
	}
	if e := s.Cleanup(at); e != nil || len(s.Incidents) != 0 {
		t.Fatal("expired retained", e)
	}
	p := Policy{Enabled: true, Revision: 1, EnabledAt: start, RetentionAcknowledged: true, Selectors: []Selector{}}
	for n := 0; n <= MaxSelectors; n++ {
		x := selector()
		x.EventID = uint16(n)
		p.Selectors = append(p.Selectors, x)
	}
	if p.Validate() == nil {
		t.Fatal("too many selectors")
	}
	x := selector()
	x.Channel = "Security"
	if x.Validate() == nil {
		t.Fatal("scope expansion")
	}
}
func FuzzDecode(f *testing.F) {
	s := New()
	b, _ := Encode(s)
	f.Add(b)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, e := Decode(b)
		if e != nil {
			return
		}
		out, e := Encode(s)
		if e != nil || !bytes.Equal(b, out) {
			t.Fatal("noncanonical roundtrip")
		}
	})
}

func TestPublicCannotLaunderEvaluatorFreshness(t *testing.T) {
	s := matched(t)
	same := source(start.Add(time.Second), 2, 11, 10)
	if s.Public(same, same.Source.ReceivedAt).Status != "matched" {
		t.Fatal("matching watermark hidden")
	}
	newer := source(start.Add(2*time.Second), 3, 12)
	if s.Public(newer, newer.Source.ReceivedAt).Status != "unknown" {
		t.Fatal("new source renewed unevaluated state")
	}
	if s.Public(same, start.Add(MaxAge+2*time.Second)).Status != "unknown" {
		t.Fatal("stale evaluator shown current")
	}
}

func TestOlderOrFutureEventAboveBaselineNeverBackfills(t *testing.T) {
	s := enabled(t)
	eval(t, &s, source(start, 1, 10), start)
	in := source(start.Add(time.Second), 2, 11, 12)
	in.Events.Channels[0].Rows[0].Timestamp = start.Add(-time.Hour)
	in.Events.Channels[0].Rows[1].Timestamp = start.Add(time.Hour)
	eval(t, &s, in, in.Source.ReceivedAt)
	if len(s.Incidents) != 0 || s.Floors[0].RecordID != "12" {
		t.Fatal("historical/future event admitted")
	}
	// A later timestamp must not relabel either consumed record as a new match.
	eval(t, &s, source(start.Add(2*time.Second), 3, 11, 12), start.Add(2*time.Second))
	if len(s.Incidents) != 0 {
		t.Fatal("timestamp laundering")
	}
	eval(t, &s, source(start.Add(3*time.Second), 4, 13), start.Add(3*time.Second))
	if len(s.Incidents) != 1 {
		t.Fatal("new post-consent event missing")
	}
}

func TestPublicOriginalCapturePrivateExpiry(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		s := matched(t)
		if disabled {
			if e := s.SetPolicy(Policy{Revision: 2, Selectors: []Selector{}}, start.Add(2*time.Second)); e != nil {
				t.Fatal(e)
			}
		}
		in := source(start.Add(time.Second), 2, 11, 10)
		expiry := in.Events.CollectedAt.Add(24 * time.Hour)
		// A fresh receipt cannot renew the unchanged original capture's authority.
		in.Source.ReceivedAt = expiry.Add(-time.Nanosecond)
		before, _ := Encode(s)
		v := s.Public(in, expiry.Add(-time.Nanosecond))
		if len(v.Incidents) != 1 || !disabled && len(v.Policy.Selectors) != 1 {
			t.Fatal("private view expired early", disabled, v)
		}
		for _, at := range []time.Time{expiry, expiry.Add(time.Nanosecond), in.Events.CollectedAt.Add(-time.Nanosecond)} {
			v = s.Public(in, at)
			if len(v.Incidents) != 0 || len(v.Policy.Selectors) != 0 || v.Policy.Enabled || v.Status != "unknown" {
				t.Fatal("expired or future capture leaked", disabled, at, v)
			}
		}
		after, _ := Encode(s)
		if !bytes.Equal(before, after) {
			t.Fatal("public expiry mutated durable history")
		}
	}
}
