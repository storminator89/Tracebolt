package applicationcheck

import (
	"reflect"
	"testing"
	"time"
)

func TestIncidentLifecycleAndRestart(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	source := IncidentSource{Key: "1111111111111111111111111111111111111111111111111111111111111111", Token: "appsource_11111111111111111111111111111111", Enabled: true, Mode: "managed", IntervalSeconds: 60, MaxAgeSeconds: 70, Targets: []IncidentTarget{{ID: "db", Kind: "tcp"}}}
	s := NewIncidentState()
	c := IncidentCommand{RequestID: "apprequest_11111111111111111111111111111111", Operation: "enable", SourceToken: "appsource_11111111111111111111111111111111", TargetIDs: []string{"db"}, ConsecutiveFailures: 2, RetentionAcknowledged: true}
	if e := s.Apply(c, source, now); e != nil {
		t.Fatal(e)
	}
	feed := func(second int, state, reason string) {
		t.Helper()
		r := IncidentObservation{TargetID: "db", Kind: "tcp", State: state, Reason: reason, ObservedAt: now.Add(time.Duration(second) * time.Second), CompletedAt: now.Add(time.Duration(second+1) * time.Second)}
		if e := s.Observe(source, r, r.CompletedAt); e != nil {
			t.Fatal(e)
		}
	}
	feed(2, "network_error", "tcp_failed")
	feed(4, "network_error", "tcp_failed")
	if len(s.Records) != 1 || s.Records[0].State != "open" {
		t.Fatal(s.Records)
	}
	source.Token = "appsource_22222222222222222222222222222222"
	if e := s.Synchronize(source, now.Add(6*time.Second)); e != nil {
		t.Fatal(e)
	}
	if !s.Policy.Enabled || len(s.Progress) != 0 || s.Records[0].State != "open" {
		t.Fatal("restart lost approval or case")
	}
	feed(8, "ok", "tcp_connected")
	feed(10, "unknown", "destination_blocked")
	feed(12, "ok", "tcp_connected")
	if s.Records[0].State != "open" {
		t.Fatal("unknown recovered")
	}
	feed(14, "ok", "tcp_connected")
	if s.Records[0].State != "recovered" {
		t.Fatal("not recovered")
	}
	old := s.copy()
	c.RequestID = "apprequest_33333333333333333333333333333333"
	c.ExpectedRevision = 0
	if s.Apply(c, source, now) == nil || !reflect.DeepEqual(old, s) {
		t.Fatal("failed mutation changed state")
	}
}
func TestIncidentConcurrentClockAndRollback(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	src := IncidentSource{Key: "1111111111111111111111111111111111111111111111111111111111111111", Token: "appsource_11111111111111111111111111111111", Enabled: true, Mode: "managed", IntervalSeconds: 60, MaxAgeSeconds: 70, Targets: []IncidentTarget{{ID: "db", Kind: "tcp"}}}
	s := NewIncidentState()
	c := IncidentCommand{RequestID: "apprequest_22222222222222222222222222222222", Operation: "enable", SourceToken: "appsource_11111111111111111111111111111111", TargetIDs: []string{"db"}, ConsecutiveFailures: 2, RetentionAcknowledged: true}
	if e := s.Apply(c, src, now); e != nil {
		t.Fatal(e)
	}
	if e := s.Synchronize(src, now.Add(20*time.Second)); e != nil {
		t.Fatal(e)
	}
	r := IncidentObservation{TargetID: "db", Kind: "tcp", State: "network_error", Reason: "tcp_failed", ObservedAt: now.Add(time.Second), CompletedAt: now.Add(2 * time.Second)}
	if e := s.Observe(src, r, now.Add(21*time.Second)); e != nil {
		t.Fatal(e)
	}
	if s.Progress["db"].Check.FailureCount != 1 {
		t.Fatal("valid queued result rejected")
	}
	if e := s.Observe(src, r, now.Add(22*time.Second)); e != nil {
		t.Fatal(e)
	}
	if s.Progress["db"].Check.FailureCount != 0 {
		t.Fatal("duplicate earned progress")
	}
	if e := s.Synchronize(src, now); e != nil {
		t.Fatal(e)
	}
	v := s.View(src, now, false)
	if v.ClockReliable || len(v.Checks) != 1 || v.Checks[0].ObservedAt != nil {
		t.Fatal("rollback exposed current checks")
	}
}

func TestIncidentControlRevisionBindingAndFreshness(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	src := IncidentSource{Key: "1111111111111111111111111111111111111111111111111111111111111111", Token: "appsource_11111111111111111111111111111111", Mode: "managed", Enabled: true, IntervalSeconds: 60, MaxAgeSeconds: 70, Targets: []IncidentTarget{{ID: "db", Kind: "tcp"}}}
	s := NewIncidentState()
	c := IncidentCommand{RequestID: "apprequest_11111111111111111111111111111111", Operation: "enable", SourceToken: src.Token, TargetIDs: []string{"db"}, ConsecutiveFailures: 2, RetentionAcknowledged: true}
	if e := s.Synchronize(src, now); e != nil || s.Revision != 0 {
		t.Fatal(e, s.Revision)
	}
	if e := s.Apply(c, src, now); e != nil || s.Revision != 1 {
		t.Fatal(e, s.Revision)
	}
	if e := s.Apply(c, src, now.Add(time.Second)); e != nil || s.Revision != 1 || !s.Policy.EnabledAt.Equal(now) {
		t.Fatal("retry slid approval", e)
	}
	r := IncidentObservation{TargetID: "db", Kind: "tcp", State: "network_error", Reason: "tcp_failed", ObservedAt: now.Add(2 * time.Second), CompletedAt: now.Add(7 * time.Second)}
	if e := s.Observe(src, r, now.Add(73*time.Second)); e != nil || s.Progress["db"].Check.FailureCount != 0 || s.Revision != 1 {
		t.Fatal("stale original start counted", e)
	}
	src.Token = "appsource_22222222222222222222222222222222"
	if s.Apply(c, src, now.Add(74*time.Second)) == nil {
		t.Fatal("stale runtime retry accepted")
	}
	src.Key = "2222222222222222222222222222222222222222222222222222222222222222"
	if e := s.Synchronize(src, now.Add(75*time.Second)); e != nil {
		t.Fatal(e)
	}
	if s.Policy.Enabled || s.PolicyKey != "" || s.View(src, now.Add(75*time.Second), true).Policy.SourceMatches || s.Revision != 1 {
		t.Fatal("source retirement binding")
	}
	for _, mutate := range []func(*IncidentState){func(x *IncidentState) { x.NextID = 0 }, func(x *IncidentState) { x.SourceToken = "bad" }, func(x *IncidentState) { x.Revision++ }, func(x *IncidentState) { x.PolicyKey = src.Key }, func(x *IncidentState) { x.Progress["alien"] = incidentProgress{} }} {
		n := s.copy()
		mutate(&n)
		if n.Validate() == nil {
			t.Fatal("corrupt state accepted")
		}
	}
	bad := src
	bad.MaxAgeSeconds++
	if s.Synchronize(bad, now.Add(76*time.Second)) == nil {
		t.Fatal("bad source accepted")
	}
}
