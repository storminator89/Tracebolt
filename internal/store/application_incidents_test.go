package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/applicationcheck"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var applicationIncidentEpoch = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func applicationIncidentFixture(t *testing.T) (*Store, string, applicationcheck.IncidentSource, *atomic.Int64) {
	t.Helper()
	s, path := alarmStore(t)
	var clock atomic.Int64
	clock.Store(applicationIncidentEpoch.UnixNano())
	src := applicationcheck.IncidentSource{Key: strings.Repeat("a", 64), Token: "appsource_" + strings.Repeat("1", 32), Mode: "managed", Enabled: true, IntervalSeconds: 60, MaxAgeSeconds: 70, Targets: []applicationcheck.IncidentTarget{{ID: "fixture", Kind: "tcp"}}, Now: func() time.Time { return time.Unix(0, clock.Load()).UTC() }}
	return s, path, src, &clock
}
func applicationIncidentCommand(n int, revision uint64, src applicationcheck.IncidentSource, op string) applicationcheck.IncidentCommand {
	c := applicationcheck.IncidentCommand{RequestID: fmt.Sprintf("apprequest_%032x", n), ExpectedRevision: revision, Operation: op, SourceToken: src.Token, TargetIDs: []string{}}
	if op == "enable" {
		c.TargetIDs = []string{"fixture"}
		c.ConsecutiveFailures = 2
		c.RetentionAcknowledged = true
	}
	return c
}
func applicationIncidentEnable(t *testing.T, s *Store, src applicationcheck.IncidentSource) applicationcheck.IncidentView {
	t.Helper()
	v, e := s.ChangeApplicationIncidents(context.Background(), src, applicationIncidentCommand(1, 0, src, "enable"), func() bool { return true }, true)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func applicationIncidentRead(t *testing.T, s *Store, src applicationcheck.IncidentSource) applicationcheck.IncidentView {
	t.Helper()
	v, e := s.ApplicationIncidents(context.Background(), src, false)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func applicationIncidentFeed(t *testing.T, s *Store, src applicationcheck.IncidentSource, clock *atomic.Int64, sec int, state, reason string) {
	t.Helper()
	start := applicationIncidentEpoch.Add(time.Duration(sec) * time.Second)
	end := start.Add(time.Second)
	clock.Store(end.UnixNano())
	e := s.ObserveApplicationResult(context.Background(), src, applicationcheck.IncidentObservation{TargetID: "fixture", Kind: "tcp", State: state, Reason: reason, ObservedAt: start, CompletedAt: end})
	if e != nil {
		t.Fatal(e)
	}
}
func applicationIncidentRaw(t *testing.T, s *Store) []byte {
	t.Helper()
	var raw []byte
	if e := s.db.QueryRow(`SELECT body FROM application_incidents WHERE id=1`).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	return raw
}
func applicationIncidentWaiter(t *testing.T, s *Store, before int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for s.db.Stats().WaitCount <= before {
		if time.Now().After(deadline) {
			t.Fatal("local fixture did not queue on sole DB connection")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestApplicationIncidentStoreDefaultReadsAndResultsStayInert(t *testing.T) {
	s, _, src, clock := applicationIncidentFixture(t)
	if e := s.ObserveApplicationSource(context.Background(), src); e != nil {
		t.Fatal(e)
	}
	applicationIncidentFeed(t, s, src, clock, 1, "network_error", "tcp_failed")
	v := applicationIncidentRead(t, s, src)
	if v.Policy.Enabled || v.Revision != 0 || v.CanManage || len(v.Checks) != 0 || len(v.Incidents) != 0 || v.LastRequest != nil {
		t.Fatal("default state was promoted", v)
	}
	var count int
	if e := s.db.QueryRow(`SELECT count(*) FROM application_incidents`).Scan(&count); e != nil || count != 0 {
		t.Fatal("inert read/results created retention", count, e)
	}
}
func TestApplicationIncidentStoreRestartResetsProgressKeepsOpenAndApproval(t *testing.T) {
	s, path, src, clock := applicationIncidentFixture(t)
	applicationIncidentEnable(t, s, src)
	applicationIncidentFeed(t, s, src, clock, 1, "network_error", "tcp_failed")
	applicationIncidentFeed(t, s, src, clock, 3, "network_error", "tcp_failed")
	v := applicationIncidentRead(t, s, src)
	if len(v.Incidents) != 1 || v.Incidents[0].State != "open" || v.Revision != 1 {
		t.Fatal("opening/revision", v)
	}
	original := v.Incidents[0]
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	src.Token = "appsource_" + strings.Repeat("2", 32)
	clock.Store(applicationIncidentEpoch.Add(6 * time.Second).UnixNano())
	if e = reopened.ObserveApplicationSource(context.Background(), src); e != nil {
		t.Fatal(e)
	}
	v = applicationIncidentRead(t, reopened, src)
	if !v.Policy.Enabled || len(v.Checks) != 1 || v.Checks[0].Condition != "unknown" || v.Checks[0].ObservedAt != nil || len(v.Incidents) != 1 || v.Incidents[0].ID != original.ID || v.Incidents[0].State != "open" || !v.Incidents[0].Opening.CompletedAt.Equal(original.Opening.CompletedAt) {
		t.Fatal("restart changed evidence or reused counters", v)
	}
	old := applicationIncidentCommand(1, 0, src, "enable")
	old.SourceToken = "appsource_" + strings.Repeat("1", 32)
	if _, e = reopened.ChangeApplicationIncidents(context.Background(), src, old, func() bool { return true }, true); !errors.Is(e, applicationcheck.ErrIncidentInvalid) {
		t.Fatal("old runtime request admitted", e)
	}
	applicationIncidentFeed(t, reopened, src, clock, 8, "ok", "tcp_connected")
	applicationIncidentFeed(t, reopened, src, clock, 10, "unknown", "destination_blocked")
	applicationIncidentFeed(t, reopened, src, clock, 12, "ok", "tcp_connected")
	if v = applicationIncidentRead(t, reopened, src); v.Incidents[0].State != "open" {
		t.Fatal("unknown or one sample recovered", v)
	}
	applicationIncidentFeed(t, reopened, src, clock, 14, "ok", "tcp_connected")
	if v = applicationIncidentRead(t, reopened, src); v.Incidents[0].State != "recovered" || v.Incidents[0].Recovery == nil || v.Incidents[0].Recovery.Samples != 2 || v.Revision != 1 {
		t.Fatal("sampled recovery missing", v)
	}
}
func TestApplicationIncidentStoreReplacementDoesNotAdoptSameTargetID(t *testing.T) {
	s, _, src, clock := applicationIncidentFixture(t)
	applicationIncidentEnable(t, s, src)
	applicationIncidentFeed(t, s, src, clock, 1, "network_error", "tcp_failed")
	applicationIncidentFeed(t, s, src, clock, 3, "network_error", "tcp_failed")
	old := applicationIncidentRead(t, s, src).Incidents[0]
	src.Key = strings.Repeat("b", 64)
	src.Token = "appsource_" + strings.Repeat("2", 32)
	clock.Store(applicationIncidentEpoch.Add(6 * time.Second).UnixNano())
	if e := s.ObserveApplicationSource(context.Background(), src); e != nil {
		t.Fatal(e)
	}
	applicationIncidentFeed(t, s, src, clock, 8, "ok", "tcp_connected")
	v := applicationIncidentRead(t, s, src)
	if v.Policy.Enabled || v.Policy.SourceMatches || len(v.Checks) != 0 || len(v.Incidents) != 1 || v.Incidents[0].SourceCurrent || v.Incidents[0].State != "monitoring_stopped" || v.Incidents[0].Recovery != nil || v.Incidents[0].ID != old.ID {
		t.Fatal("replacement adopted or recovered old source", v)
	}
	c := applicationIncidentCommand(2, v.Revision, src, "enable")
	if _, e := s.ChangeApplicationIncidents(context.Background(), src, c, func() bool { return true }, true); e != nil {
		t.Fatal(e)
	}
	applicationIncidentFeed(t, s, src, clock, 10, "network_error", "tcp_failed")
	applicationIncidentFeed(t, s, src, clock, 12, "network_error", "tcp_failed")
	v = applicationIncidentRead(t, s, src)
	if len(v.Incidents) != 2 || v.Incidents[0].ID == old.ID || !v.Incidents[0].SourceCurrent || v.Incidents[1].SourceCurrent {
		t.Fatal("source occurrence collapsed", v)
	}
}
func TestApplicationIncidentStoreExactCASReplayAndSessionRollback(t *testing.T) {
	s, _, src, clock := applicationIncidentFixture(t)
	applicationIncidentEnable(t, s, src)
	applicationIncidentFeed(t, s, src, clock, 1, "network_error", "tcp_failed")
	applicationIncidentFeed(t, s, src, clock, 3, "network_error", "tcp_failed")
	replay := applicationIncidentCommand(1, 0, src, "enable")
	if v, e := s.ChangeApplicationIncidents(context.Background(), src, replay, func() bool { return true }, true); e != nil || v.Revision != 1 || v.Incidents[0].State != "open" {
		t.Fatal("exact replay recreated policy", v, e)
	}
	c := applicationIncidentCommand(2, 1, src, "disable")
	raw := string(applicationIncidentRaw(t, s))
	clock.Store(applicationIncidentEpoch.Add(5 * time.Second).UnixNano())
	calls := 0
	if _, e := s.ChangeApplicationIncidents(context.Background(), src, c, func() bool { calls++; return calls < 3 }, true); !errors.Is(e, ErrApplicationIncidentSession) {
		t.Fatal("ended session accepted", e, calls)
	}
	if got := string(applicationIncidentRaw(t, s)); got != raw {
		t.Fatal("uncommitted state escaped ended session")
	}
	if s.applicationIncidentBlocked.Load() {
		t.Fatal("known session rollback fenced component")
	}
	v, e := s.ChangeApplicationIncidents(context.Background(), src, c, func() bool { return true }, true)
	if e != nil || v.Revision != 2 || v.Policy.Enabled || v.Incidents[0].State != "monitoring_stopped" {
		t.Fatal("valid retry after known rollback failed", v, e)
	}
	stale := applicationIncidentCommand(3, 1, src, "enable")
	if _, e = s.ChangeApplicationIncidents(context.Background(), src, stale, func() bool { return true }, true); !errors.Is(e, applicationcheck.ErrIncidentInvalid) {
		t.Fatal("stale revision admitted", e)
	}
}
func TestApplicationIncidentStoreClockSamplesAfterQueuedDBAdmission(t *testing.T) {
	s, _, src, clock := applicationIncidentFixture(t)
	applicationIncidentEnable(t, s, src)
	applicationIncidentFeed(t, s, src, clock, 1, "network_error", "tcp_failed")
	conn, e := s.db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	before := s.db.Stats().WaitCount
	out := make(chan error, 1)
	go func() { _, e := s.ApplicationIncidents(context.Background(), src, false); out <- e }()
	applicationIncidentWaiter(t, s, before)
	clock.Store(applicationIncidentEpoch.Add(30 * time.Second).UnixNano())
	if e = conn.Close(); e != nil {
		t.Fatal(e)
	}
	if e = <-out; e != nil {
		t.Fatal(e)
	}
	var state applicationcheck.IncidentState
	if e = json.Unmarshal(applicationIncidentRaw(t, s), &state); e != nil || !state.Floor.Equal(applicationIncidentEpoch.Add(30*time.Second)) {
		t.Fatal("pre-admission clock used", state.Floor, e)
	}
	v := applicationIncidentRead(t, s, src)
	if !v.ClockReliable || v.Checks[0].FailureCount != 1 || !v.ServerNow.Equal(state.Floor) {
		t.Fatal("queued valid progress treated as rollback", v)
	}
}
func TestApplicationIncidentStoreCancelledQueuedReadDoesNotFence(t *testing.T) {
	s, _, src, _ := applicationIncidentFixture(t)
	applicationIncidentEnable(t, s, src)
	raw := string(applicationIncidentRaw(t, s))
	conn, e := s.db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	before := s.db.Stats().WaitCount
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan error, 1)
	go func() { _, e := s.ApplicationIncidents(ctx, src, false); out <- e }()
	applicationIncidentWaiter(t, s, before)
	cancel()
	e = <-out
	if e == nil {
		t.Fatal("cancelled read succeeded")
	}
	if e = conn.Close(); e != nil {
		t.Fatal(e)
	}
	if s.applicationIncidentBlocked.Load() {
		t.Fatal("known pre-write cancellation fenced component")
	}
	if string(applicationIncidentRaw(t, s)) != raw {
		t.Fatal("cancelled queued read wrote state")
	}
	_ = applicationIncidentRead(t, s, src)
}
func TestApplicationIncidentStoreCorruptionStaysBlockedUntilReopen(t *testing.T) {
	for name, change := range map[string]func(string) string{
		"unknown": func(s string) string {
			return strings.Replace(s, `"Version":1`, `"Version":1,"Unexpected":"private text"`, 1)
		},
		"duplicate":    func(s string) string { return strings.Replace(s, `"Version":1`, `"Version":1,"Version":1`, 1) },
		"alias":        func(s string) string { return strings.Replace(s, `"Version":1`, `"version":1`, 1) },
		"null-records": func(s string) string { return strings.Replace(s, `"Records":[]`, `"Records":null`, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			s, path, src, _ := applicationIncidentFixture(t)
			applicationIncidentEnable(t, s, src)
			good := string(applicationIncidentRaw(t, s))
			bad := change(good)
			if bad == good {
				t.Fatal("corruption fixture unchanged")
			}
			if _, e := s.db.Exec(`UPDATE application_incidents SET body=? WHERE id=1`, bad); e != nil {
				t.Fatal(e)
			}
			if _, e := s.ApplicationIncidents(context.Background(), src, false); !errors.Is(e, applicationcheck.ErrIncidentUnavailable) || !s.applicationIncidentBlocked.Load() {
				t.Fatal("corrupt state returned", e)
			}
			if _, e := s.db.Exec(`UPDATE application_incidents SET body=? WHERE id=1`, good); e != nil {
				t.Fatal(e)
			}
			if _, e := s.ApplicationIncidents(context.Background(), src, false); !errors.Is(e, applicationcheck.ErrIncidentUnavailable) {
				t.Fatal("same instance silently unfenced", e)
			}
			if e := s.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			if v := applicationIncidentRead(t, reopened, src); !v.Policy.Enabled || v.Revision != 1 {
				t.Fatal("verified reopen lost approval", v)
			}
		})
	}
}
func TestApplicationIncidentStoreWriteFailureRollsBackAndFencesOnlyIncidents(t *testing.T) {
	s, path, src, clock := applicationIncidentFixture(t)
	applicationIncidentEnable(t, s, src)
	good := string(applicationIncidentRaw(t, s))
	if _, e := s.db.Exec(`CREATE TRIGGER fail_application_incidents BEFORE UPDATE ON application_incidents BEGIN SELECT RAISE(ABORT,'synthetic failure'); END`); e != nil {
		t.Fatal(e)
	}
	clock.Store(applicationIncidentEpoch.Add(time.Second).UnixNano())
	if _, e := s.ApplicationIncidents(context.Background(), src, false); !errors.Is(e, applicationcheck.ErrIncidentUnavailable) {
		t.Fatal("storage error hidden", e)
	}
	if got := string(applicationIncidentRaw(t, s)); got != good {
		t.Fatal("failed write partially committed")
	}
	if _, e := s.db.Exec(`DROP TRIGGER fail_application_incidents`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ApplicationIncidents(context.Background(), src, false); !errors.Is(e, applicationcheck.ErrIncidentUnavailable) {
		t.Fatal("storage fence silently retried", e)
	}
	var n int
	if e := s.db.QueryRow(`SELECT count(*) FROM devices`).Scan(&n); e != nil {
		t.Fatal("incident failure broke unrelated store", e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if v := applicationIncidentRead(t, reopened, src); !v.Policy.Enabled || v.Revision != 1 {
		t.Fatal("readback did not restore exact committed state", v)
	}
}
func TestApplicationIncidentStoreOriginalStartFreshness(t *testing.T) {
	s, _, src, clock := applicationIncidentFixture(t)
	applicationIncidentEnable(t, s, src)
	clock.Store(applicationIncidentEpoch.Add(72 * time.Second).UnixNano())
	r := applicationcheck.IncidentObservation{TargetID: "fixture", Kind: "tcp", State: "network_error", Reason: "tcp_failed", ObservedAt: applicationIncidentEpoch.Add(time.Second), CompletedAt: applicationIncidentEpoch.Add(6 * time.Second)}
	if e := s.ObserveApplicationResult(context.Background(), src, r); e != nil {
		t.Fatal(e)
	}
	v := applicationIncidentRead(t, s, src)
	if len(v.Incidents) != 0 || len(v.Checks) != 1 || v.Checks[0].Condition != "unknown" || v.Checks[0].FailureCount != 0 {
		t.Fatal("stale start earned progress", v)
	}
}

func TestApplicationIncidentStoreConcurrentCASHasOneWinner(t *testing.T) {
	s, _, src, clock := applicationIncidentFixture(t)
	applicationIncidentEnable(t, s, src)
	applicationIncidentFeed(t, s, src, clock, 1, "network_error", "tcp_failed")
	applicationIncidentFeed(t, s, src, clock, 3, "network_error", "tcp_failed")
	id := applicationIncidentRead(t, s, src).Incidents[0].ID
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, n := range []int{2, 3} {
		go func(n int) {
			<-start
			c := applicationIncidentCommand(n, 1, src, "acknowledge")
			c.IncidentID = &id
			_, e := s.ChangeApplicationIncidents(context.Background(), src, c, func() bool { return true }, true)
			results <- e
		}(n)
	}
	close(start)
	winners, conflicts := 0, 0
	for range 2 {
		e := <-results
		if e == nil {
			winners++
		} else if errors.Is(e, applicationcheck.ErrIncidentInvalid) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	v := applicationIncidentRead(t, s, src)
	if winners != 1 || conflicts != 1 || v.Revision != 2 || v.Incidents[0].AcknowledgedAt == nil || v.Incidents[0].State != "open" {
		t.Fatal("CAS lost update or changed health", winners, conflicts, v)
	}
}

func TestApplicationIncidentStoreRollbackStopAndRetention(t *testing.T) {
	s, _, src, clock := applicationIncidentFixture(t)
	applicationIncidentEnable(t, s, src)
	applicationIncidentFeed(t, s, src, clock, 1, "network_error", "tcp_failed")
	applicationIncidentFeed(t, s, src, clock, 3, "network_error", "tcp_failed")
	clock.Store(applicationIncidentEpoch.Add(-time.Second).UnixNano())
	v := applicationIncidentRead(t, s, src)
	if v.ClockReliable || v.Checks[0].Condition != "unknown" || v.Incidents[0].State != "open" {
		t.Fatal("rollback invented current health", v)
	}
	c := applicationIncidentCommand(2, v.Revision, src, "disable")
	v, e := s.ChangeApplicationIncidents(context.Background(), src, c, func() bool { return true }, true)
	if e != nil || v.Policy.Enabled || v.Incidents[0].State != "monitoring_stopped" || v.Incidents[0].Recovery != nil || v.Incidents[0].ClosedAt != nil {
		t.Fatal("rollback prevented safe stop or invented close", v, e)
	}
	clock.Store(applicationIncidentEpoch.Add(32 * 24 * time.Hour).UnixNano())
	v = applicationIncidentRead(t, s, src)
	if len(v.Incidents) != 0 || !v.EarlierOmitted || !v.ClockReliable {
		t.Fatal("unknown close retained indefinitely", v)
	}
}

func TestApplicationIncidentStoreRuntimeChangeCannotEarnFailureSequence(t *testing.T) {
	s, _, src, clock := applicationIncidentFixture(t)
	applicationIncidentEnable(t, s, src)
	applicationIncidentFeed(t, s, src, clock, 1, "network_error", "tcp_failed")
	src.Token = "appsource_" + strings.Repeat("2", 32)
	clock.Store(applicationIncidentEpoch.Add(3 * time.Second).UnixNano())
	if e := s.ObserveApplicationSource(context.Background(), src); e != nil {
		t.Fatal(e)
	}
	applicationIncidentFeed(t, s, src, clock, 4, "network_error", "tcp_failed")
	v := applicationIncidentRead(t, s, src)
	if !v.Policy.Enabled || len(v.Incidents) != 0 || v.Checks[0].FailureCount != 1 || v.Revision != 1 {
		t.Fatal("runtime change inherited pending count", v)
	}
}

func TestApplicationIncidentStoreRejectsImpossibleCurrentConditions(t *testing.T) {
	for _, name := range []string{"orphan-incident", "pending-success", "current-kind-mismatch"} {
		t.Run(name, func(t *testing.T) {
			s, _, src, clock := applicationIncidentFixture(t)
			applicationIncidentEnable(t, s, src)
			state, reason := "network_error", "timeout"
			if name == "pending-success" {
				state, reason = "ok", "tcp_connected"
			}
			applicationIncidentFeed(t, s, src, clock, 1, state, reason)
			if name == "current-kind-mismatch" {
				applicationIncidentFeed(t, s, src, clock, 3, state, reason)
			}
			var saved applicationcheck.IncidentState
			if e := json.Unmarshal(applicationIncidentRaw(t, s), &saved); e != nil {
				t.Fatal(e)
			}
			p := saved.Progress["fixture"]
			switch name {
			case "orphan-incident":
				p.Check.Condition = "incident"
			case "pending-success":
				p.Check.Condition = "pending"
			case "current-kind-mismatch":
				p.Check.Kind = "dns"
				r := saved.Records[0]
				r.Kind = "dns"
				saved.Records[0] = r
			}
			saved.Progress["fixture"] = p
			raw, e := json.Marshal(saved)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.db.Exec(`UPDATE application_incidents SET body=? WHERE id=1`, raw); e != nil {
				t.Fatal(e)
			}
			if _, e = s.ApplicationIncidents(context.Background(), src, false); !errors.Is(e, applicationcheck.ErrIncidentUnavailable) {
				t.Fatal("impossible canonical current condition escaped", name, e)
			}
		})
	}
}

func TestApplicationIncidentStoreMissingUsedLedgerOrMarkerNeverLooksPristine(t *testing.T) {
	for _, table := range []string{"application_incidents", "application_incident_marker"} {
		t.Run(table, func(t *testing.T) {
			s, path, src, _ := applicationIncidentFixture(t)
			applicationIncidentEnable(t, s, src)
			if _, e := s.db.Exec("DELETE FROM " + table + " WHERE id=1"); e != nil {
				t.Fatal(e)
			}
			if _, e := s.ApplicationIncidents(context.Background(), src, false); !errors.Is(e, applicationcheck.ErrIncidentUnavailable) {
				t.Fatal("missing used state silently became pristine", e)
			}
			if e := s.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			if _, e = reopened.ApplicationIncidents(context.Background(), src, false); !errors.Is(e, applicationcheck.ErrIncidentUnavailable) {
				t.Fatal("reopen forgot prior incident use", e)
			}
			if _, e = reopened.ChangeApplicationIncidents(context.Background(), src, applicationIncidentCommand(2, 0, src, "enable"), func() bool { return true }, true); !errors.Is(e, applicationcheck.ErrIncidentUnavailable) {
				t.Fatal("missing used state permitted reinitialization", e)
			}
		})
	}
}
func TestApplicationIncidentStoreInitialMarkerAndLedgerCommitAtomically(t *testing.T) {
	for _, mode := range []string{"session-ended", "marker-insert-failed"} {
		t.Run(mode, func(t *testing.T) {
			s, path, src, _ := applicationIncidentFixture(t)
			if mode == "marker-insert-failed" {
				if _, e := s.db.Exec(`CREATE TRIGGER fail_application_marker BEFORE INSERT ON application_incident_marker BEGIN SELECT RAISE(ABORT,'synthetic marker failure'); END`); e != nil {
					t.Fatal(e)
				}
			}
			calls := 0
			_, e := s.ChangeApplicationIncidents(context.Background(), src, applicationIncidentCommand(1, 0, src, "enable"), func() bool { calls++; return mode != "session-ended" || calls < 3 }, true)
			if mode == "session-ended" && !errors.Is(e, ErrApplicationIncidentSession) || mode == "marker-insert-failed" && !errors.Is(e, applicationcheck.ErrIncidentUnavailable) {
				t.Fatal("wrong atomic rollback result", e)
			}
			for _, table := range []string{"application_incidents", "application_incident_marker"} {
				var n int
				if e = s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil || n != 0 {
					t.Fatal("half-initialized local state", table, n, e)
				}
			}
			if mode == "session-ended" {
				if s.applicationIncidentBlocked.Load() {
					t.Fatal("known session rollback blocked component")
				}
				applicationIncidentEnable(t, s, src)
				return
			}
			if _, e = s.db.Exec(`DROP TRIGGER fail_application_marker`); e != nil {
				t.Fatal(e)
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			if v := applicationIncidentRead(t, reopened, src); v.Revision != 0 || v.Policy.Enabled {
				t.Fatal("failed first opt-in resumed", v)
			}
		})
	}
}

func TestApplicationIncidentStoreQueuedAdmissionCannotCrossRaisedFence(t *testing.T) {
	for _, mode := range []string{"read", "command"} {
		t.Run(mode, func(t *testing.T) {
			s, _, src, clock := applicationIncidentFixture(t)
			applicationIncidentEnable(t, s, src)
			beforeRaw := string(applicationIncidentRaw(t, s))
			conn, e := s.db.Conn(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			before := s.db.Stats().WaitCount
			out := make(chan error, 1)
			go func() {
				var err error
				if mode == "read" {
					_, err = s.ApplicationIncidents(context.Background(), src, false)
				} else {
					_, err = s.ChangeApplicationIncidents(context.Background(), src, applicationIncidentCommand(2, 1, src, "disable"), func() bool { return true }, true)
				}
				out <- err
			}()
			applicationIncidentWaiter(t, s, before)
			// The preceding serialized storage operation has discovered an integrity or
			// uncertain-write failure. This queued request passed the earlier fast gate.
			s.applicationIncidentBlocked.Store(true)
			clock.Store(applicationIncidentEpoch.Add(time.Second).UnixNano())
			if e = conn.Close(); e != nil {
				t.Fatal(e)
			}
			if e = <-out; !errors.Is(e, applicationcheck.ErrIncidentUnavailable) {
				t.Fatal("queued request crossed newly raised component fence", mode, e)
			}
			if string(applicationIncidentRaw(t, s)) != beforeRaw {
				t.Fatal("fenced queued request persisted state", mode)
			}
		})
	}
}
