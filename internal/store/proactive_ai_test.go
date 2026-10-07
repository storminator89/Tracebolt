package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/analysis"
	"localrmm/internal/health"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newHealthAnalysisStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "operator.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func analysisIncident(t *testing.T, s *Store, device string, n uint64, at time.Time) health.Incident {
	t.Helper()
	x := health.Incident{ID: fmt.Sprintf("health_%016x", n), Key: "filesystem:root", Kind: "filesystem", Target: "/", OpenedAt: at, LastObservedAt: at}
	_, err := s.UpdateHealth(context.Background(), device, func(state *health.State) error {
		for i := range state.Incidents {
			if state.Incidents[i].ResolvedAt == nil {
				closed := at
				state.Incidents[i].ResolvedAt = &closed
				state.Incidents[i].ClosedReason = "recovered"
			}
		}
		value := 95.0
		observed := at
		state.Checks[1].State = "open"
		state.Checks[1].Value = &value
		state.Checks[1].ObservedAt = &observed
		state.EvaluatedAt = &observed
		state.NextID = n
		state.Incidents = append(state.Incidents, x)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return x
}
func refreshAnalysisIncident(t *testing.T, s *Store, device string, now time.Time) {
	t.Helper()
	_, err := s.UpdateHealth(context.Background(), device, func(state *health.State) error {
		state.EvaluatedAt = &now
		state.Checks[1].ObservedAt = &now
		for i := range state.Incidents {
			if state.Incidents[i].ResolvedAt == nil {
				state.Incidents[i].LastObservedAt = now
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func claimAnalysis(t *testing.T, s *Store, device, id, revision string, enabled, now time.Time) *HealthAnalysisClaim {
	t.Helper()
	claim, err := s.ClaimHealthAnalysis(context.Background(), device, id, revision, enabled, now)
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

type analysisStoreProvider struct{ err error }

func (p analysisStoreProvider) Identity() analysis.ProviderIdentity {
	return analysis.ProviderIdentity{Name: "test", Model: "fixture", Destination: "loopback", EndpointOrigin: "http://127.0.0.1:11434"}
}
func (p analysisStoreProvider) Generate(context.Context, analysis.ProviderRequest) ([]byte, error) {
	if p.err != nil {
		return nil, p.err
	}
	return []byte(`{"observedEvidenceIDs":["health-event"],"hypotheses":[],"counterevidence":[],"missingData":[],"nextCheck":"none"}`), nil
}
func analysisResult(t *testing.T, claim *HealthAnalysisClaim, err error) analysis.Result {
	t.Helper()
	result, e := analysis.NewService(analysisStoreProvider{err: err}).AnalyzeHealth(context.Background(), claim.Incident, claim.Check)
	if e != nil {
		t.Fatal(e)
	}
	return result
}

func TestHealthAnalysisClaimDedupAndSnapshot(t *testing.T) {
	s := newHealthAnalysisStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	x := analysisIncident(t, s, "agent-a", 1, now)
	var count atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := s.ClaimHealthAnalysis(ctx, "agent-a", x.ID, "revision-1", now, now)
			if e != nil {
				t.Error(e)
			}
			if c != nil {
				count.Add(1)
				if !reflect.DeepEqual(c.Incident, x) || c.Check.Value == nil || *c.Check.Value != 95 {
					t.Error("claim lost exact snapshot")
				}
			}
		}()
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatalf("got %d claims", count.Load())
	}
	if c := claimAnalysis(t, s, "agent-a", x.ID, "revision-2", now, now.Add(time.Minute)); c != nil {
		t.Fatal("revision change replayed claim")
	}
	view, e := s.HealthAnalyses(ctx, "agent-a")
	if e != nil || len(view) != 1 || view[x.ID].Status != "running" || view[x.ID].Result != nil {
		t.Fatal(e, view)
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), "revision") {
		t.Fatal("private revision leaked")
	}
	other, e := s.HealthAnalyses(ctx, "agent-b")
	if e != nil || len(other) != 0 {
		t.Fatal("cross-device exposure", e)
	}
}

func TestHealthAnalysisClaimEligibility(t *testing.T) {
	for _, scenario := range []string{"old-incident", "unknown", "missing-snapshot", "missing-value", "future-snapshot", "stale-evaluation", "maintenance", "resolved", "future-incident"} {
		t.Run(scenario, func(t *testing.T) {
			s := newHealthAnalysisStore(t)
			now := time.Now().UTC().Truncate(time.Millisecond)
			x := analysisIncident(t, s, "agent-a", 1, now)
			enabled := now
			_, e := s.UpdateHealth(context.Background(), "agent-a", func(state *health.State) error {
				switch scenario {
				case "old-incident":
					enabled = now.Add(time.Second)
				case "unknown":
					state.Checks[1].State = "unknown"
				case "missing-snapshot":
					state.Checks[1].ObservedAt = nil
				case "missing-value":
					state.Checks[1].Value = nil
				case "future-snapshot":
					future := now.Add(time.Hour)
					state.Checks[1].ObservedAt = &future
				case "stale-evaluation":
					old := now.Add(-3 * time.Minute)
					state.EvaluatedAt = &old
				case "maintenance":
					future := now.Add(time.Hour)
					state.MaintenanceUntil = &future
				case "resolved":
					state.Incidents[0].ResolvedAt = &now
					state.Incidents[0].ClosedReason = "recovered"
				case "future-incident":
					state.Incidents[0].OpenedAt = now.Add(time.Hour)
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			if c := claimAnalysis(t, s, "agent-a", x.ID, "revision", enabled, now.Add(time.Second)); c != nil {
				t.Fatal("ineligible incident claimed")
			}
			var n int
			if e := s.db.QueryRow(`SELECT count(*) FROM health_analyses`).Scan(&n); e != nil || n != 0 {
				t.Fatal("ineligible incident consumed a claim", e, n)
			}
		})
	}
}

func TestHealthAnalysisRateWindowAndGlobalInterval(t *testing.T) {
	s := newHealthAnalysisStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	for i := 0; i < 7; i++ {
		at := now.Add(time.Duration(i) * time.Minute)
		device := fmt.Sprintf("agent-%d", i)
		x := analysisIncident(t, s, device, 1, at)
		c := claimAnalysis(t, s, device, x.ID, "revision", now, at)
		if (c != nil) != (i < 6) {
			t.Fatalf("hourly claim %d allowed=%v", i, c != nil)
		}
		if i == 0 {
			y := analysisIncident(t, s, "interval-device", 1, at)
			if c := claimAnalysis(t, s, "interval-device", y.ID, "revision", now, at.Add(59*time.Second)); c != nil {
				t.Fatal("global interval was ignored")
			}
		}
	}
	at := now.Add(time.Hour)
	refreshAnalysisIncident(t, s, "agent-6", at)
	if c := claimAnalysis(t, s, "agent-6", "health_0000000000000001", "revision", now, at); c == nil {
		t.Fatal("rolling window did not release first claim")
	}
	if c, e := s.ClaimHealthAnalysis(context.Background(), "interval-device", "health_0000000000000001", "revision", now, now.Add(30*time.Second)); e != nil || c != nil {
		t.Fatal("backward clock bypassed budget", e)
	}
}

func TestHealthAnalysisReopenedRuleCooldown(t *testing.T) {
	s := newHealthAnalysisStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	x := analysisIncident(t, s, "agent-a", 1, now)
	if claimAnalysis(t, s, "agent-a", x.ID, "revision", now, now) == nil {
		t.Fatal("first claim missing")
	}
	at := now.Add(5 * time.Minute)
	y := analysisIncident(t, s, "agent-a", 2, at)
	if c := claimAnalysis(t, s, "agent-a", y.ID, "revision-2", now, at); c != nil {
		t.Fatal("reopened rule ignored cooldown")
	}
	at = now.Add(30 * time.Minute)
	refreshAnalysisIncident(t, s, "agent-a", at)
	if c := claimAnalysis(t, s, "agent-a", y.ID, "revision-2", now, at); c == nil {
		t.Fatal("cooldown did not expire")
	}
}

func TestHealthAnalysisCompletionFailuresAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { s.Close() }()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	x := analysisIncident(t, s, "agent-a", 1, now)
	claim := claimAnalysis(t, s, "agent-a", x.ID, "revision", now, now)
	result := analysisResult(t, claim, analysis.ErrUnavailable)
	if e = s.CompleteHealthAnalysis(ctx, "agent-a", x.ID, "wrong", result, now); !errors.Is(e, ErrHealthAnalysisConflict) {
		t.Fatal("wrong revision completed", e)
	}
	if e = s.CompleteHealthAnalysis(ctx, "agent-a", x.ID, "revision", result, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteHealthAnalysis(ctx, "agent-a", x.ID, "revision", result, now.Add(2*time.Second)); !errors.Is(e, ErrHealthAnalysisConflict) {
		t.Fatal("double completion", e)
	}
	at := now.Add(time.Minute)
	y := analysisIncident(t, s, "agent-b", 1, at)
	if claimAnalysis(t, s, "agent-b", y.ID, "revision", now, at) == nil {
		t.Fatal("missing second claim")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	view, e := s.HealthAnalyses(ctx, "agent-a")
	if e != nil || view[x.ID].Status != "unavailable" || view[x.ID].Result == nil || view[x.ID].Result.AI.Findings != nil {
		t.Fatal("failed inference was lost or invented", e, view)
	}
	view, e = s.HealthAnalyses(ctx, "agent-b")
	if e != nil || view[y.ID].Status != "interrupted" || view[y.ID].Result != nil || view[y.ID].FinishedAt == nil {
		t.Fatal("restart replay/fabrication", e, view)
	}
	refreshAnalysisIncident(t, s, "agent-b", at.Add(time.Minute))
	if claimAnalysis(t, s, "agent-b", y.ID, "changed", now, at.Add(time.Minute)) != nil {
		t.Fatal("restart/config change replayed")
	}
}

func TestHealthAnalysisCancellationAndRecovery(t *testing.T) {
	for _, reason := range []string{"recovered", "monitoring_stopped"} {
		t.Run(reason, func(t *testing.T) {
			s := newHealthAnalysisStore(t)
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			x := analysisIncident(t, s, "agent-a", 1, now)
			claim := claimAnalysis(t, s, "agent-a", x.ID, "revision", now, now)
			result := analysisResult(t, claim, nil)
			if e := s.CompleteHealthAnalysis(ctx, "agent-a", x.ID, "revision", result, now.Add(time.Second)); e != nil {
				t.Fatal(e)
			}
			recovered := now.Add(time.Minute)
			_, e := s.UpdateHealth(ctx, "agent-a", func(state *health.State) error {
				state.Incidents[0].ResolvedAt = &recovered
				state.Incidents[0].ClosedReason = reason
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			view, e := s.HealthAnalyses(ctx, "agent-a")
			if e != nil {
				t.Fatal(e)
			}
			record := view[x.ID]
			if (record.RecoveredAt != nil) != (reason == "recovered") {
				t.Fatal("incorrect recovery marker", record)
			}
			if record.Status != "completed" || record.Result == nil || !reflect.DeepEqual(*record.Result, result) {
				t.Fatal("recovery rewrote model findings")
			}
			var alarms int
			if e = s.db.QueryRow(`SELECT count(*) FROM alarm_outbox`).Scan(&alarms); e != nil || alarms != 0 {
				t.Fatal("local analysis broadened alarm delivery")
			}
		})
	}
	s := newHealthAnalysisStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	x := analysisIncident(t, s, "agent-a", 1, now)
	claim := claimAnalysis(t, s, "agent-a", x.ID, "revision", now, now)
	if e := s.FinishHealthAnalysisFailure(ctx, "agent-a", x.ID, "revision", "canceled", now); e != nil {
		t.Fatal(e)
	}
	if e := s.CompleteHealthAnalysis(ctx, "agent-a", x.ID, "revision", analysisResult(t, claim, nil), now); !errors.Is(e, ErrHealthAnalysisConflict) {
		t.Fatal("late provider result survived revoke", e)
	}
	view, e := s.HealthAnalyses(ctx, "agent-a")
	if e != nil || view[x.ID].Status != "canceled" || view[x.ID].Result != nil {
		t.Fatal(e, view)
	}
}

func TestHealthAnalysisInvalidAndOversizeInputs(t *testing.T) {
	s := newHealthAnalysisStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	x := analysisIncident(t, s, "agent-a", 1, now)
	for _, args := range [][3]string{{"", x.ID, "revision"}, {"agent-a", "", "revision"}, {"agent-a", x.ID, ""}, {"agent a", x.ID, "revision"}, {"agent-a", x.ID, strings.Repeat("r", 129)}} {
		if c, e := s.ClaimHealthAnalysis(ctx, args[0], args[1], args[2], now, now); e == nil || c != nil {
			t.Fatal("invalid claim admitted", args)
		}
	}
	if c, e := s.ClaimHealthAnalysis(ctx, "agent-a", x.ID, "revision", now, time.Time{}); e == nil || c != nil {
		t.Fatal("zero clock admitted")
	}
	claim := claimAnalysis(t, s, "agent-a", x.ID, "revision", now, now)
	for _, scenario := range []string{"empty", "oversize", "scope", "incident", "rule", "evidence", "status", "findings", "root-cause"} {
		t.Run(scenario, func(t *testing.T) {
			result := analysisResult(t, claim, nil)
			switch scenario {
			case "empty":
				result = analysis.Result{}
			case "oversize":
				result.Limitations = []string{strings.Repeat("x", MaxHealthAnalysisBytes)}
			case "scope":
				result.Packet.DataScope = ""
			case "incident":
				result.Packet.Case.ID = "health_other"
			case "rule":
				result.Packet.Case.RuleID = "other"
			case "evidence":
				result.Packet.Evidence[0].ID = "raw-journal"
			case "status":
				result.AI.Status = "made-up"
			case "findings":
				result.AI.Findings.ObservedEvidenceIDs = []string{"missing"}
			case "root-cause":
				result.RootCauseConfirmed = true
			}
			if e := s.CompleteHealthAnalysis(ctx, "agent-a", x.ID, "revision", result, now); e == nil {
				t.Fatal("invalid result persisted")
			}
		})
	}
	if e := s.FinishHealthAnalysisFailure(ctx, "agent-a", x.ID, "revision", "completed", now); e == nil {
		t.Fatal("invented completion accepted")
	}
	view, e := s.HealthAnalyses(ctx, "agent-a")
	if e != nil || view[x.ID].Status != "running" {
		t.Fatal("invalid input mutated claim", e)
	}
	if _, e = s.HealthAnalyses(ctx, strings.Repeat("a", 129)); e == nil {
		t.Fatal("unbounded read id")
	}
}

func TestHealthAnalysisCapacitySkipsWithoutBlockingHealth(t *testing.T) {
	s := newHealthAnalysisStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	x := analysisIncident(t, s, "agent-a", 1, now)
	for i := 0; i < MaxHealthAnalyses; i++ {
		_, err := s.db.Exec(`INSERT INTO health_analyses(device,incident,rule,revision,status,created) VALUES(?,?,'filesystem:root','fixture','running',?)`, fmt.Sprintf("fixture-%d", i), "health_0000000000000001", now.Add(-2*time.Hour).UnixMilli())
		if err != nil {
			t.Fatal(err)
		}
	}
	if c := claimAnalysis(t, s, "agent-a", x.ID, "revision", now, now); c != nil {
		t.Fatal("unbounded claim admitted")
	}
	if _, err := s.UpdateHealth(ctx, "agent-a", func(state *health.State) error { return state.Acknowledge(x.ID, now) }); err != nil {
		t.Fatal("AI capacity blocked deterministic health", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM health_analyses`).Scan(&count); err != nil || count != MaxHealthAnalyses {
		t.Fatal("claim bound", err, count)
	}
	// A closed, terminal row outside the full hour window can be evicted safely.
	if _, err := s.db.Exec(`UPDATE health_analyses SET status='interrupted',finished=created WHERE device='fixture-0'`); err != nil {
		t.Fatal(err)
	}
	if c := claimAnalysis(t, s, "agent-a", x.ID, "revision", now, now); c == nil {
		t.Fatal("safe eviction failed")
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM health_analyses`).Scan(&count); err != nil || count != MaxHealthAnalyses {
		t.Fatal("eviction failed to maintain bound", err, count)
	}
}

func TestHealthAnalysisRetentionProtectsOpenClaims(t *testing.T) {
	s := newHealthAnalysisStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	old := now.Add(-HealthAnalysisRetention - time.Hour)
	x := analysisIncident(t, s, "agent-a", 1, old)
	claim := claimAnalysis(t, s, "agent-a", x.ID, "revision", old, old)
	if claim == nil {
		t.Fatal("old fixture claim failed")
	}
	if err := s.CompleteHealthAnalysis(ctx, "agent-a", x.ID, "revision", analysisResult(t, claim, nil), old.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// Public reads omit expired evidence but never mutate the database.
	view, err := s.HealthAnalyses(ctx, "agent-a")
	if err != nil || len(view) != 0 {
		t.Fatal("expired analysis exposed", err, view)
	}
	var retained int
	var hasResult bool
	if err = s.db.QueryRow(`SELECT count(*),coalesce(max(result IS NOT NULL),0) FROM health_analyses WHERE device='agent-a'`).Scan(&retained, &hasResult); err != nil || retained != 1 || !hasResult {
		t.Fatal("public read mutated private retention state", err, retained, hasResult)
	}
	refreshAnalysisIncident(t, s, "agent-a", now)
	if c := claimAnalysis(t, s, "agent-a", x.ID, "new-revision", old, now); c != nil {
		t.Fatal("expired current incident replayed")
	}
	if err = s.db.QueryRow(`SELECT count(*),coalesce(max(result IS NOT NULL),0) FROM health_analyses WHERE device='agent-a'`).Scan(&retained, &hasResult); err != nil || retained != 1 || hasResult {
		t.Fatal("claim not retained or evidence not expired", err, retained, hasResult)
	}
	_, err = s.UpdateHealth(ctx, "agent-a", func(state *health.State) error {
		state.Incidents[0].ResolvedAt = &now
		state.Incidents[0].ClosedReason = "recovered"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	y := analysisIncident(t, s, "agent-b", 1, now)
	claimAnalysis(t, s, "agent-b", y.ID, "revision", now, now)
	if err = s.db.QueryRow(`SELECT count(*) FROM health_analyses WHERE device='agent-a'`).Scan(&retained); err != nil || retained != 0 {
		t.Fatal("expired closed row not pruned", err, retained)
	}
}

func TestHealthAnalysisRecoveryTransitionBeforeHistoryPruneAndRollback(t *testing.T) {
	s := newHealthAnalysisStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	x := analysisIncident(t, s, "agent-a", 1, now)
	claimAnalysis(t, s, "agent-a", x.ID, "revision", now, now)
	recovery := now.Add(time.Minute)
	transition := x
	transition.ResolvedAt = &recovery
	transition.ClosedReason = "recovered"
	// Recovery is still recorded when a bounded history immediately drops it.
	_, err := s.updateHealth(ctx, "agent-a", func(state *health.State) ([]health.Incident, error) {
		state.Incidents = []health.Incident{}
		state.Checks[1].State = "ok"
		return []health.Incident{transition}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.HealthAnalyses(ctx, "agent-a")
	if err != nil || view[x.ID].RecoveredAt == nil || !view[x.ID].RecoveredAt.Equal(recovery) {
		t.Fatal("transition lost before pruning", err, view)
	}

	y := analysisIncident(t, s, "agent-b", 1, recovery)
	claimAnalysis(t, s, "agent-b", y.ID, "revision", now, recovery)
	if _, err = s.db.Exec(`CREATE TRIGGER reject_fixture_recovery BEFORE UPDATE OF recovered ON health_analyses WHEN OLD.device='agent-b' BEGIN SELECT RAISE(ABORT,'fixture failure'); END`); err != nil {
		t.Fatal(err)
	}
	_, err = s.UpdateHealth(ctx, "agent-b", func(state *health.State) error {
		state.Incidents[0].ResolvedAt = &recovery
		state.Incidents[0].ClosedReason = "recovered"
		return nil
	})
	if err == nil {
		t.Fatal("expected recovery persistence failure")
	}
	state, err := s.HealthState(ctx, "agent-b")
	if err != nil || state.Incidents[0].ResolvedAt != nil {
		t.Fatal("health committed without recovery marker", err)
	}
}

func TestHealthAnalysesReadIsReadOnly(t *testing.T) {
	s := newHealthAnalysisStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	x := analysisIncident(t, s, "agent-a", 1, now)
	claimAnalysis(t, s, "agent-a", x.ID, "revision", now, now)
	if _, err := s.db.Exec(`PRAGMA query_only=ON`); err != nil {
		t.Fatal(err)
	}
	defer s.db.Exec(`PRAGMA query_only=OFF`)
	view, err := s.HealthAnalyses(ctx, "agent-a")
	if err != nil || view[x.ID].Status != "running" {
		t.Fatal("analysis read attempted a write", err)
	}
}

func TestHealthAnalysisClaimPreservesObservationBeforeManagerOpening(t *testing.T) {
	s := newHealthAnalysisStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	x := analysisIncident(t, s, "agent-a", 1, now)
	observed := now.Add(-5 * time.Second)
	_, err := s.UpdateHealth(ctx, "agent-a", func(state *health.State) error {
		state.Incidents[0].LastObservedAt = observed
		state.Checks[1].ObservedAt = &observed
		state.Checks[1].BadSince = &observed
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claim := claimAnalysis(t, s, "agent-a", x.ID, "revision", now, now)
	if claim == nil || !claim.Incident.LastObservedAt.Equal(observed) || !claim.Check.ObservedAt.Equal(observed) || claim.Check.BadSince == nil || !claim.Check.BadSince.Equal(observed) {
		t.Fatal("legitimate source timestamp rejected or changed")
	}
}

func TestPruneHealthAnalysesWorksWithoutProviderApproval(t *testing.T) {
	s := newHealthAnalysisStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	old := now.Add(-HealthAnalysisRetention - time.Hour)
	x := analysisIncident(t, s, "agent-a", 1, old)
	claim := claimAnalysis(t, s, "agent-a", x.ID, "expired-revision", old, old)
	if err := s.CompleteHealthAnalysis(ctx, "agent-a", x.ID, "expired-revision", analysisResult(t, claim, nil), old.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// This operation owns no provider or authorization configuration. A separate
	// alarm setting trigger makes any accidental settings mutation fail the test.
	if _, err := s.db.Exec(`CREATE TRIGGER reject_settings_write BEFORE UPDATE ON alarm_settings BEGIN SELECT RAISE(ABORT,'settings must not change'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneHealthAnalyses(ctx, now); err != nil {
		t.Fatal(err)
	}
	var count, hasResult, enabled int
	if err := s.db.QueryRow(`SELECT count(*),coalesce(max(result IS NOT NULL),0) FROM health_analyses`).Scan(&count, &hasResult); err != nil || count != 1 || hasResult != 0 {
		t.Fatal("open consume-once claim not preserved or evidence not expired", err, count, hasResult)
	}
	if err := s.db.QueryRow(`SELECT enabled FROM alarm_settings WHERE id=1`).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatal("pruning enabled settings", err, enabled)
	}
	refreshAnalysisIncident(t, s, "agent-a", now)
	if c := claimAnalysis(t, s, "agent-a", x.ID, "changed-revision", old, now); c != nil {
		t.Fatal("pruning reset consumed incident")
	}
	if _, err := s.UpdateHealth(ctx, "agent-a", func(state *health.State) error {
		state.Incidents[0].ResolvedAt = &now
		state.Incidents[0].ClosedReason = "recovered"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneHealthAnalyses(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM health_analyses`).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired closed claim not removed", err, count)
	}
	if err := s.PruneHealthAnalyses(ctx, time.Time{}); !errors.Is(err, ErrInvalidHealthAnalysis) {
		t.Fatal("zero retention clock accepted", err)
	}
}

func TestHealthAnalysesRejectCorruptRecordState(t *testing.T) {
	for _, scenario := range []string{"missing-result", "missing-finish", "running-with-result", "status-mismatch", "wrong-incident", "wrong-rule", "early-finish", "early-recovery"} {
		t.Run(scenario, func(t *testing.T) {
			s := newHealthAnalysisStore(t)
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Millisecond)
			x := analysisIncident(t, s, "agent-a", 1, now)
			claim := claimAnalysis(t, s, "agent-a", x.ID, "revision", now, now)
			if err := s.CompleteHealthAnalysis(ctx, "agent-a", x.ID, "revision", analysisResult(t, claim, nil), now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			query := ""
			switch scenario {
			case "missing-result":
				query = `UPDATE health_analyses SET result=NULL`
			case "missing-finish":
				query = `UPDATE health_analyses SET finished=NULL`
			case "running-with-result":
				query = `UPDATE health_analyses SET status='running',finished=NULL`
			case "status-mismatch":
				query = `UPDATE health_analyses SET status='unavailable'`
			case "wrong-incident":
				query = `UPDATE health_analyses SET incident='health_other'`
			case "wrong-rule":
				query = `UPDATE health_analyses SET rule='service:fixture.service'`
			case "early-finish":
				query = `UPDATE health_analyses SET finished=created-1`
			case "early-recovery":
				query = `UPDATE health_analyses SET recovered=created-1`
			}
			if _, err := s.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if _, err := s.HealthAnalyses(ctx, "agent-a"); !errors.Is(err, ErrInvalidHealthAnalysis) {
				t.Fatal("corrupt record accepted", err)
			}
		})
	}
}
