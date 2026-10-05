package store

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/health"
	"localrmm/internal/model"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var alarmEpoch = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
var alarmBinding = alarmdelivery.Binding{ManagerInstanceID: "manager_fixture", Profile: "tls", DestinationID: "fixture", Generation: "one", Fingerprint: strings.Repeat("a", 64)}

func alarmStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "operator.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}
func configureAlarm(t *testing.T, s *Store, b *alarmdelivery.Binding) {
	t.Helper()
	if e := s.ConfigureAlarms(context.Background(), b, alarmEpoch); e != nil {
		t.Fatal(e)
	}
}
func alarmTick(t *testing.T, s *Store, id string, sec int, value float64) {
	t.Helper()
	at := alarmEpoch.Add(time.Duration(sec) * time.Second)
	_, e := s.EvaluateHealth(context.Background(), health.Input{DeviceID: id, Authorized: true, ReceivedAt: at, Disk: model.Metric{Value: &value, Unit: "%", Quality: "healthy", CollectedAt: at}}, at)
	if e != nil {
		t.Fatal(e)
	}
}
func alarmOpen(t *testing.T, s *Store, id string, start int) {
	t.Helper()
	for sec := start; sec <= start+120; sec += 30 {
		alarmTick(t, s, id, sec, 95)
	}
}
func alarmRecover(t *testing.T, s *Store, id string, start int) {
	t.Helper()
	for sec := start; sec <= start+60; sec += 30 {
		alarmTick(t, s, id, sec, 50)
	}
}
func alarmClaim(t *testing.T, s *Store, sec int) *alarmdelivery.Attempt {
	t.Helper()
	a, e := s.ClaimAlarm(context.Background(), alarmBinding, alarmEpoch.Add(time.Duration(sec)*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func alarmComplete(t *testing.T, s *Store, a *alarmdelivery.Attempt, result alarmdelivery.Result, sec int) {
	t.Helper()
	if a == nil {
		t.Fatal("missing attempt")
	}
	if e := s.CompleteAlarm(context.Background(), alarmBinding, *a, result, alarmEpoch.Add(time.Duration(sec)*time.Second)); e != nil {
		t.Fatal(e)
	}
}
func alarmStatus(t *testing.T, s *Store) AlarmStatus {
	t.Helper()
	x, e := s.AlarmStatus(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return x
}
func TestAlarmDisabledNoHistoricalBroadcastAndDeviceKeys(t *testing.T) {
	s, _ := alarmStore(t)
	alarmOpen(t, s, "agent_a", 0)
	if x := alarmStatus(t, s); x.Enabled || x.Queued != 0 {
		t.Fatal(x)
	}
	configureAlarm(t, s, &alarmBinding)
	alarmTick(t, s, "agent_a", 150, 95)
	if x := alarmStatus(t, s); x.Queued != 0 {
		t.Fatal("history broadcast", x)
	}
	alarmRecover(t, s, "agent_a", 180)
	if x := alarmStatus(t, s); x.Queued != 0 {
		t.Fatal("recovery without opening", x)
	}
	alarmOpen(t, s, "agent_a", 270)
	alarmOpen(t, s, "agent_b", 270)
	if x := alarmStatus(t, s); x.Queued != 2 {
		t.Fatal("device-local incident IDs collided", x)
	}
	// Re-evaluation, acknowledgement and no-op mutation never create messages.
	for i := 0; i < 3; i++ {
		alarmTick(t, s, "agent_a", 390, 95)
	}
	_, e := s.UpdateHealth(context.Background(), "agent_b", func(h *health.State) error { return h.Acknowledge(h.Incidents[0].ID, alarmEpoch.Add(400*time.Second)) })
	if e != nil {
		t.Fatal(e)
	}
	if x := alarmStatus(t, s); x.Queued != 2 {
		t.Fatal(x)
	}
}
func TestAlarmAtomicRollbackOnOutboxFailure(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	for sec := 0; sec < 120; sec += 30 {
		alarmTick(t, s, "agent_a", sec, 95)
	}
	if _, e := s.db.Exec(`CREATE TRIGGER alarm_fail BEFORE INSERT ON alarm_outbox BEGIN SELECT RAISE(ABORT,'fixture fail'); END`); e != nil {
		t.Fatal(e)
	}
	at := alarmEpoch.Add(120 * time.Second)
	value := 95.0
	_, e := s.UpdateHealth(context.Background(), "agent_a", func(h *health.State) error {
		h.Evaluate(health.Input{Authorized: true, ReceivedAt: at, Disk: model.Metric{Value: &value, Unit: "%", Quality: "healthy", CollectedAt: at}}, at)
		return nil
	})
	if e == nil {
		t.Fatal("outbox failure ignored")
	}
	h, e := s.HealthState(context.Background(), "agent_a")
	if e != nil || len(h.Incidents) != 0 {
		t.Fatal("health committed without intent", e)
	}
	s.db.Exec(`DROP TRIGGER alarm_fail`)
	alarmTick(t, s, "agent_a", 120, 95)
	if x := alarmStatus(t, s); x.Queued != 1 {
		t.Fatal(x)
	}
}
func TestAlarmRecoveryBeforeDuringAndAfterSend(t *testing.T) {
	for _, mode := range []string{"before", "accepted", "uncertain", "retryable"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := alarmStore(t)
			configureAlarm(t, s, &alarmBinding)
			alarmOpen(t, s, "agent_a", 0)
			var a *alarmdelivery.Attempt
			if mode != "before" {
				a = alarmClaim(t, s, 120)
			}
			alarmRecover(t, s, "agent_a", 150)
			if mode == "before" {
				if x := alarmStatus(t, s); x.Queued != 0 || x.Suppressed != 1 {
					t.Fatal(x)
				}
				return
			}
			outcomes := map[string]alarmdelivery.Outcome{"accepted": alarmdelivery.Accepted, "uncertain": alarmdelivery.Uncertain, "retryable": alarmdelivery.Retryable}
			alarmComplete(t, s, a, alarmdelivery.Result{Outcome: outcomes[mode], Code: "provider_accepted"}, 210)
			recovered := alarmClaim(t, s, 212)
			if mode == "accepted" {
				if recovered == nil || recovered.Payload.Transition != "recovered" {
					t.Fatal("accepted opening lost recovery")
				}
				alarmComplete(t, s, recovered, alarmdelivery.Result{Outcome: alarmdelivery.Accepted}, 212)
				if x := alarmStatus(t, s); x.ProviderAccepted != 2 {
					t.Fatal(x)
				}
			} else if recovered != nil {
				t.Fatal("unaccepted opening fabricated recovery")
			}
		})
	}
}
func TestAlarmRestartUncertainAndDestinationBinding(t *testing.T) {
	s, path := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	alarmOpen(t, s, "agent_a", 0)
	a := alarmClaim(t, s, 120)
	if a == nil {
		t.Fatal("missing claim")
	}
	s.Close()
	reopened, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	configureAlarm(t, reopened, &alarmBinding)
	if a := alarmClaim(t, reopened, 122); a != nil {
		t.Fatal("in-flight replayed")
	}
	alarmComplete(t, reopened, a, alarmdelivery.Result{Outcome: alarmdelivery.Accepted}, 123)
	if x := alarmStatus(t, reopened); x.Uncertain != 1 || x.ProviderAccepted != 0 {
		t.Fatal("stale completion overwrote restart", x)
	}
	alarmOpen(t, reopened, "agent_b", 180)
	other := alarmBinding
	other.Fingerprint = strings.Repeat("b", 64)
	configureAlarm(t, reopened, &other)
	if a := alarmClaim(t, reopened, 300); a != nil {
		t.Fatal("old worker crossed binding")
	}
	if x := alarmStatus(t, reopened); x.Queued != 0 || x.Suppressed != 1 {
		t.Fatal("destination re-routed pending", x)
	}
	configureAlarm(t, reopened, nil)
	if x := alarmStatus(t, reopened); x.Enabled {
		t.Fatal(x)
	}
}
func TestAlarmBoundedBackoffRateAndExpiry(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	alarmOpen(t, s, "agent_a", 0)
	alarmOpen(t, s, "agent_b", 0)
	a := alarmClaim(t, s, 120)
	alarmComplete(t, s, a, alarmdelivery.Result{Outcome: alarmdelivery.Retryable, Code: "dns_failed"}, 120)
	if alarmClaim(t, s, 121) != nil {
		t.Fatal("global rate bypass")
	}
	second := alarmClaim(t, s, 122)
	if second == nil {
		t.Fatal("other record blocked")
	}
	alarmComplete(t, s, second, alarmdelivery.Result{Outcome: alarmdelivery.Failed}, 122)
	times := []int{180, 300, 600, 1500}
	for i, sec := range times {
		alarmTick(t, s, a.Payload.DeviceID, sec, 95)
		if early := alarmClaim(t, s, sec-1); early != nil {
			t.Fatal("retried before backoff")
		}
		next := alarmClaim(t, s, sec)
		if next == nil || next.Number != i+2 {
			t.Fatal("missing scheduled attempt", i)
		}
		alarmComplete(t, s, next, alarmdelivery.Result{Outcome: alarmdelivery.Retryable}, sec)
	}
	if x := alarmStatus(t, s); x.Queued != 0 || x.Failed != 2 {
		t.Fatal("retry exhaustion unbounded", x)
	}
	alarmOpen(t, s, "agent_c", 1800)
	if a := alarmClaim(t, s, 1800+120+86400); a != nil {
		t.Fatal("expired queue sent")
	}
	if x := alarmStatus(t, s); x.Failed != 3 {
		t.Fatal(x)
	}
}
func TestAlarmMaintenanceStaleAndFlapCooldown(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	alarmOpen(t, s, "agent_a", 0)
	if alarmClaim(t, s, 300) != nil {
		t.Fatal("stale source sent")
	}
	alarmTick(t, s, "agent_a", 300, 95)
	a := alarmClaim(t, s, 300)
	alarmComplete(t, s, a, alarmdelivery.Result{Outcome: alarmdelivery.Accepted}, 300)
	alarmRecover(t, s, "agent_a", 330)
	r := alarmClaim(t, s, 390)
	alarmComplete(t, s, r, alarmdelivery.Result{Outcome: alarmdelivery.Accepted}, 390)
	alarmOpen(t, s, "agent_a", 420)
	if alarmClaim(t, s, 540) != nil {
		t.Fatal("flap cooldown bypassed")
	}
	alarmTick(t, s, "agent_a", 900, 95)
	if alarmClaim(t, s, 900) == nil {
		t.Fatal("latest continuing outage never sent")
	}
	alarmOpen(t, s, "agent_b", 930)
	_, e := s.UpdateHealth(context.Background(), "agent_b", func(h *health.State) error { return h.Maintain(15, alarmEpoch.Add(1050*time.Second)) })
	if e != nil {
		t.Fatal(e)
	}
	if alarmClaim(t, s, 1050) != nil {
		t.Fatal("maintenance queued opening sent")
	}
	if x := alarmStatus(t, s); x.Suppressed != 1 {
		t.Fatal(x)
	}
}
func TestAlarmCapacityPersistsVisibleGapWithoutFreezingHealth(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	tx, e := s.db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < alarmdelivery.MaxPending; i++ {
		if _, e = tx.Exec(`INSERT INTO alarm_outbox(id,binding,device,incident,rule,transition,body,state,created,due) VALUES(?,?,'fixture',?,'offline:contact','opened','{}','queued',?,?)`, i, alarmBinding.Key(), i, alarmEpoch.UnixMilli(), alarmEpoch.UnixMilli()); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	alarmOpen(t, s, "agent_a", 0)
	h, e := s.HealthState(context.Background(), "agent_a")
	if e != nil || len(h.Incidents) != 1 {
		t.Fatal("capacity froze health")
	}
	x := alarmStatus(t, s)
	if x.Queued != alarmdelivery.MaxPending || x.Dropped != 1 {
		t.Fatal(x)
	}
	alarmTick(t, s, "agent_a", 150, 95)
	if alarmStatus(t, s).Dropped != 1 {
		t.Fatal("duplicate gap counted")
	}
}

type fakeAlarmTransport struct {
	calls int
	fn    func(alarmdelivery.Payload) alarmdelivery.Result
}

func (f *fakeAlarmTransport) Send(_ context.Context, p alarmdelivery.Payload) alarmdelivery.Result {
	f.calls++
	return f.fn(p)
}
func TestAlarmInjectedWorkerAndNoOutboundWhileDisabled(t *testing.T) {
	s, _ := alarmStore(t)
	now := alarmEpoch.Add(120 * time.Second)
	f := &fakeAlarmTransport{fn: func(p alarmdelivery.Payload) alarmdelivery.Result {
		// Storage is available during provider I/O; no transaction or connection held.
		if _, e := s.HealthState(context.Background(), p.DeviceID); e != nil {
			t.Fatal(e)
		}
		return alarmdelivery.Result{Outcome: alarmdelivery.Uncertain, Code: "https://secret.invalid/token"}
	}}
	w, e := alarmdelivery.NewWorker(s, alarmBinding, f, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	alarmOpen(t, s, "agent_a", 0)
	if e = w.Step(context.Background()); e != nil || f.calls != 0 {
		t.Fatal("disabled worker sent", e)
	}
	configureAlarm(t, s, &alarmBinding)
	alarmOpen(t, s, "agent_b", 0)
	if e = w.Step(context.Background()); e != nil || f.calls != 1 {
		t.Fatal(e)
	}
	now = now.Add(30 * time.Second)
	if e = w.Step(context.Background()); e != nil || f.calls != 1 {
		t.Fatal("uncertain automatically replayed", e)
	}
	var code string
	s.db.QueryRow(`SELECT code FROM alarm_outbox LIMIT 1`).Scan(&code)
	if code != "transport_result" {
		t.Fatal("raw diagnostic persisted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(w.Step(cancelled), context.Canceled) {
		t.Fatal("cancelled worker continued")
	}
}

func TestAlarmRecoveryForLongLivedAcceptedIncident(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	alarmOpen(t, s, "agent_a", 0)
	a := alarmClaim(t, s, 120)
	alarmComplete(t, s, a, alarmdelivery.Result{Outcome: alarmdelivery.Accepted}, 120)
	start := 31 * 24 * 60 * 60
	alarmRecover(t, s, "agent_a", start)
	recovery := alarmClaim(t, s, start+60)
	if recovery == nil || recovery.Payload.Transition != "recovered" {
		t.Fatal("retention discarded accepted opening before its recovery")
	}
}
func TestAlarmRecoveryDuringMaintenanceAndMonitoringStopped(t *testing.T) {
	t.Run("accepted recovery in maintenance", func(t *testing.T) {
		s, _ := alarmStore(t)
		configureAlarm(t, s, &alarmBinding)
		alarmOpen(t, s, "agent_a", 0)
		a := alarmClaim(t, s, 120)
		alarmComplete(t, s, a, alarmdelivery.Result{Outcome: alarmdelivery.Accepted}, 120)
		_, e := s.UpdateHealth(context.Background(), "agent_a", func(h *health.State) error { return h.Maintain(15, alarmEpoch.Add(130*time.Second)) })
		if e != nil {
			t.Fatal(e)
		}
		alarmRecover(t, s, "agent_a", 150)
		a = alarmClaim(t, s, 210)
		if a == nil || a.Payload.Transition != "recovered" {
			t.Fatal("maintenance blocked accepted opening recovery")
		}
	})
	t.Run("monitoring stopped is not recovered", func(t *testing.T) {
		s, _ := alarmStore(t)
		configureAlarm(t, s, &alarmBinding)
		_, e := s.UpdateHealth(context.Background(), "agent_a", func(h *health.State) error { return h.SetServices([]string{"fixture.service"}, alarmEpoch) })
		if e != nil {
			t.Fatal(e)
		}
		for sec := 0; sec <= 120; sec += 30 {
			at := alarmEpoch.Add(time.Duration(sec) * time.Second)
			_, e = s.UpdateHealth(context.Background(), "agent_a", func(h *health.State) error {
				h.Evaluate(health.Input{Authorized: true, ReceivedAt: at, Services: map[string]health.ServiceSample{"fixture.service": {State: "failed", ObservedAt: at}}}, at)
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		}
		if alarmStatus(t, s).Queued != 1 {
			t.Fatal("service not queued")
		}
		_, e = s.UpdateHealth(context.Background(), "agent_a", func(h *health.State) error { return h.SetServices([]string{}, alarmEpoch.Add(130*time.Second)) })
		if e != nil {
			t.Fatal(e)
		}
		if x := alarmStatus(t, s); x.Queued != 0 || x.Suppressed != 1 {
			t.Fatal("monitoring stopped created recovery", x)
		}
	})
	t.Run("authority loss pauses old opening", func(t *testing.T) {
		s, _ := alarmStore(t)
		configureAlarm(t, s, &alarmBinding)
		alarmOpen(t, s, "agent_a", 0)
		_, e := s.UpdateHealth(context.Background(), "agent_a", func(h *health.State) error {
			h.Evaluate(health.Input{Authorized: false}, alarmEpoch.Add(150*time.Second))
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
		if alarmClaim(t, s, 150) != nil {
			t.Fatal("authority loss opening sent")
		}
	})
}

func TestAlarmExactTransitionsSurviveFullHistoryPruning(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	alarmOpen(t, s, "agent_a", 0)
	opening := alarmClaim(t, s, 120)
	alarmComplete(t, s, opening, alarmdelivery.Result{Outcome: alarmdelivery.Accepted}, 120)
	now := alarmEpoch.Add(31 * 24 * time.Hour)
	good := now.Add(-time.Minute)
	bad := now.Add(-2 * time.Minute)
	prior := now.Add(-30 * time.Second)
	_, e := s.UpdateHealth(context.Background(), "agent_a", func(h *health.State) error {
		original := h.Incidents[0]
		if e := h.SetServices([]string{"fixture.service"}, now); e != nil {
			return e
		}
		h.Incidents = nil
		for i := 100; i >= 2; i-- {
			closed := now.Add(-time.Duration(i) * time.Minute)
			h.Incidents = append(h.Incidents, health.Incident{ID: fmt.Sprintf("health_%016x", i), Key: "filesystem:root", Kind: "filesystem", Target: "/", OpenedAt: closed.Add(-time.Minute), LastObservedAt: closed, ResolvedAt: &closed, ClosedReason: "recovered"})
		}
		h.Incidents = append(h.Incidents, original)
		h.NextID = 100
		h.EvaluatedAt = &prior
		h.Checks[1].GoodSince = &good
		h.Checks[1].ObservedAt = &prior
		h.Checks[2].BadSince = &bad
		h.Checks[2].ObservedAt = &prior
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	value := 50.0
	_, e = s.EvaluateHealth(context.Background(), health.Input{DeviceID: "agent_a", Authorized: true, ReceivedAt: now, Disk: model.Metric{Value: &value, Unit: "%", Quality: "healthy", CollectedAt: now}, Services: map[string]health.ServiceSample{"fixture.service": {State: "failed", ObservedAt: now}}}, now)
	if e != nil {
		t.Fatal(e)
	}
	h, _ := s.HealthState(context.Background(), "agent_a")
	if len(h.Incidents) != 100 {
		t.Fatal("fixture did not fill history")
	}
	for _, x := range h.Incidents {
		if x.ID == opening.Payload.IncidentID {
			t.Fatal("fixture must prune oldest incident")
		}
	}
	// Force another enqueue after pruning; it must not delete the dependency of
	// the still-pending recovery merely because its UI history was evicted.
	alarmOpen(t, s, "agent_b", 31*24*60*60)
	var state string
	if e = s.db.QueryRow(`SELECT state FROM alarm_outbox WHERE id=?`, opening.Payload.EventID).Scan(&state); e != nil || state != "provider_accepted" {
		t.Fatal("pending recovery lost accepted dependency", e)
	}
	var recovery int
	if e = s.db.QueryRow(`SELECT count(*) FROM alarm_outbox WHERE device='agent_a' AND transition='recovered' AND state='queued'`).Scan(&recovery); e != nil || recovery != 1 {
		t.Fatal("pruned transition lost", e)
	}
}

func TestAlarmQueuedRestartAndTotalRecordBound(t *testing.T) {
	t.Run("queued restart remains single intent", func(t *testing.T) {
		s, path := alarmStore(t)
		configureAlarm(t, s, &alarmBinding)
		alarmOpen(t, s, "agent_a", 0)
		s.Close()
		reopened, e := Open(path)
		if e != nil {
			t.Fatal(e)
		}
		defer reopened.Close()
		configureAlarm(t, reopened, &alarmBinding)
		a := alarmClaim(t, reopened, 120)
		if a == nil {
			t.Fatal("queued intent lost")
		}
		alarmComplete(t, reopened, a, alarmdelivery.Result{Outcome: alarmdelivery.Accepted, Code: "provider_accepted"}, 120)
		if alarmClaim(t, reopened, 122) != nil {
			t.Fatal("queued restart duplicated")
		}
		var code string
		if e = reopened.db.QueryRow(`SELECT code FROM alarm_outbox WHERE id=?`, a.Payload.EventID).Scan(&code); e != nil || code != "provider_accepted" {
			t.Fatal("fixed diagnostic lost", e)
		}
	})
	t.Run("total retained records bounded", func(t *testing.T) {
		s, _ := alarmStore(t)
		configureAlarm(t, s, &alarmBinding)
		tx, e := s.db.Begin()
		if e != nil {
			t.Fatal(e)
		}
		for i := 0; i < alarmdelivery.MaxRecords; i++ {
			if _, e = tx.Exec(`INSERT INTO alarm_outbox(id,binding,device,incident,rule,transition,body,state,created,due) VALUES(?,?,'fixture',?,'offline:contact','opened','{}','suppressed',?,?)`, i, alarmBinding.Key(), i, alarmEpoch.UnixMilli(), alarmEpoch.UnixMilli()); e != nil {
				t.Fatal(e)
			}
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
		alarmOpen(t, s, "agent_a", 0)
		if x := alarmStatus(t, s); x.Suppressed != alarmdelivery.MaxRecords || x.Dropped != 1 || x.Queued != 0 {
			t.Fatal(x)
		}
	})
}

type cancelledAlarmTransport struct{ entered chan struct{} }

func (f cancelledAlarmTransport) Send(ctx context.Context, _ alarmdelivery.Payload) alarmdelivery.Result {
	close(f.entered)
	<-ctx.Done()
	return alarmdelivery.Result{Outcome: alarmdelivery.Uncertain, Code: "request_uncertain"}
}
func TestAlarmWorkerShutdownPersistsUncertaintyBeforeReturn(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	alarmOpen(t, s, "agent_a", 0)
	entered := make(chan struct{})
	w, e := alarmdelivery.NewWorker(s, alarmBinding, cancelledAlarmTransport{entered}, func() time.Time { return alarmEpoch.Add(120 * time.Second) })
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, nil) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("worker never entered fixture transport")
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker shutdown did not finish")
	}
	if x := alarmStatus(t, s); x.InFlight != 0 || x.Uncertain != 1 {
		t.Fatal("shutdown returned before durable uncertainty", x)
	}
}
