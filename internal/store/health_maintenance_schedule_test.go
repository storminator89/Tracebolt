package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/health"
	"localrmm/internal/model"
	"sync"
	"testing"
	"time"
)

func scheduledStoreCommand(n int, revision uint64, start time.Time) health.MaintenanceCommand {
	end := start.Add(15 * time.Minute)
	id := fmt.Sprintf("maintenance_%032x", n)
	return health.MaintenanceCommand{RequestID: id, WindowID: id, ExpectedRevision: revision, Action: "schedule", StartsAt: &start, EndsAt: &end}
}
func applyStoreSchedule(t *testing.T, s *Store, device string, command health.MaintenanceCommand, at time.Time) health.State {
	t.Helper()
	state, err := s.UpdateHealth(context.Background(), device, func(state *health.State) error { return state.ApplyMaintenance(command, at) })
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func storedHealthBytes(t *testing.T, s *Store, device string) string {
	t.Helper()
	var body string
	if err := s.db.QueryRow(`SELECT body FROM health_devices WHERE id=?`, device).Scan(&body); err != nil {
		t.Fatal(err)
	}
	return body
}
func scheduledInput(device string, at time.Time) health.Input {
	value := 95.0
	return health.Input{DeviceID: device, Authorized: true, ReceivedAt: at, Disk: model.Metric{Value: &value, Quality: "healthy", Unit: "%", CollectedAt: at}}
}
func TestScheduledHealthStoreLegacyReadBytesUnchanged(t *testing.T) {
	s, _ := alarmStore(t)
	ctx := context.Background()
	if _, err := s.UpdateHealth(ctx, "agent_legacy", func(*health.State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	before := storedHealthBytes(t, s, "agent_legacy")
	got, err := s.HealthStateAt(ctx, "agent_legacy", alarmEpoch.Add(time.Hour))
	if err != nil || got.Version != 1 || got.Schedule != nil || before != storedHealthBytes(t, s, "agent_legacy") {
		t.Fatal("legacy read wrote or promoted state", err)
	}
}
func TestScheduledHealthStoreReopenAndTerminalClockFloor(t *testing.T) {
	s, path := alarmStore(t)
	ctx := context.Background()
	device := "agent_schedule"
	command := scheduledStoreCommand(1, 0, alarmEpoch.Add(5*time.Minute))
	applyStoreSchedule(t, s, device, command, alarmEpoch)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	state, err := reopened.HealthStateAt(ctx, device, *command.StartsAt)
	if err != nil || state.MaintenanceEnd(*command.StartsAt) == nil {
		t.Fatal("restart lost pending plan", err)
	}
	after := command.EndsAt.Add(time.Nanosecond)
	state, err = reopened.HealthStateAt(ctx, device, after)
	if err != nil || state.Schedule.Windows[0].ClosedReason != "expired" || !state.Schedule.Windows[0].ClosedAt.Equal(*command.EndsAt) {
		t.Fatal("expiry was not original terminal end", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	final, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Close()
	body := storedHealthBytes(t, final, device)
	if _, err = final.HealthStateAt(ctx, device, *command.StartsAt); !errors.Is(err, health.ErrInvalid) {
		t.Fatal("rollback accepted", err)
	}
	if body != storedHealthBytes(t, final, device) {
		t.Fatal("failed rollback read altered state")
	}
	state, err = final.HealthState(ctx, device)
	if err != nil || state.MaintenanceEnd(*command.StartsAt) != nil || !state.Schedule.ClockFloor.Equal(after) {
		t.Fatal("known completed plan reactivated", err)
	}
}
func TestScheduledHealthStoreConcurrentExactCancellation(t *testing.T) {
	s, path := alarmStore(t)
	ctx := context.Background()
	device := "agent_schedule"
	create := scheduledStoreCommand(1, 0, alarmEpoch.Add(5*time.Minute))
	applyStoreSchedule(t, s, device, create, alarmEpoch)
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	begin := make(chan struct{})
	out := make(chan error, 2)
	var wg sync.WaitGroup
	for i, store := range []*Store{s, other} {
		wg.Add(1)
		go func(i int, store *Store) {
			defer wg.Done()
			<-begin
			command := health.MaintenanceCommand{RequestID: fmt.Sprintf("maintenance_%032x", i+2), ExpectedRevision: 1, Action: "cancel", WindowID: create.WindowID}
			_, err := store.UpdateHealth(ctx, device, func(state *health.State) error { return state.ApplyMaintenance(command, alarmEpoch.Add(time.Second)) })
			out <- err
		}(i, store)
	}
	close(begin)
	wg.Wait()
	close(out)
	successes := 0
	for err := range out {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("cancellation CAS admitted wrong number", successes)
	}
	state, err := s.HealthState(ctx, device)
	if err != nil || state.Schedule.Revision != 2 || state.Schedule.Windows[0].ClosedReason != "canceled" {
		t.Fatal("lost terminal cancellation", err)
	}
}
func TestScheduledHealthStoreTrustedClockAfterQueuedAdmission(t *testing.T) {
	s, path := alarmStore(t)
	ctx := context.Background()
	device := "agent_schedule"
	applyStoreSchedule(t, s, device, scheduledStoreCommand(1, 0, alarmEpoch.Add(5*time.Minute)), alarmEpoch)
	first := alarmEpoch.Add(10 * time.Second)
	if _, err := s.EvaluateHealth(ctx, scheduledInput(device, first), first); err != nil {
		t.Fatal(err)
	}
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	held, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	sampled := alarmEpoch.Add(20 * time.Second)
	fresh := alarmEpoch.Add(22 * time.Second)
	clockCalled := make(chan struct{}, 1)
	entered := make(chan struct{})
	done := make(chan struct {
		state health.State
		err   error
	}, 1)
	go func() {
		close(entered)
		state, err := s.EvaluateHealth(health.WithMaintenanceClock(ctx, func() time.Time { clockCalled <- struct{}{}; return fresh }), scheduledInput(device, fresh), sampled)
		done <- struct {
			state health.State
			err   error
		}{state, err}
	}()
	<-entered
	if _, err := other.HealthStateAt(ctx, device, alarmEpoch.Add(21*time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-clockCalled:
		t.Fatal("trusted time sampled before serialized DB admission")
	default:
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.err != nil || result.state.EvaluatedAt == nil || !result.state.EvaluatedAt.Equal(fresh) || result.state.Checks[1].BadSince == nil || !result.state.Checks[1].BadSince.Equal(first) || result.state.Checks[1].State != "pending" {
		t.Fatal("normal concurrent floor observation looked like rollback", result.err, result.state)
	}
}
func prepareScheduledOpening(t *testing.T) (*Store, health.MaintenanceCommand) {
	t.Helper()
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	alarmOpen(t, s, "agent_a", 0)
	command := scheduledStoreCommand(1, 0, alarmEpoch.Add(5*time.Minute))
	applyStoreSchedule(t, s, "agent_a", command, alarmEpoch.Add(150*time.Second))
	return s, command
}
func TestScheduledHealthStoreSuppressesFutureDueAndMissedWindowBacklog(t *testing.T) {
	for _, missed := range []bool{false, true} {
		t.Run(fmt.Sprintf("missed_%v", missed), func(t *testing.T) {
			s, command := prepareScheduledOpening(t)
			if _, err := s.db.Exec(`UPDATE alarm_outbox SET due=? WHERE device='agent_a'`, command.EndsAt.Add(time.Hour).UnixMilli()); err != nil {
				t.Fatal(err)
			}
			if attempt, err := s.ClaimAlarm(context.Background(), alarmBinding, command.StartsAt.Add(-time.Nanosecond)); err != nil || attempt != nil {
				t.Fatal(err, attempt)
			}
			if got := alarmStatus(t, s); got.Queued != 1 || got.Suppressed != 0 {
				t.Fatal("future plan suppressed early", got)
			}
			at := *command.StartsAt
			if missed {
				at = command.EndsAt.Add(time.Second)
			}
			if attempt, err := s.ClaimAlarm(context.Background(), alarmBinding, at); err != nil || attempt != nil {
				t.Fatal(err, attempt)
			}
			if got := alarmStatus(t, s); got.Queued != 0 || got.Suppressed != 1 {
				t.Fatal("future due opening escaped window", got)
			}
		})
	}
}
func TestScheduledHealthStoreLateRetryStillSuppressed(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	alarmOpen(t, s, "agent_a", 0)
	attempt := alarmClaim(t, s, 120)
	if attempt == nil {
		t.Fatal("fixture did not claim")
	}
	command := scheduledStoreCommand(1, 0, alarmEpoch.Add(5*time.Minute))
	applyStoreSchedule(t, s, "agent_a", command, alarmEpoch.Add(150*time.Second))
	if got, err := s.ClaimAlarm(context.Background(), alarmBinding, *command.StartsAt); err != nil || got != nil {
		t.Fatal(err, got)
	}
	if got := alarmStatus(t, s); got.InFlight != 1 || got.Suppressed != 0 {
		t.Fatal("claimed operation was called recalled", got)
	}
	at := command.EndsAt.Add(time.Second)
	if err := s.CompleteAlarm(context.Background(), alarmBinding, *attempt, alarmdelivery.Result{Outcome: alarmdelivery.Retryable, Code: "provider_rate_limited"}, at); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ClaimAlarm(context.Background(), alarmBinding, at.Add(time.Second)); err != nil || got != nil {
		t.Fatal(err, got)
	}
	if got := alarmStatus(t, s); got.Suppressed != 1 || got.Queued != 0 || got.InFlight != 0 {
		t.Fatal("late retry escaped retained interval", got)
	}
	var attempts int
	if err := s.db.QueryRow(`SELECT attempts FROM alarm_outbox WHERE id=?`, attempt.Payload.EventID).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatal("retry attempted a new send", err, attempts)
	}
}
func TestScheduledHealthStoreInFlightTruthAndPairedRecovery(t *testing.T) {
	for _, outcome := range []alarmdelivery.Outcome{alarmdelivery.Accepted, alarmdelivery.Uncertain} {
		t.Run(string(outcome), func(t *testing.T) {
			s, _ := alarmStore(t)
			configureAlarm(t, s, &alarmBinding)
			alarmOpen(t, s, "agent_a", 0)
			attempt := alarmClaim(t, s, 120)
			command := scheduledStoreCommand(1, 0, alarmEpoch.Add(5*time.Minute))
			applyStoreSchedule(t, s, "agent_a", command, alarmEpoch.Add(150*time.Second))
			if _, err := s.HealthStateAt(context.Background(), "agent_a", *command.StartsAt); err != nil {
				t.Fatal(err)
			}
			if err := s.CompleteAlarm(context.Background(), alarmBinding, *attempt, alarmdelivery.Result{Outcome: outcome, Code: "provider_accepted"}, command.StartsAt.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			alarmRecover(t, s, "agent_a", 330)
			recovery, err := s.ClaimAlarm(context.Background(), alarmBinding, alarmEpoch.Add(392*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			got := alarmStatus(t, s)
			if outcome == alarmdelivery.Accepted {
				if got.ProviderAccepted != 1 || recovery == nil || recovery.Payload.Transition != "recovered" {
					t.Fatal("maintenance lost genuine paired recovery", got, recovery)
				}
			} else if got.Uncertain != 1 || recovery != nil {
				t.Fatal("uncertain opening fabricated recovery", got, recovery)
			}
		})
	}
}
func insertScheduledOpening(t *testing.T, s *Store, n int, at, due time.Time) {
	t.Helper()
	id := fmt.Sprintf("%064x", n)
	incident := fmt.Sprintf("health_%016x", n)
	p := alarmdelivery.Payload{SchemaVersion: "tracebolt.alarm-event.v1", EventID: id, DeviceID: "agent_a", IncidentID: incident, Rule: "filesystem:root", Target: "/", Severity: "warning", Transition: "opened", State: "open", Reason: "confirmed_unhealthy", ObservedAt: at, TransitionAt: at}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO alarm_outbox(id,binding,device,incident,rule,transition,body,state,created,due) VALUES(?,?,?,?,?,'opened',?,'queued',?,?)`, id, alarmBinding.Key(), "agent_a", incident, p.Rule, body, at.UnixMilli(), due.UnixMilli()); err != nil {
		t.Fatal(err)
	}
}
func TestScheduledHealthStoreEarlyEndOriginalNanosecondBoundary(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	command := scheduledStoreCommand(1, 0, alarmEpoch.Add(5*time.Minute))
	applyStoreSchedule(t, s, "agent_a", command, alarmEpoch)
	end := command.StartsAt.Add(time.Second + 123*time.Nanosecond)
	applyStoreSchedule(t, s, "agent_a", health.MaintenanceCommand{RequestID: fmt.Sprintf("maintenance_%032x", 2), ExpectedRevision: 1, Action: "end", WindowID: command.WindowID}, end)
	for i, at := range []time.Time{end.Add(-time.Nanosecond), end, end.Add(time.Nanosecond)} {
		insertScheduledOpening(t, s, i+1, at, command.EndsAt.Add(time.Hour))
	}
	// A later pending plan must not erase the original early-end tombstone.
	applyStoreSchedule(t, s, "agent_a", scheduledStoreCommand(3, 2, command.EndsAt.Add(time.Hour)), end.Add(time.Second))
	if got, err := s.ClaimAlarm(context.Background(), alarmBinding, end.Add(2*time.Second)); err != nil || got != nil {
		t.Fatal(err, got)
	}
	if got := alarmStatus(t, s); got.Suppressed != 1 || got.Queued != 2 {
		t.Fatal("millisecond index replaced original early-end boundary", got)
	}
}
func TestScheduledHealthStoreReadFailureRollsBackFloorAndSuppression(t *testing.T) {
	s, _ := alarmStore(t)
	command := scheduledStoreCommand(1, 0, alarmEpoch.Add(5*time.Minute))
	applyStoreSchedule(t, s, "agent_a", command, alarmEpoch)
	before := storedHealthBytes(t, s, "agent_a")
	if _, err := s.db.Exec(`INSERT INTO alarm_outbox(id,binding,device,incident,rule,transition,body,state,created,due) VALUES('corrupt',?,'agent_a','health_0000000000000001','filesystem:root','opened','{}','queued',?,?)`, alarmBinding.Key(), alarmEpoch.UnixMilli(), alarmEpoch.Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HealthStateAt(context.Background(), "agent_a", *command.StartsAt); !errors.Is(err, health.ErrInvalid) {
		t.Fatal("invalid outbox source accepted", err)
	}
	if before != storedHealthBytes(t, s, "agent_a") {
		t.Fatal("failed read committed later floor")
	}
	var state string
	if err := s.db.QueryRow(`SELECT state FROM alarm_outbox WHERE id='corrupt'`).Scan(&state); err != nil || state != "queued" {
		t.Fatal("partial suppression committed", err, state)
	}
}

func TestScheduledHealthStoreAnalysisAdmissionUsesAdvancingTrustedClock(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprintf("active_%v", active), func(t *testing.T) {
			s, _ := alarmStore(t)
			device := "agent_a"
			ctx := context.Background()
			incident := analysisIncident(t, s, device, 1, alarmEpoch)
			command := scheduledStoreCommand(1, 0, alarmEpoch.Add(5*time.Minute))
			applyStoreSchedule(t, s, device, command, alarmEpoch)
			sampled := alarmEpoch
			observedFloor := alarmEpoch.Add(time.Second)
			trusted := alarmEpoch.Add(2 * time.Second)
			if active {
				sampled = command.StartsAt.Add(-time.Second)
				observedFloor = command.StartsAt.Add(-time.Nanosecond)
				trusted = command.StartsAt.Add(time.Nanosecond)
				refreshAnalysisIncident(t, s, device, sampled)
			}
			if _, err := s.HealthStateAt(ctx, device, observedFloor); err != nil {
				t.Fatal(err)
			}
			claim, err := s.ClaimHealthAnalysis(health.WithMaintenanceClock(ctx, func() time.Time { return trusted }), device, incident.ID, "revision", alarmEpoch.Add(-time.Second), sampled)
			if err != nil || (claim != nil) == active {
				t.Fatal("AI maintenance admission used the pre-storage clock", err, claim)
			}
			saved, err := s.HealthState(ctx, device)
			if err != nil || !saved.Schedule.ClockFloor.Equal(trusted) {
				t.Fatal("eligible/blocked claim lost observed floor", err, saved.Schedule)
			}
		})
	}
}
