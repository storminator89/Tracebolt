package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"localrmm/internal/alarmdelivery"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsresource"
)

func notificationGuard(time.Time) error { return nil }
func notificationEnable(t *testing.T, s *Store, domain string) WindowsNotificationPolicy {
	t.Helper()
	p, e := s.ChangeWindowsNotificationPolicy(context.Background(), maintenanceFixtureTarget(1, domain), 0, true, alarmBinding.Key(), func() time.Time { return contactAt }, notificationGuard)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func notificationCounts(t *testing.T, s *Store) AlarmStatus {
	t.Helper()
	v, e := s.WindowsNotifications(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return v.Counts
}
func notificationClaim(t *testing.T, s *Store, in windowscapacity.Input, at time.Time) *alarmdelivery.Attempt {
	t.Helper()
	c, e := s.NextWindowsNotification(context.Background(), alarmBinding, at)
	if e != nil {
		t.Fatal(e)
	}
	if c == nil {
		return nil
	}
	a, e := s.ClaimWindowsNotification(context.Background(), alarmBinding, *c, in, contactAt, func() time.Time { return at }, notificationGuard)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func notificationComplete(t *testing.T, s *Store, a *alarmdelivery.Attempt, outcome alarmdelivery.Outcome, at time.Time) {
	t.Helper()
	if a == nil {
		t.Fatal("missing Windows attempt")
	}
	if e := s.CompleteWindowsNotification(context.Background(), alarmBinding, *a, alarmdelivery.Result{Outcome: outcome, Code: "provider_accepted"}, at); e != nil {
		t.Fatal(e)
	}
}
func notificationRecoverDisk(t *testing.T, s *Store) {
	t.Helper()
	for _, sec := range []int{90, 120, 150} {
		in := capacityInput(1, sec, 50)
		if _, e := s.EvaluateWindowsCapacity(context.Background(), in, in.ReceivedAt, contactEpoch); e != nil {
			t.Fatal(e)
		}
	}
}
func TestWindowsNotificationsDefaultOffNoBackfillAndReadOnly(t *testing.T) {
	s := contactStore(t)
	configureAlarm(t, s, &alarmBinding)
	state := capacityOpen(t, s)
	raw := capacityRaw(t, s, state.DeviceID)
	if c := notificationCounts(t, s); c.Queued != 0 {
		t.Fatal("recipient enabled Windows source", c)
	}
	notificationEnable(t, s, "disk")
	if !bytes.Equal(raw, capacityRaw(t, s, state.DeviceID)) {
		t.Fatal("source enablement changed v1 ledger")
	}
	notificationRecoverDisk(t, s)
	if c := notificationCounts(t, s); c.Queued != 0 {
		t.Fatal("backfilled unpaired recovery", c)
	}
	before, e := s.WindowsIncidentSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec(`PRAGMA query_only=ON`); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if _, e = s.WindowsNotifications(context.Background()); e != nil {
			t.Fatal("GET writes/prunes", e)
		}
	}
	after, e := s.WindowsIncidentSnapshot(context.Background())
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read changed source", e)
	}
}
func TestWindowsNotificationsMetricCollisionsAcceptedPairingAndLinuxIsolation(t *testing.T) {
	s := contactStore(t)
	configureAlarm(t, s, &alarmBinding)
	for _, d := range []string{"disk", "cpu", "memory"} {
		notificationEnable(t, s, d)
	}
	disk := capacityOpen(t, s)
	cpu := resourceOpen(t, s, windowsresource.CPU)
	memory := resourceOpen(t, s, windowsresource.Memory)
	if disk.Incidents[0].ID != cpu.Assessment.Incidents[0].ID || disk.Incidents[0].ID != memory.Assessment.Incidents[0].ID {
		t.Fatal("fixture lacks collision")
	}
	if c := notificationCounts(t, s); c.Queued != 3 {
		t.Fatal("metric collision", c)
	}
	in := resourceInput(1, 60, 95, 95)
	in.Disk = capacityInput(1, 60, 95).Disk
	seen := map[string]bool{}
	for n := 0; n < 3; n++ {
		at := contactAt.Add(time.Duration(60+n*2) * time.Second)
		a := notificationClaim(t, s, in, at)
		if a == nil || seen[a.Payload.EventID] || a.Payload.SchemaVersion != WindowsNotificationSchema {
			t.Fatal("missing/colliding dispatch", a)
		}
		seen[a.Payload.EventID] = true
		notificationComplete(t, s, a, alarmdelivery.Accepted, at)
	}
	for _, sec := range []int{90, 120, 150} {
		in = resourceInput(1, sec, 50, 50)
		in.Disk = capacityInput(1, sec, 50).Disk
		for _, kind := range []windowsresource.Kind{windowsresource.CPU, windowsresource.Memory} {
			if _, e := s.EvaluateWindowsResource(context.Background(), in, kind, in.ReceivedAt, contactEpoch); e != nil {
				t.Fatal(e)
			}
		}
		if _, e := s.EvaluateWindowsCapacity(context.Background(), in, in.ReceivedAt, contactEpoch); e != nil {
			t.Fatal(e)
		}
	}
	if c := notificationCounts(t, s); c.ProviderAccepted != 3 || c.Queued != 3 {
		t.Fatal("recovery pairing", c)
	}
	for n := 0; n < 3; n++ {
		at := contactAt.Add(time.Duration(150+n*2) * time.Second)
		a := notificationClaim(t, s, in, at)
		if a == nil || a.Payload.Transition != "recovered" || a.Payload.Reason != "within-policy" {
			t.Fatal(a)
		}
		notificationComplete(t, s, a, alarmdelivery.Accepted, at)
	}
	for _, table := range []string{"alarm_outbox", "health_devices", "health_analyses"} {
		var count int
		if e := s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); e != nil || count != 0 {
			t.Fatal("Windows crossed Linux/AI boundary", table, e)
		}
	}
}
func TestWindowsNotificationsMaintenanceConsumesWithoutChangingEvidenceOrBacklog(t *testing.T) {
	s := contactStore(t)
	configureAlarm(t, s, &alarmBinding)
	notificationEnable(t, s, "disk")
	maintenanceStart(t, s, maintenanceFixtureTarget(1, "disk"), 0, contactAt)
	state := capacityOpen(t, s)
	if len(state.Incidents) != 1 || state.Incidents[0].ResolvedAt != nil {
		t.Fatal("maintenance hid incident")
	}
	if c := notificationCounts(t, s); c.Suppressed != 1 || c.Queued != 0 {
		t.Fatal("maintenance did not consume opening", c)
	}
	at := contactAt.Add(70 * time.Second)
	if _, e := s.ChangeWindowsMaintenance(context.Background(), maintenanceFixtureTarget(1, "disk"), 1, time.Time{}, "", 1, func() time.Time { return at }, maintenanceGuard); e != nil {
		t.Fatal(e)
	}
	in := capacityInput(1, 90, 95)
	if _, e := s.EvaluateWindowsCapacity(context.Background(), in, in.ReceivedAt, contactEpoch); e != nil {
		t.Fatal(e)
	}
	if a := notificationClaim(t, s, in, in.ReceivedAt); a != nil {
		t.Fatal("maintenance end flushed backlog")
	}
	if c := notificationCounts(t, s); c.Suppressed != 1 || c.Queued != 0 {
		t.Fatal(c)
	}
}
func TestWindowsNotificationsInFlightMaintenancePreservesTruthAndStopsRetry(t *testing.T) {
	for _, result := range []alarmdelivery.Outcome{alarmdelivery.Accepted, alarmdelivery.Uncertain, alarmdelivery.Retryable} {
		t.Run(string(result), func(t *testing.T) {
			s := contactStore(t)
			configureAlarm(t, s, &alarmBinding)
			notificationEnable(t, s, "disk")
			capacityOpen(t, s)
			a := notificationClaim(t, s, capacityInput(1, 60, 95), contactAt.Add(time.Minute))
			maintenanceStart(t, s, maintenanceFixtureTarget(1, "all"), 0, contactAt.Add(61*time.Second))
			if c := notificationCounts(t, s); c.InFlight != 1 {
				t.Fatal("maintenance claimed in-flight cancellation", c)
			}
			end := contactAt.Add(62 * time.Second)
			if _, e := s.ChangeWindowsMaintenance(context.Background(), maintenanceFixtureTarget(1, "all"), 1, time.Time{}, "", 1, func() time.Time { return end }, maintenanceGuard); e != nil {
				t.Fatal(e)
			}
			notificationComplete(t, s, a, result, end)
			c := notificationCounts(t, s)
			if result == alarmdelivery.Accepted && c.ProviderAccepted != 1 || result == alarmdelivery.Uncertain && c.Uncertain != 1 || result == alarmdelivery.Retryable && c.Suppressed != 1 || c.Queued != 0 {
				t.Fatal("in-flight result truth", c)
			}
		})
	}
}
func TestWindowsNotificationsQueuedMaintenanceAndPolicyChangedNeverRecovery(t *testing.T) {
	s := contactStore(t)
	configureAlarm(t, s, &alarmBinding)
	notificationEnable(t, s, "disk")
	capacityOpen(t, s)
	before := capacityRaw(t, s, contactInput(1).DeviceID)
	maintenanceStart(t, s, maintenanceFixtureTarget(1, "disk"), 0, contactAt.Add(61*time.Second))
	if !bytes.Equal(before, capacityRaw(t, s, contactInput(1).DeviceID)) {
		t.Fatal("maintenance edited evidence")
	}
	if c := notificationCounts(t, s); c.Suppressed != 1 {
		t.Fatal(c)
	}
	s2 := contactStore(t)
	configureAlarm(t, s2, &alarmBinding)
	notificationEnable(t, s2, "disk")
	capacityOpen(t, s2)
	a := notificationClaim(t, s2, capacityInput(1, 60, 95), contactAt.Add(time.Minute))
	notificationComplete(t, s2, a, alarmdelivery.Accepted, contactAt.Add(time.Minute))
	in := capacityInput(1, 90, 95)
	if _, e := s2.ConfigureWindowsCapacity(context.Background(), in, false, 90, 1, in.ReceivedAt); e != nil {
		t.Fatal(e)
	}
	if c := notificationCounts(t, s2); c.ProviderAccepted != 1 || c.Queued != 0 {
		t.Fatal("policy closure became recovery", c)
	}
}
func TestWindowsNotificationsSourceRevisionDestinationIdentityAndFinalGuards(t *testing.T) {
	s := contactStore(t)
	configureAlarm(t, s, &alarmBinding)
	p := notificationEnable(t, s, "disk")
	capacityOpen(t, s)
	ctx := context.Background()
	at := contactAt.Add(time.Minute)
	if _, e := s.ChangeWindowsNotificationPolicy(ctx, p.Target, 0, false, "", func() time.Time { return at }, notificationGuard); !errors.Is(e, ErrWindowsNotificationConflict) {
		t.Fatal("replayed revision", e)
	}
	c, e := s.NextWindowsNotification(ctx, alarmBinding, at)
	if e != nil || c == nil {
		t.Fatal(e)
	}
	in := capacityInput(1, 60, 95)
	wrong := in
	wrong.InvitationID = contactInput(2).InvitationID
	if a, e := s.ClaimWindowsNotification(ctx, alarmBinding, *c, wrong, contactAt, func() time.Time { return at }, notificationGuard); e == nil || a != nil {
		t.Fatal("replacement inherited queue")
	}
	calls := 0
	guard := func(time.Time) error {
		calls++
		if calls > 1 {
			return context.Canceled
		}
		return nil
	}
	if a, e := s.ClaimWindowsNotification(ctx, alarmBinding, *c, in, contactAt, func() time.Time { return at }, guard); e == nil || a != nil {
		t.Fatal("final authority failure dispatched")
	}
	if v := notificationCounts(t, s); v.Queued != 1 || v.InFlight != 0 {
		t.Fatal("guard committed claim", v)
	}
	b := alarmBinding
	b.Generation = "replacement"
	if e = s.ConfigureAlarms(ctx, &b, at); e != nil {
		t.Fatal(e)
	}
	if v := notificationCounts(t, s); v.Suppressed != 1 {
		t.Fatal("old destination work redirected", v)
	}
	if _, e = s.ChangeWindowsNotificationPolicy(ctx, p.Target, 1, true, alarmBinding.Key(), func() time.Time { return at }, notificationGuard); !errors.Is(e, ErrWindowsNotificationConflict) {
		t.Fatal("stale recipient approved", e)
	}
}
func TestWindowsNotificationsRestartUncertaintyCapacityAndDurableGap(t *testing.T) {
	s, path := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	notificationEnable(t, s, "disk")
	capacityOpen(t, s)
	a := notificationClaim(t, s, capacityInput(1, 60, 95), contactAt.Add(time.Minute))
	if a == nil {
		t.Fatal("no claim")
	}
	s.Close()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.ConfigureAlarms(context.Background(), &alarmBinding, contactAt.Add(65*time.Second)); e != nil {
		t.Fatal(e)
	}
	if c := notificationCounts(t, s); c.Uncertain != 1 || c.Queued != 0 {
		t.Fatal("restart replayed", c)
	}
	// Fill only bounded synthetic outbox metadata; this invokes no transport.
	for i := 1; i < alarmdelivery.MaxRecords; i++ {
		id := fmt.Sprintf("fixture-%d", i)
		_, e = s.db.Exec(`INSERT INTO windows_notification_outbox(id,binding,target_key,policy_key,revision,device,domain,target,body,transition,state,created,due) SELECT ?,binding,?,policy_key,revision,device,domain,target,body,transition,'suppressed',created,due FROM windows_notification_outbox LIMIT 1`, id, id)
		if e != nil {
			t.Fatal(e)
		}
	}
	notificationEnable(t, s, "cpu")
	state := resourceOpen(t, s, windowsresource.CPU)
	if len(state.Assessment.Incidents) != 1 {
		t.Fatal("queue full blocked health")
	}
	if c := notificationCounts(t, s); c.Dropped != 1 {
		t.Fatal("delivery gap not durable", c)
	}
}
func TestWindowsNotificationsContactReportsResumedAndServiceRunning(t *testing.T) {
	t.Run("contact", func(t *testing.T) {
		s := contactStore(t)
		configureAlarm(t, s, &alarmBinding)
		notificationEnable(t, s, "contact")
		in := contactInput(1)
		for _, sec := range []int{121, 151, 181} {
			contactEvaluate(t, s, in, contactAt.Add(time.Duration(sec)*time.Second))
		}
		at := contactAt.Add(181 * time.Second)
		a := notificationClaim(t, s, windowscapacity.Input{Input: in}, at)
		if a == nil || a.Payload.Rule != "windows-contact" {
			t.Fatal(a)
		}
		notificationComplete(t, s, a, alarmdelivery.Accepted, at)
		for _, sec := range []int{190, 220, 250} {
			in.Sequence++
			in.ReceivedAt = contactAt.Add(time.Duration(sec) * time.Second)
			contactEvaluate(t, s, in, in.ReceivedAt)
		}
		a = notificationClaim(t, s, windowscapacity.Input{Input: in}, in.ReceivedAt)
		if a == nil || a.Payload.Reason != "reports-resumed" || a.Payload.Transition != "recovered" {
			t.Fatal("contact recovery semantics", a)
		}
	})
	t.Run("service", func(t *testing.T) {
		s := contactStore(t)
		configureAlarm(t, s, &alarmBinding)
		notificationEnable(t, s, "service")
		serviceHealthOpen(t, s)
		in := serviceHealthInput(1, 120, "stopped")
		a := notificationClaim(t, s, windowscapacity.Input{Input: in.Input, Services: in.Sample}, in.ReceivedAt)
		if a == nil || a.Payload.Target != "FixtureService" {
			t.Fatal(a)
		}
		notificationComplete(t, s, a, alarmdelivery.Accepted, in.ReceivedAt)
		for _, sec := range []int{150, 180, 210, 240, 270} {
			in = serviceHealthInput(1, sec, "running")
			if _, e := s.EvaluateWindowsService(context.Background(), in, in.ReceivedAt, contactEpoch); e != nil {
				t.Fatal(e)
			}
		}
		a = notificationClaim(t, s, windowscapacity.Input{Input: in.Input, Services: in.Sample}, in.ReceivedAt)
		if a == nil || a.Payload.Reason != "running" {
			t.Fatal("service recovery semantics", a)
		}
	})
}

func TestWindowsNotificationsFinalWriteClockCannotOutliveSourceOrQueue(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint("recovery=", recovery), func(t *testing.T) {
			s := contactStore(t)
			configureAlarm(t, s, &alarmBinding)
			notificationEnable(t, s, "disk")
			capacityOpen(t, s)
			ctx := context.Background()
			in := capacityInput(1, 60, 95)
			at := contactAt.Add(179 * time.Second)
			if recovery {
				opening := notificationClaim(t, s, in, contactAt.Add(time.Minute))
				notificationComplete(t, s, opening, alarmdelivery.Accepted, contactAt.Add(time.Minute))
				notificationRecoverDisk(t, s)
				in = capacityInput(1, 150, 50)
				at = in.ReceivedAt.Add(alarmdelivery.MaxQueueAge - time.Second)
			}
			c, e := s.NextWindowsNotification(ctx, alarmBinding, at)
			if e != nil || c == nil {
				t.Fatal(e)
			}
			calls := 0
			clock := func() time.Time {
				calls++
				if calls >= 3 {
					return at.Add(2 * time.Second)
				}
				return at
			}
			a, e := s.ClaimWindowsNotification(ctx, alarmBinding, *c, in, contactAt, clock, notificationGuard)
			if !errors.Is(e, ErrWindowsNotificationConflict) || a != nil {
				t.Fatal("claim committed past final local deadline", a, e, calls)
			}
			counts := notificationCounts(t, s)
			if counts.Queued != 1 || counts.InFlight != 0 {
				t.Fatal("expired claim did not roll back", counts)
			}
		})
	}
}
