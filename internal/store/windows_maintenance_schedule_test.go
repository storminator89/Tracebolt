package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/alarmdelivery"
)

func scheduleWindows(t *testing.T, s *Store, target WindowsMaintenanceTarget, revision uint64, now, start, end time.Time) WindowsMaintenanceScheduleState {
	t.Helper()
	v, e := s.ChangeWindowsMaintenanceSchedule(context.Background(), target, revision, "schedule", 0, start, end, "planned-work", func() time.Time { return now }, maintenanceGuard)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestWindowsMaintenanceScheduleLifecycleRestartAndCompatibility(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "scheduled.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { s.Close() }()
	target := maintenanceFixtureTarget(1, "disk")
	now := contactAt
	var version int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != 1 {
		t.Fatal(version)
	}
	before, _ := s.WindowsIncidentSnapshot(ctx)
	v := scheduleWindows(t, s, target, 0, now, now.Add(time.Hour), now.Add(2*time.Hour))
	if !v.Windows[0].Pending(now) || v.Windows[0].Active(now) {
		t.Fatal(v)
	}
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != 2 {
		t.Fatal("downgrade silently ignores plans", version)
	}
	if _, e = s.ChangeWindowsMaintenanceSchedule(ctx, target, 0, "schedule", 0, now.Add(3*time.Hour), now.Add(4*time.Hour), "planned-work", func() time.Time { return now }, maintenanceGuard); !errors.Is(e, ErrWindowsMaintenanceConflict) {
		t.Fatal("replay", e)
	}
	now = now.Add(time.Minute)
	v, e = s.ChangeWindowsMaintenanceSchedule(ctx, target, 1, "cancel", 1, time.Time{}, time.Time{}, "", func() time.Time { return now }, maintenanceGuard)
	if e != nil || v.Windows[0].CancelledAt == nil || v.Windows[0].Suppresses(contactAt, now.Add(5*time.Hour)) {
		t.Fatal("cancel", v, e)
	}
	v = scheduleWindows(t, s, target, 2, now, now.Add(time.Hour), now.Add(2*time.Hour))
	now = v.Windows[0].StartsAt.Add(123 * time.Nanosecond)
	if _, e = s.ChangeWindowsMaintenanceSchedule(ctx, target, 3, "cancel", 3, time.Time{}, time.Time{}, "", func() time.Time { return now }, maintenanceGuard); !errors.Is(e, ErrWindowsMaintenanceConflict) {
		t.Fatal("late cancel", e)
	}
	v, e = s.ChangeWindowsMaintenanceSchedule(ctx, target, 3, "end", 3, time.Time{}, time.Time{}, "", func() time.Time { return now }, maintenanceGuard)
	if e != nil || v.Windows[0].EndedAt == nil || !v.Windows[0].EndsAt.Equal(contactAt.Add(121*time.Minute)) {
		t.Fatal("early end moved bound", v, e)
	}
	if !v.Windows[0].Suppresses(now.Add(-time.Nanosecond), now.Add(time.Hour)) || v.Windows[0].Suppresses(now, now.Add(time.Hour)) {
		t.Fatal("nanosecond early-end edge")
	}
	after, _ := s.WindowsIncidentSnapshot(ctx)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("changed incidents")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.WindowsMaintenanceSchedules(ctx, func() time.Time { return now.Add(time.Hour) })
	if e != nil || len(rows) != 1 || rows[0].Revision != 4 {
		t.Fatal("restart", rows, e)
	}
	if _, e = s.WindowsMaintenanceSchedules(ctx, func() time.Time { return now }); !errors.Is(e, ErrWindowsMaintenanceConflict) {
		t.Fatal("rollback reactivated", e)
	}
	if _, e = s.db.Exec(`DELETE FROM windows_maintenance_schedules`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.WindowsMaintenanceSchedules(ctx, func() time.Time { return now.Add(2 * time.Hour) }); e == nil {
		t.Fatal("missing used row repaired")
	}
}
func TestWindowsMaintenanceScheduleOverlapAndReplacement(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	target := maintenanceFixtureTarget(1, "disk")
	now := contactAt
	scheduleWindows(t, s, target, 0, now, now.Add(time.Hour), now.Add(2*time.Hour))
	for _, domain := range []string{"all", "disk"} {
		other := maintenanceFixtureTarget(1, domain)
		if _, e := s.ChangeWindowsMaintenance(ctx, other, 0, now.Add(time.Minute*10), "other", 0, func() time.Time { return now }, maintenanceGuard); !errors.Is(e, ErrWindowsMaintenanceConflict) {
			t.Fatal("immediate overlaps pending", domain, e)
		}
		if _, e := s.ChangeWindowsMaintenanceSchedule(ctx, other, 0, "schedule", 0, now.Add(3*time.Hour), now.Add(4*time.Hour), "other", func() time.Time { return now }, maintenanceGuard); !errors.Is(e, ErrWindowsMaintenanceConflict) {
			t.Fatal("conflicting schedule", e)
		}
	}
	scheduleWindows(t, s, maintenanceFixtureTarget(1, "cpu"), 0, now, now.Add(time.Hour), now.Add(2*time.Hour))
	replacement := target
	replacement.InvitationID = "invite_" + strings.Repeat("a", 32)
	replacement.CertificateHash = strings.Repeat("b", 64)
	v := scheduleWindows(t, s, replacement, 0, now, now.Add(time.Hour), now.Add(2*time.Hour))
	if v.Revision != 1 || len(v.Windows) != 1 {
		t.Fatal("replacement inherited")
	}
	maintenanceStart(t, s, maintenanceFixtureTarget(2, "all"), 0, now)
	if _, e := s.ChangeWindowsMaintenanceSchedule(ctx, maintenanceFixtureTarget(2, "disk"), 0, "schedule", 0, now.Add(3*time.Hour), now.Add(4*time.Hour), "other", func() time.Time { return now }, maintenanceGuard); !errors.Is(e, ErrWindowsMaintenanceConflict) {
		t.Fatal("schedule ignored immediate", e)
	}
}
func TestWindowsMaintenanceScheduleBoundsCapacityFinalGuard(t *testing.T) {
	for _, lead := range []time.Duration{time.Minute - time.Nanosecond, 7*24*time.Hour + time.Nanosecond} {
		s := contactStore(t)
		_, e := s.ChangeWindowsMaintenanceSchedule(context.Background(), maintenanceFixtureTarget(1, "all"), 0, "schedule", 0, contactAt.Add(lead), contactAt.Add(lead+time.Hour), "other", func() time.Time { return contactAt }, maintenanceGuard)
		if !errors.Is(e, ErrWindowsMaintenanceConflict) {
			t.Fatal(lead, e)
		}
	}
	s := contactStore(t)
	target := maintenanceFixtureTarget(1, "all")
	now := contactAt
	revision := uint64(0)
	for i := 0; i < MaxWindowsMaintenanceSchedules; i++ {
		v := scheduleWindows(t, s, target, revision, now, now.Add(time.Minute), now.Add(2*time.Minute))
		revision = v.Revision
		now = now.Add(3 * time.Minute)
	}
	if _, e := s.ChangeWindowsMaintenanceSchedule(context.Background(), target, revision, "schedule", 0, now.Add(time.Minute), now.Add(2*time.Minute), "other", func() time.Time { return now }, maintenanceGuard); !errors.Is(e, ErrLimit) {
		t.Fatal("capacity eviction", e)
	}
	s2 := contactStore(t)
	calls := 0
	_, e := s2.ChangeWindowsMaintenanceSchedule(context.Background(), target, 0, "schedule", 0, contactAt.Add(61*time.Second), contactAt.Add(time.Hour), "other", func() time.Time {
		calls++
		if calls > 1 {
			return contactAt.Add(2 * time.Second)
		}
		return contactAt
	}, maintenanceGuard)
	if !errors.Is(e, ErrWindowsMaintenanceConflict) {
		t.Fatal("admission delayed shifted window", e)
	}
	rows, e := s2.WindowsMaintenanceSchedules(context.Background(), func() time.Time { return contactAt.Add(2 * time.Second) })
	if e != nil || len(rows) != 0 {
		t.Fatal("failed transaction persisted")
	}
}
func TestWindowsMaintenanceScheduleMissedWindowConsumesFutureDueAndPreservesIncidents(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	configureAlarm(t, s, &alarmBinding)
	notificationEnable(t, s, "disk")
	state := capacityOpen(t, s)
	raw := capacityRaw(t, s, state.DeviceID)
	scheduleWindows(t, s, maintenanceFixtureTarget(1, "all"), 0, contactAt.Add(time.Minute), contactAt.Add(2*time.Minute), contactAt.Add(3*time.Minute))
	if c := notificationCounts(t, s); c.Queued != 1 {
		t.Fatal("planning muted before start", c)
	}
	if _, e := s.db.Exec(`UPDATE windows_notification_outbox SET due=? WHERE state='queued'`, contactAt.Add(time.Hour).UnixMilli()); e != nil {
		t.Fatal(e)
	}
	if _, e := s.NextWindowsNotification(ctx, alarmBinding, contactAt.Add(4*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if c := notificationCounts(t, s); c.Queued != 0 || c.Suppressed != 1 {
		t.Fatal("missed window backlog", c)
	}
	if !reflect.DeepEqual(raw, capacityRaw(t, s, state.DeviceID)) {
		t.Fatal("schedule changed source evidence")
	}
}
func TestWindowsMaintenanceScheduleNativeSourceTransitionsStillOpenIncidents(t *testing.T) {
	s := contactStore(t)
	configureAlarm(t, s, &alarmBinding)
	notificationEnable(t, s, "disk")
	scheduleWindows(t, s, maintenanceFixtureTarget(1, "disk"), 0, contactAt, contactAt.Add(time.Minute), contactAt.Add(5*time.Minute))
	state := capacityOpen(t, s)
	if len(state.Incidents) == 0 {
		t.Fatal("Windows incident was suppressed")
	}
	if c := notificationCounts(t, s); c.Suppressed != 1 || c.Queued != 0 {
		t.Fatal("scheduled source admission", c)
	}
}
func TestWindowsMaintenanceScheduleCompleteServicesAndInflightTruth(t *testing.T) {
	for _, outcome := range []alarmdelivery.Outcome{alarmdelivery.Accepted, alarmdelivery.Uncertain, alarmdelivery.Retryable} {
		t.Run(string(outcome), func(t *testing.T) {
			s := contactStore(t)
			ctx := context.Background()
			configureAlarm(t, s, &alarmBinding)
			in := completeNotificationConfigure(t, s, "FixtureService")
			completeNotificationEnable(t, s, in)
			completeNotificationOpen(t, s, &in)
			at := contactAt.Add(180 * time.Second)
			a := completeNotificationClaim(t, s, in, at)
			if a == nil {
				t.Fatal("missing attempt")
			}
			scheduleWindows(t, s, maintenanceFixtureTarget(1, "service"), 0, at, at.Add(time.Minute), at.Add(2*time.Minute))
			if _, e := s.WindowsMaintenanceSchedules(ctx, func() time.Time { return at.Add(3 * time.Minute) }); e != nil {
				t.Fatal(e)
			}
			notificationComplete(t, s, a, outcome, at.Add(3*time.Minute))
			state, _, _ := completeNotificationRow(t, s, a.Payload.EventID)
			want := string(outcome)
			if outcome == alarmdelivery.Retryable {
				want = "suppressed"
			}
			if state != want {
				t.Fatal(state, want)
			}
		})
	}
}

func TestWindowsMaintenanceScheduleReclaimsOnlyPastQueueHorizonWithDurableFloor(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	target := maintenanceFixtureTarget(1, "all")
	now := contactAt
	revision := uint64(0)
	for i := 0; i < 16; i++ {
		v := scheduleWindows(t, s, target, revision, now, now.Add(time.Minute), now.Add(2*time.Minute))
		revision = v.Revision
		now = now.Add(3 * time.Minute)
	}
	before, e := s.WindowsMaintenanceSchedules(ctx, func() time.Time { return now })
	if e != nil || len(before[0].Windows) != 16 {
		t.Fatal("premature retirement", e)
	}
	later := contactAt.Add(25 * time.Hour)
	after, e := s.WindowsMaintenanceSchedules(ctx, func() time.Time { return later })
	if e != nil || len(after[0].Windows) != 4 || after[0].RetiredWindows != 12 || after[0].RetiredThroughRevision != 12 || after[0].Windows[3].ID != 13 {
		t.Fatal("retirement floor", after, e)
	}
	next := scheduleWindows(t, s, target, revision, later, later.Add(time.Minute), later.Add(2*time.Minute))
	if next.Revision != 17 || next.Windows[0].ID != 17 || next.RetiredWindows != 12 {
		t.Fatal("retirement reset identity", next)
	}
	if _, e = s.WindowsMaintenanceSchedules(ctx, func() time.Time { return contactAt.Add(time.Hour) }); !errors.Is(e, ErrWindowsMaintenanceConflict) {
		t.Fatal("clock rollback crossed retirement", e)
	}
	// A late transition beyond its original immutable queue lifetime cannot be
	// made deliverable merely because a maintenance interval was retired.
	configureAlarm(t, s, &alarmBinding)
	notificationEnable(t, s, "disk")
	capacityOpen(t, s)
	if _, e = s.NextWindowsNotification(ctx, alarmBinding, later.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if a := notificationClaim(t, s, capacityInput(1, 60, 95), later.Add(time.Minute)); a != nil {
		t.Fatal("old transition escaped queue expiry")
	}
}

func TestWindowsMaintenanceScheduleStartsDuringFinalNotificationGuard(t *testing.T) {
	s := contactStore(t)
	configureAlarm(t, s, &alarmBinding)
	notificationEnable(t, s, "disk")
	capacityOpen(t, s)
	scheduleWindows(t, s, maintenanceFixtureTarget(1, "disk"), 0, contactAt, contactAt.Add(2*time.Minute), contactAt.Add(3*time.Minute))
	now := contactAt.Add(2*time.Minute - time.Millisecond)
	candidate, err := s.NextWindowsNotification(context.Background(), alarmBinding, now)
	if err != nil || candidate == nil {
		t.Fatal(candidate, err)
	}
	calls := 0
	attempt, err := s.ClaimWindowsNotification(context.Background(), alarmBinding, *candidate, capacityInput(1, 60, 95), contactAt, func() time.Time { return now }, func(time.Time) error {
		calls++
		if calls == 3 {
			now = contactAt.Add(2 * time.Minute)
		}
		return nil
	})
	if attempt != nil {
		t.Fatalf("dispatched at %s during active schedule after guard (calls=%d error=%v)", now, calls, err)
	}
}
func TestWindowsMaintenanceScheduleSourceAdmissionRetainsClockFloor(t *testing.T) {
	s := contactStore(t)
	configureAlarm(t, s, &alarmBinding)
	notificationEnable(t, s, "disk")
	target := maintenanceFixtureTarget(1, "disk")
	scheduleWindows(t, s, target, 0, contactAt, contactAt.Add(time.Minute), contactAt.Add(5*time.Minute))
	capacityOpen(t, s)
	if counts := notificationCounts(t, s); counts.Suppressed != 1 {
		t.Fatal("fixture", counts)
	}
	changed, err := s.ChangeWindowsMaintenanceSchedule(context.Background(), target, 1, "cancel", 1, time.Time{}, time.Time{}, "", func() time.Time { return contactAt.Add(30 * time.Second) }, maintenanceGuard)
	if err == nil {
		t.Fatalf("clock rollback canceled already-used active plan: %+v", changed)
	}
}

func TestWindowsMaintenanceScheduleReadRollbackDoesNotCommitSuppression(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	configureAlarm(t, s, &alarmBinding)
	notificationEnable(t, s, "disk")
	capacityOpen(t, s)
	scheduleWindows(t, s, maintenanceFixtureTarget(1, "disk"), 0, contactAt, contactAt.Add(2*time.Minute), contactAt.Add(3*time.Minute))
	calls := 0
	_, e := s.WindowsMaintenanceSchedules(ctx, func() time.Time {
		calls++
		if calls == 1 {
			return contactAt.Add(2 * time.Minute)
		}
		return contactAt.Add(2*time.Minute - time.Second)
	})
	if !errors.Is(e, ErrWindowsMaintenanceConflict) {
		t.Fatal("mutating read ignored rollback", e)
	}
	if c := notificationCounts(t, s); c.Queued != 1 || c.Suppressed != 0 {
		t.Fatal("rollback committed suppression", c)
	}
}
func TestWindowsMaintenanceScheduleFinalAuthorityGuardPreservesMinimumLead(t *testing.T) {
	s := contactStore(t)
	now := contactAt
	calls := 0
	_, e := s.ChangeWindowsMaintenanceSchedule(context.Background(), maintenanceFixtureTarget(1, "all"), 0, "schedule", 0, now.Add(61*time.Second), now.Add(time.Hour), "planned-work", func() time.Time { return now }, func(time.Time, time.Time) error {
		calls++
		if calls == 2 {
			now = now.Add(2 * time.Second)
		}
		return nil
	})
	if !errors.Is(e, ErrWindowsMaintenanceConflict) {
		t.Fatal("authority guard shortened minimum lead", e)
	}
	rows, e := s.WindowsMaintenanceSchedules(context.Background(), func() time.Time { return now })
	if e != nil || len(rows) != 0 {
		t.Fatal("rejected schedule committed", rows, e)
	}
}

// The shared schema initializer must preserve Linux and Windows watch policies when the
// first Windows schedule raises the operator database compatibility version.
func TestWindowsMaintenanceSchedulePreservesExistingWatchPolicies(t *testing.T) {
	s, path, mountInput, mountCommand := mountFixture(t)
	defer func() { s.Close() }()
	ctx := context.Background()
	processInput, processCommand, now := processWatchInput()
	clock := func() time.Time { return now }
	guard := func(time.Time) error { return nil }
	if _, _, err := s.UpdateLinuxProcessWatches(ctx, processInput, &processCommand, nil, false, clock, guard); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpdateLinuxMountWatches(ctx, mountInput, &mountCommand, false, clock, guard); err != nil {
		t.Fatal(err)
	}
	windowsInput, windowsRequest, _ := processWatchStoreFixture(t)
	if _, err := s.ConfigureWindowsProcessWatch(ctx, windowsInput, windowsRequest, clock, guard); err != nil {
		t.Fatal(err)
	}
	var windowsBefore string
	if err := s.db.QueryRow(`SELECT body FROM windows_process_watch_devices WHERE id=?`, windowsInput.DeviceID).Scan(&windowsBefore); err != nil {
		t.Fatal(err)
	}
	processBefore := string(processWatchRaw(t, s, processInput.DeviceID))
	var mountBefore string
	if err := s.db.QueryRow(`SELECT body FROM linux_mount_watches WHERE id=?`, mountInput.DeviceID).Scan(&mountBefore); err != nil {
		t.Fatal(err)
	}
	scheduleWindows(t, s, maintenanceFixtureTarget(1, "all"), 0, now, now.Add(time.Hour), now.Add(2*time.Hour))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err = s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 2 {
		t.Fatal("reopen downgraded schedule compatibility", version, err)
	}
	var windowsAfter string
	if err = s.db.QueryRow(`SELECT body FROM windows_process_watch_devices WHERE id=?`, windowsInput.DeviceID).Scan(&windowsAfter); err != nil {
		t.Fatal(err)
	}
	if windowsBefore != windowsAfter {
		t.Fatal("scheduled maintenance changed existing Windows presence policy bytes")
	}
	if state, err := s.WindowsProcessWatchState(ctx, windowsInput.DeviceID); err != nil || state.Policy.Revision != 1 || !state.Policy.Enabled {
		t.Fatal("Windows presence policy lost", err)
	}
	var mountAfter string
	if err = s.db.QueryRow(`SELECT body FROM linux_mount_watches WHERE id=?`, mountInput.DeviceID).Scan(&mountAfter); err != nil {
		t.Fatal(err)
	}
	if processBefore != string(processWatchRaw(t, s, processInput.DeviceID)) || mountBefore != mountAfter {
		t.Fatal("scheduled maintenance changed existing Linux watch bytes")
	}
	if state, err := s.LinuxProcessWatchState(ctx, processInput.DeviceID); err != nil || state.Revision != 1 || !state.Policy.Enabled {
		t.Fatal("Linux process policy lost", err)
	}
	if state, err := s.LinuxMountWatchState(ctx, mountInput.DeviceID); err != nil || state.Revision != 1 || !state.Policy.Enabled {
		t.Fatal("Linux mount policy lost", err)
	}
}
