package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/alarmdelivery"
)

func TestFleetGroupMaintenanceEndExactWindowAndUnchangedHistory(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	target := maintenanceFixtureTarget(1, "disk")
	_, selection := groupMaintenanceSelection(t, s, target)
	capacityOpen(t, s)
	before, err := s.WindowsIncidentSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A group end can deliberately select an existing individual window. It
	// does not require or infer a durable group-start job.
	original := maintenanceStart(t, s, target, 0, contactAt)
	other := maintenanceStart(t, s, maintenanceFixtureTarget(1, "cpu"), 0, contactAt)
	endAt := contactAt.Add(time.Minute)
	end := func(sel FleetGroupMaintenanceSelection, revision, id uint64) (WindowsMaintenanceState, error) {
		return s.EndFleetGroupMaintenance(ctx, sel, target, revision, id, func() time.Time { return endAt }, maintenanceGuard)
	}
	for _, change := range []string{"manager", "group", "revision", "identity"} {
		bad := selection
		switch change {
		case "manager":
			bad.Manager = strings.Repeat("c", 64)
		case "group":
			bad.GroupID = "group_" + strings.Repeat("2", 32)
		case "revision":
			bad.GroupRevision++
		case "identity":
			bad.Identity = strings.Repeat("d", 64)
		}
		if _, err = end(bad, 1, 1); !errors.Is(err, ErrWindowsMaintenanceConflict) {
			t.Fatal("unreviewed group end accepted", change, err)
		}
	}
	for _, id := range []uint64{0, MaxWindowsMaintenanceRevision + 1} {
		if _, err = end(selection, 1, id); !errors.Is(err, ErrWindowsMaintenance) {
			t.Fatal("invalid end became another operation", id, err)
		}
	}
	if _, err = end(selection, 1, 2); !errors.Is(err, ErrWindowsMaintenanceConflict) {
		t.Fatal("unreviewed window ended", err)
	}
	v, err := end(selection, 1, 1)
	if err != nil || v.Revision != 2 || v.Windows[0].ID != 1 || v.Windows[0].EndedAt == nil || !v.Windows[0].EndedAt.Equal(endAt) || !v.Windows[0].EndsAt.Equal(original.Windows[0].EndsAt) || !v.Windows[0].StartedAt.Equal(original.Windows[0].StartedAt) || v.Windows[0].Intent != original.Windows[0].Intent {
		t.Fatal("exact end lost original window", v, err)
	}
	for _, revision := range []uint64{1, 2} {
		if _, err = end(selection, revision, 1); !errors.Is(err, ErrWindowsMaintenanceConflict) {
			t.Fatal("ended window replayed", revision, err)
		}
	}
	next := maintenanceStart(t, s, target, 2, endAt)
	if _, err = end(selection, next.Revision, 1); !errors.Is(err, ErrWindowsMaintenanceConflict) {
		t.Fatal("old window ID ended newer window", err)
	}
	states, err := s.WindowsMaintenance(ctx)
	if err != nil || len(states) != 2 || !reflect.DeepEqual(states[0], other) || !reflect.DeepEqual(states[1], next) || len(next.Windows) != 2 || !reflect.DeepEqual(next.Windows[1], v.Windows[0]) {
		t.Fatal("end changed another target or history", states, err)
	}
	after, err := s.WindowsIncidentSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("group early end changed incidents or acknowledgement", err)
	}
}

func TestFleetGroupMaintenanceEndReloadsGroupAfterOperatorSQLWait(t *testing.T) {
	for _, change := range []string{"revision", "membership", "identity", "manager", "deleted"} {
		t.Run(change, func(t *testing.T) {
			s := contactStore(t)
			ctx := context.Background()
			target := maintenanceFixtureTarget(1, "all")
			g, selection := groupMaintenanceSelection(t, s, target)
			original := maintenanceStart(t, s, target, 0, contactAt)
			conn, err := s.db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			waits := s.db.Stats().WaitCount
			result := make(chan error, 1)
			go func() {
				_, e := s.EndFleetGroupMaintenance(ctx, selection, target, 1, 1, func() time.Time { return contactAt.Add(time.Second) }, maintenanceGuard)
				result <- e
			}()
			until := time.Now().Add(5 * time.Second)
			for s.db.Stats().WaitCount == waits && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			if s.db.Stats().WaitCount == waits {
				conn.Close()
				t.Fatal("end did not wait for operator connection")
			}
			switch change {
			case "revision":
				g.Revision++
			case "membership":
				g.Members = []FleetGroupMember{}
			case "identity":
				g.Members[0].Identity = strings.Repeat("c", 64)
			case "manager":
				g.Manager = strings.Repeat("d", 64)
			}
			if change == "deleted" {
				_, err = conn.ExecContext(ctx, "DELETE FROM fleet_groups WHERE id=?", g.ID)
			} else {
				raw, _ := json.Marshal(g)
				_, err = conn.ExecContext(ctx, "UPDATE fleet_groups SET body=? WHERE id=?", raw, g.ID)
			}
			if err != nil {
				conn.Close()
				t.Fatal(err)
			}
			conn.Close()
			if err = <-result; !errors.Is(err, ErrWindowsMaintenanceConflict) {
				t.Fatal("stale group ended after SQL wait", err)
			}
			states, err := s.WindowsMaintenance(ctx)
			if err != nil || len(states) != 1 || !reflect.DeepEqual(states[0], original) {
				t.Fatal("failed group guard changed active window", err)
			}
		})
	}
}

func TestFleetGroupMaintenanceEndFinalGuardAndTimeRollback(t *testing.T) {
	for _, failure := range []string{"final-guard", "expired", "final-expiry", "rollback"} {
		t.Run(failure, func(t *testing.T) {
			s := contactStore(t)
			target := maintenanceFixtureTarget(1, "all")
			_, selection := groupMaintenanceSelection(t, s, target)
			original := maintenanceStart(t, s, target, 0, contactAt)
			reads, guards := 0, 0
			clock := func() time.Time {
				reads++
				if failure == "expired" || failure == "final-expiry" && reads == 3 {
					return original.Windows[0].EndsAt
				}
				if failure == "rollback" && reads == 3 {
					return contactAt
				}
				return contactAt.Add(time.Second)
			}
			guard := func(time.Time, time.Time) error {
				guards++
				if failure == "final-guard" && guards == 2 {
					return ErrWindowsMaintenanceConflict
				}
				return nil
			}
			if _, err := s.EndFleetGroupMaintenance(context.Background(), selection, target, 1, 1, clock, guard); !errors.Is(err, ErrWindowsMaintenanceConflict) {
				t.Fatal("failed end guard accepted", err)
			}
			states, err := s.WindowsMaintenance(context.Background())
			if err != nil || len(states) != 1 || !reflect.DeepEqual(states[0], original) {
				t.Fatal("failed end committed", states, err)
			}
		})
	}
}

func TestFleetGroupMaintenanceEndKeepsNotificationTruthAndNoBacklog(t *testing.T) {
	t.Run("queued", func(t *testing.T) {
		s := contactStore(t)
		configureAlarm(t, s, &alarmBinding)
		notificationEnable(t, s, "disk")
		capacityOpen(t, s)
		if notificationCounts(t, s).Queued != 1 {
			t.Fatal("fixture did not queue notification")
		}
		target := maintenanceFixtureTarget(1, "all")
		_, selection := groupMaintenanceSelection(t, s, target)
		start := contactAt.Add(61 * time.Second)
		original := maintenanceStart(t, s, target, 0, start)
		counts := notificationCounts(t, s)
		if counts.Queued != 0 || counts.Suppressed != 1 {
			t.Fatal("start did not consume queued work", counts)
		}
		_, err := s.EndFleetGroupMaintenance(context.Background(), selection, target, original.Revision, original.Windows[0].ID, func() time.Time { return start.Add(time.Second) }, maintenanceGuard)
		if err != nil || !reflect.DeepEqual(counts, notificationCounts(t, s)) || notificationClaim(t, s, capacityInput(1, 63, 95), start.Add(2*time.Second)) != nil {
			t.Fatal("group end restored consumed notification", err)
		}
	})
	for _, outcome := range []alarmdelivery.Outcome{alarmdelivery.Accepted, alarmdelivery.Uncertain, alarmdelivery.Retryable} {
		t.Run(string(outcome), func(t *testing.T) {
			s := contactStore(t)
			configureAlarm(t, s, &alarmBinding)
			notificationEnable(t, s, "disk")
			capacityOpen(t, s)
			a := notificationClaim(t, s, capacityInput(1, 60, 95), contactAt.Add(time.Minute))
			target := maintenanceFixtureTarget(1, "all")
			_, selection := groupMaintenanceSelection(t, s, target)
			before := capacityRaw(t, s, target.DeviceID)
			start := contactAt.Add(61 * time.Second)
			original := maintenanceStart(t, s, target, 0, start)
			counts := notificationCounts(t, s)
			_, err := s.EndFleetGroupMaintenance(context.Background(), selection, target, original.Revision, original.Windows[0].ID, func() time.Time { return start.Add(time.Second) }, maintenanceGuard)
			if err != nil || !bytes.Equal(before, capacityRaw(t, s, target.DeviceID)) || !reflect.DeepEqual(counts, notificationCounts(t, s)) {
				t.Fatal("group end changed evidence or inflight state", err)
			}
			notificationComplete(t, s, a, outcome, start.Add(2*time.Second))
			c := notificationCounts(t, s)
			if outcome == alarmdelivery.Accepted && c.ProviderAccepted != 1 || outcome == alarmdelivery.Uncertain && c.Uncertain != 1 || outcome == alarmdelivery.Retryable && c.Suppressed != 1 || c.Queued != 0 {
				t.Fatal("group end lost inflight truth or restored retry", c)
			}
			in := capacityInput(1, 180, 95)
			if _, err = s.EvaluateWindowsCapacity(context.Background(), in, in.ReceivedAt, contactEpoch); err != nil {
				t.Fatal(err)
			}
			if notificationClaim(t, s, in, in.ReceivedAt) != nil || notificationCounts(t, s).Queued != 0 {
				t.Fatal("group end released backlog")
			}
		})
	}
}
