package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"localrmm/internal/alarmdelivery"
)

func groupMaintenanceSelection(t *testing.T, s *Store, target WindowsMaintenanceTarget) (FleetGroup, FleetGroupMaintenanceSelection) {
	t.Helper()
	selection := FleetGroupMaintenanceSelection{Manager: strings.Repeat("a", 64), GroupID: "group_" + strings.Repeat("1", 32), GroupRevision: 1, Identity: strings.Repeat("b", 64)}
	g, err := s.SaveFleetGroup(context.Background(), selection.Manager, selection.GroupID, "Office", []FleetGroupMember{{DeviceID: target.DeviceID, Identity: selection.Identity}}, 0, false, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return g, selection
}

func TestFleetGroupMaintenanceExactMembershipAndUnchangedStartSemantics(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	target := maintenanceFixtureTarget(1, "disk")
	g, selection := groupMaintenanceSelection(t, s, target)
	start := func(selection FleetGroupMaintenanceSelection, target WindowsMaintenanceTarget, revision uint64, ends time.Time) (WindowsMaintenanceState, error) {
		return s.StartFleetGroupMaintenance(ctx, selection, target, revision, ends, "planned-work", func() time.Time { return contactAt }, maintenanceGuard)
	}
	for _, change := range []string{"manager", "group", "revision", "identity", "device"} {
		bad, badTarget := selection, target
		switch change {
		case "manager":
			bad.Manager = strings.Repeat("c", 64)
		case "group":
			bad.GroupID = "group_" + strings.Repeat("2", 32)
		case "revision":
			bad.GroupRevision++
		case "identity":
			bad.Identity = strings.Repeat("d", 64)
		case "device":
			badTarget = maintenanceFixtureTarget(2, "disk")
		}
		if _, err := start(bad, badTarget, 0, contactAt.Add(time.Hour)); !errors.Is(err, ErrWindowsMaintenanceConflict) {
			t.Fatal("unreviewed group selection accepted", change, err)
		}
	}
	for _, ends := range []time.Time{contactAt.Add(59 * time.Second), contactAt.Add(24*time.Hour + time.Second)} {
		if _, err := start(selection, target, 0, ends); !errors.Is(err, ErrWindowsMaintenanceConflict) {
			t.Fatal("group route relaxed duration", err)
		}
	}
	v, err := start(selection, target, 0, contactAt.Add(time.Hour))
	if err != nil || v.Revision != 1 || !v.Windows[0].Active(contactAt) {
		t.Fatal("exact group start failed", v, err)
	}
	for _, conflicting := range []WindowsMaintenanceTarget{target, maintenanceFixtureTarget(1, "all")} {
		if _, err = start(selection, conflicting, 0, contactAt.Add(2*time.Hour)); !errors.Is(err, ErrWindowsMaintenanceConflict) {
			t.Fatal("group start bypassed overlap/replay", err)
		}
	}
	if _, err = start(selection, maintenanceFixtureTarget(1, "cpu"), 0, contactAt.Add(time.Hour)); err != nil {
		t.Fatal("independent domain rejected", err)
	}
	if _, err = s.SaveFleetGroup(ctx, g.Manager, g.ID, g.Name, nil, g.Revision, true, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = start(selection, maintenanceFixtureTarget(1, "memory"), 0, contactAt.Add(time.Hour)); !errors.Is(err, ErrWindowsMaintenanceConflict) {
		t.Fatal("deleted group retained authority", err)
	}
	// Deleting the organizational selection does not end a confirmed window.
	states, err := s.WindowsMaintenance(ctx)
	if err != nil || len(states) != 2 || !states[0].Windows[0].Active(contactAt) {
		t.Fatal("group deletion mutated maintenance", err)
	}
}

func TestFleetGroupMaintenanceReloadsGroupAfterOperatorSQLWait(t *testing.T) {
	for _, change := range []string{"revision", "membership", "identity", "manager", "deleted"} {
		t.Run(change, func(t *testing.T) {
			s := contactStore(t)
			ctx := context.Background()
			target := maintenanceFixtureTarget(1, "all")
			g, selection := groupMaintenanceSelection(t, s, target)
			conn, err := s.db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			waits := s.db.Stats().WaitCount
			result := make(chan error, 1)
			go func() {
				_, e := s.StartFleetGroupMaintenance(ctx, selection, target, 0, contactAt.Add(time.Hour), "other", func() time.Time { return contactAt }, maintenanceGuard)
				result <- e
			}()
			until := time.Now().Add(5 * time.Second)
			for s.db.Stats().WaitCount == waits && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			if s.db.Stats().WaitCount == waits {
				conn.Close()
				t.Fatal("start did not wait for operator connection")
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
				t.Fatal("stale group committed after SQL wait", err)
			}
			states, err := s.WindowsMaintenance(ctx)
			if err != nil || len(states) != 0 {
				t.Fatal("failed group guard wrote maintenance", err)
			}
		})
	}
}

func TestFleetGroupMaintenanceFinalGuardRollsBackAndExpiryStaysReadOnly(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	target := maintenanceFixtureTarget(1, "all")
	_, selection := groupMaintenanceSelection(t, s, target)
	calls := 0
	guard := func(time.Time, time.Time) error {
		calls++
		if calls == 2 {
			return ErrWindowsMaintenanceConflict
		}
		return nil
	}
	if _, err := s.StartFleetGroupMaintenance(ctx, selection, target, 0, contactAt.Add(time.Hour), "other", func() time.Time { return contactAt }, guard); !errors.Is(err, ErrWindowsMaintenanceConflict) {
		t.Fatal("final guard ignored", err)
	}
	states, err := s.WindowsMaintenance(ctx)
	if err != nil || len(states) != 0 {
		t.Fatal("failed final guard wrote metadata", err)
	}
	v, err := s.StartFleetGroupMaintenance(ctx, selection, target, 0, contactAt.Add(time.Hour), "other", func() time.Time { return contactAt }, maintenanceGuard)
	if err != nil {
		t.Fatal(err)
	}
	states, err = s.WindowsMaintenance(ctx)
	if err != nil || states[0].Windows[0].Active(contactAt.Add(time.Hour)) || !states[0].Windows[0].EndsAt.Equal(v.Windows[0].EndsAt) || states[0].Revision != v.Revision {
		t.Fatal("expiry changed original window", err)
	}
}

func TestFleetGroupMaintenanceNotificationSuppressionKeepsInflightTruthAndNoBacklog(t *testing.T) {
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
			_, err := s.StartFleetGroupMaintenance(context.Background(), selection, target, 0, start.Add(time.Minute), "planned-work", func() time.Time { return start }, maintenanceGuard)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, capacityRaw(t, s, target.DeviceID)) || notificationCounts(t, s).InFlight != 1 {
				t.Fatal("group start changed evidence or claimed inflight cancellation")
			}
			notificationComplete(t, s, a, outcome, start.Add(2*time.Second))
			c := notificationCounts(t, s)
			if outcome == alarmdelivery.Accepted && c.ProviderAccepted != 1 || outcome == alarmdelivery.Uncertain && c.Uncertain != 1 || outcome == alarmdelivery.Retryable && c.Suppressed != 1 || c.Queued != 0 {
				t.Fatal("group start hid inflight truth", c)
			}
			in := capacityInput(1, 180, 95)
			if _, err = s.EvaluateWindowsCapacity(context.Background(), in, in.ReceivedAt, contactEpoch); err != nil {
				t.Fatal(err)
			}
			if notificationClaim(t, s, in, in.ReceivedAt) != nil || notificationCounts(t, s).Queued != 0 {
				t.Fatal("group window expiry released backlog")
			}
		})
	}
}
