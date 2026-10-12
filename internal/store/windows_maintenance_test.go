package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func maintenanceFixtureTarget(n int, domain string) WindowsMaintenanceTarget {
	in := contactInput(n)
	return WindowsMaintenanceTarget{in.DeviceID, in.InvitationID, in.CertificateHash, domain}
}
func maintenanceGuard(time.Time, time.Time) error { return nil }
func maintenanceStart(t *testing.T, s *Store, target WindowsMaintenanceTarget, revision uint64, now time.Time) WindowsMaintenanceState {
	t.Helper()
	v, err := s.ChangeWindowsMaintenance(context.Background(), target, revision, now.Add(time.Hour), "planned-work", 0, func() time.Time { return now }, maintenanceGuard)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestWindowsMaintenanceHistoryRevisionIsolationAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "maintenance.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	capacityOpen(t, s)
	before, err := s.WindowsIncidentSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	target := maintenanceFixtureTarget(1, "disk")
	now := contactAt.Add(5 * time.Minute)
	v := maintenanceStart(t, s, target, 0, now)
	if v.Revision != 1 || v.Windows[0].ID != 1 || !v.Windows[0].Active(now) {
		t.Fatal(v)
	}
	if _, err = s.ChangeWindowsMaintenance(ctx, target, 0, now.Add(2*time.Hour), "planned-work", 0, func() time.Time { return now }, maintenanceGuard); !errors.Is(err, ErrWindowsMaintenanceConflict) {
		t.Fatal("uncertain retry extended or recreated window", err)
	}
	end := now.Add(time.Minute)
	v, err = s.ChangeWindowsMaintenance(ctx, target, 1, time.Time{}, "", 1, func() time.Time { return end }, maintenanceGuard)
	if err != nil || v.Revision != 2 || v.Windows[0].EndedAt == nil || v.Windows[0].Active(now) || !v.Windows[0].EndsAt.Equal(now.Add(time.Hour)) {
		t.Fatal("early end changed original end or resurrected", v, err)
	}
	for i := 0; i < 5; i++ {
		now = now.Add(2 * time.Hour)
		v = maintenanceStart(t, s, target, v.Revision, now)
	}
	if len(v.Windows) != MaxWindowsMaintenanceHistory || v.Revision != 7 || v.Windows[0].ID != 7 {
		t.Fatal("history/revision bound", v)
	}
	after, err := s.WindowsIncidentSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("maintenance changed source history or acknowledgement", err)
	}
	for _, table := range []string{"health_devices", "health_analyses", "alarm_outbox"} {
		var count int
		if err = s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatal("maintenance entered Linux/AI/alarm domain", table, err)
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := s.WindowsMaintenance(ctx)
	if err != nil || len(loaded) != 1 || !reflect.DeepEqual(loaded[0], v) || !loaded[0].Windows[0].Active(now) {
		t.Fatal("normal restart lost window/history", err)
	}
}

func TestWindowsMaintenanceScopeOverlapIdentityAndNoEvidenceRequired(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	now := contactAt
	disk := maintenanceFixtureTarget(1, "disk")
	maintenanceStart(t, s, disk, 0, now)
	maintenanceStart(t, s, maintenanceFixtureTarget(1, "cpu"), 0, now)
	maintenanceStart(t, s, maintenanceFixtureTarget(2, "all"), 0, now)
	for _, target := range []WindowsMaintenanceTarget{disk, maintenanceFixtureTarget(1, "all"), maintenanceFixtureTarget(2, "service")} {
		if _, err := s.ChangeWindowsMaintenance(ctx, target, 0, now.Add(time.Hour), "other", 0, func() time.Time { return now }, maintenanceGuard); !errors.Is(err, ErrWindowsMaintenanceConflict) {
			t.Fatal("overlap accepted", target, err)
		}
	}
	// An explicitly approved replacement starts from revision zero and cannot
	// inherit metadata or the old history even when the display device ID is reused.
	replacement := disk
	replacement.InvitationID = "invite_" + strings.Repeat("a", 32)
	replacement.CertificateHash = strings.Repeat("b", 64)
	if replacement.Key() == disk.Key() {
		t.Fatal("identity key collision")
	}
	v := maintenanceStart(t, s, replacement, 0, now)
	if len(v.Windows) != 1 || v.Target != replacement || v.Revision != 1 {
		t.Fatal("replacement inherited metadata")
	}
	// Reads never create policy/evidence state just to offer maintenance.
	incidents, err := s.WindowsIncidentSnapshot(ctx)
	if err != nil || len(incidents.Targets()) != 0 {
		t.Fatal("maintenance created source incidents", err)
	}
}

func TestWindowsMaintenanceBoundsCorruptionAndReadOnlyExpiry(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	target := maintenanceFixtureTarget(1, "all")
	for _, duration := range []time.Duration{0, time.Minute - time.Nanosecond, 24*time.Hour + time.Nanosecond} {
		if _, err := s.ChangeWindowsMaintenance(ctx, target, 0, contactAt.Add(duration), "other", 0, func() time.Time { return contactAt }, maintenanceGuard); !errors.Is(err, ErrWindowsMaintenanceConflict) {
			t.Fatal("unbounded end accepted", duration, err)
		}
	}
	for _, intent := range []string{"", "autofix", "planned-work "} {
		if _, err := s.ChangeWindowsMaintenance(ctx, target, 0, contactAt.Add(time.Hour), intent, 0, func() time.Time { return contactAt }, maintenanceGuard); !errors.Is(err, ErrWindowsMaintenance) {
			t.Fatal("invalid intent accepted", err)
		}
	}
	v := maintenanceStart(t, s, target, 0, contactAt)
	var before, after []byte
	s.db.QueryRow("SELECT body FROM windows_maintenance").Scan(&before)
	for _, at := range []time.Time{contactAt.Add(-time.Second), v.Windows[0].EndsAt, v.Windows[0].EndsAt.Add(time.Second)} {
		if v.Windows[0].Active(at) {
			t.Fatal("outside original interval active")
		}
		if _, err := s.ChangeWindowsMaintenance(ctx, target, 1, time.Time{}, "", 1, func() time.Time { return at }, maintenanceGuard); !errors.Is(err, ErrWindowsMaintenanceConflict) {
			t.Fatal("clock rollback/expired window ended", err)
		}
	}
	if _, err := s.WindowsMaintenance(ctx); err != nil {
		t.Fatal(err)
	}
	s.db.QueryRow("SELECT body FROM windows_maintenance").Scan(&after)
	if !bytes.Equal(before, after) {
		t.Fatal("read/failed write mutated expiry")
	}
	if _, err := s.db.Exec("UPDATE windows_maintenance SET body=body||' '"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WindowsMaintenance(ctx); !errors.Is(err, ErrWindowsMaintenance) {
		t.Fatal("noncanonical state accepted", err)
	}
	if _, err := s.ChangeWindowsMaintenance(ctx, target, 1, time.Time{}, "", 1, func() time.Time { return contactAt }, maintenanceGuard); !errors.Is(err, ErrWindowsMaintenance) {
		t.Fatal("corruption repaired by write", err)
	}
}

func TestWindowsMaintenanceCapacityNeverEvictsUnavailableHistory(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	for i := 1; i <= MaxWindowsMaintenanceTargets; i++ {
		target := maintenanceFixtureTarget(i, "all")
		state := WindowsMaintenanceState{Version: 1, Target: target, Revision: 1, ChangedAt: contactAt, Windows: []WindowsMaintenanceWindow{{ID: 1, StartedAt: contactAt, EndsAt: contactAt.Add(time.Hour), Intent: "other"}}}
		raw, _ := json.Marshal(state)
		if _, err := s.db.Exec("INSERT INTO windows_maintenance(id,domain,body) VALUES(?,?,?)", target.DeviceID, target.Domain, raw); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ChangeWindowsMaintenance(ctx, maintenanceFixtureTarget(151, "all"), 0, contactAt.Add(time.Hour), "other", 0, func() time.Time { return contactAt }, maintenanceGuard); !errors.Is(err, ErrLimit) {
		t.Fatal("capacity evicted unrelated history", err)
	}
	v, err := s.WindowsMaintenance(ctx)
	if err != nil || len(v) != MaxWindowsMaintenanceTargets {
		t.Fatal("capacity changed", err)
	}
	// Existing exact targets can still be ended at capacity.
	if _, err = s.ChangeWindowsMaintenance(ctx, maintenanceFixtureTarget(1, "all"), 1, time.Time{}, "", 1, func() time.Time { return contactAt }, maintenanceGuard); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsMaintenanceTransactionWaitAndFinalGuard(t *testing.T) {
	for _, phase := range []string{"sql-wait", "final-guard", "final-clock", "end-expiry"} {
		t.Run(phase, func(t *testing.T) {
			s := contactStore(t)
			ctx := context.Background()
			target := maintenanceFixtureTarget(1, "disk")
			var blocked atomic.Bool
			calls := 0
			clock := func() time.Time {
				calls++
				if phase == "final-clock" && calls >= 3 {
					return contactAt.Add(-time.Second)
				}
				return contactAt
			}
			guards := 0
			guard := func(sampled, deadline time.Time) error {
				guards++
				if blocked.Load() || phase == "final-guard" && guards == 2 || phase == "end-expiry" && !deadline.IsZero() && guards == 2 {
					return ErrWindowsMaintenanceConflict
				}
				return nil
			}
			expected, endID := uint64(0), uint64(0)
			ends, intent := contactAt.Add(time.Hour), "other"
			if phase == "end-expiry" {
				maintenanceStart(t, s, target, 0, contactAt)
				expected, endID, ends, intent = 1, 1, time.Time{}, ""
			}
			var err error
			if phase == "sql-wait" {
				conn, e := s.db.Conn(ctx)
				if e != nil {
					t.Fatal(e)
				}
				waits := s.db.Stats().WaitCount
				result := make(chan error, 1)
				go func() {
					_, e := s.ChangeWindowsMaintenance(ctx, target, expected, ends, intent, endID, clock, guard)
					result <- e
				}()
				until := time.Now().Add(5 * time.Second)
				for s.db.Stats().WaitCount == waits && time.Now().Before(until) {
					time.Sleep(time.Millisecond)
				}
				if s.db.Stats().WaitCount == waits {
					conn.Close()
					t.Fatal("mutation did not wait for SQLite")
				}
				blocked.Store(true)
				conn.Close()
				err = <-result
			} else {
				_, err = s.ChangeWindowsMaintenance(ctx, target, expected, ends, intent, endID, clock, guard)
			}
			if !errors.Is(err, ErrWindowsMaintenanceConflict) {
				t.Fatal("failed guard committed", err)
			}
			states, err := s.WindowsMaintenance(ctx)
			if err != nil || phase != "end-expiry" && len(states) != 0 || phase == "end-expiry" && (len(states) != 1 || states[0].Revision != 1 || states[0].Windows[0].EndedAt != nil) {
				t.Fatal("failed transaction changed state", fmt.Sprint(states), err)
			}
		})
	}
}

func TestWindowsMaintenanceCanceledSQLWaitReturnsWithoutCommit(t *testing.T) {
	s := contactStore(t)
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	returned := make(chan error, 1)
	go func() {
		_, e := s.ChangeWindowsMaintenance(ctx, maintenanceFixtureTarget(1, "all"), 0, contactAt.Add(time.Hour), "other", 0, func() time.Time { return contactAt }, maintenanceGuard)
		returned <- e
	}()
	select {
	case err = <-returned:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("SQL wait did not honor request cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled metadata wait retained the caller's authority lease")
	}
	conn.Close()
	states, err := s.WindowsMaintenance(context.Background())
	if err != nil || len(states) != 0 {
		t.Fatal("canceled wait committed metadata", err)
	}
}
