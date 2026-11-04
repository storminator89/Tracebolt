package store

import (
	"context"
	"errors"
	"localrmm/internal/linuxmountwatch"
	"strings"
	"testing"
	"time"
)

func mountFixture(t *testing.T) (*Store, string, linuxmountwatch.Input, linuxmountwatch.Command) {
	s, path := alarmStore(t)
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	target := linuxmountwatch.Target{MountPoint: "/var", Filesystem: "ext4", FilesystemGroup: "fs_8_1"}
	in := linuxmountwatch.Input{DeviceID: "agent_" + strings.Repeat("a", 32), Identity: strings.Repeat("b", 64), SourceToken: "mountsource_" + strings.Repeat("c", 32), AuthorityUntil: at.Add(time.Hour), Available: true, Reason: "none", Generation: &linuxmountwatch.Generation{Sequence: 1, ID: "sample_" + strings.Repeat("d", 32), CapturedAt: at, ReceivedAt: at}, Sample: &linuxmountwatch.Sample{Target: target, MountID: "mount_3", UsedPercent: 95, TotalBytes: 1000, AvailableBytes: 50}}
	command := linuxmountwatch.Command{RequestID: "mountrequest_" + strings.Repeat("e", 32), SourceToken: in.SourceToken, Operation: "enable", Target: &target, Threshold: 90, Recovery: 80, RetentionAcknowledged: true}
	return s, path, in, command
}
func TestLinuxMountWatchStoreRestartAndDefaultOff(t *testing.T) {
	s, path, in, c := mountFixture(t)
	ctx := context.Background()
	now := in.Generation.CapturedAt
	clock := func() time.Time { return now }
	guard := func(time.Time) error { return nil }
	state, e := s.LinuxMountWatchState(ctx, in.DeviceID)
	if e != nil || state.Policy.Enabled {
		t.Fatal(e)
	}
	_, _, e = s.UpdateLinuxMountWatches(ctx, in, nil, true, clock, guard)
	if e != nil {
		t.Fatal(e)
	}
	var n int
	_ = s.db.QueryRow(`SELECT count(*) FROM linux_mount_watches`).Scan(&n)
	if n != 0 {
		t.Fatal("default evaluation created policy")
	}
	state, _, e = s.UpdateLinuxMountWatches(ctx, in, &c, false, clock, guard)
	if e != nil || state.Revision != 1 {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	state, e = s.LinuxMountWatchState(ctx, in.DeviceID)
	if e != nil || state.Revision != 1 || !state.Policy.Enabled {
		t.Fatal(e)
	}
	state, _, e = s.UpdateLinuxMountWatches(ctx, in, &c, false, clock, guard)
	if e != nil || state.Revision != 1 {
		t.Fatal("replay", e)
	}
}
func TestLinuxMountWatchStoreFinalLeaseAndMissingMarker(t *testing.T) {
	s, _, in, c := mountFixture(t)
	ctx := context.Background()
	now := in.Generation.CapturedAt
	n := 0
	_, _, e := s.UpdateLinuxMountWatches(ctx, in, &c, false, func() time.Time { return now }, func(time.Time) error {
		n++
		if n >= 3 {
			return errors.New("lease ended")
		}
		return nil
	})
	if e == nil {
		t.Fatal("expired final lease committed")
	}
	state, e := s.LinuxMountWatchState(ctx, in.DeviceID)
	if e != nil || state.Revision != 0 {
		t.Fatal("failed lease changed state")
	}
	_, _, e = s.UpdateLinuxMountWatches(ctx, in, &c, false, func() time.Time { return now }, func(time.Time) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.db.Exec(`DELETE FROM linux_mount_watch_markers`)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.LinuxMountWatchState(ctx, in.DeviceID); !errors.Is(e, ErrLinuxMountWatchUnavailable) {
		t.Fatal("missing marker recreated", e)
	}
}

func TestLinuxMountWatchRestartAndFailedDowngradeResetConfidence(t *testing.T) {
	s, path, in, c := mountFixture(t)
	ctx := context.Background()
	now := in.Generation.CapturedAt
	clock := func() time.Time { return now }
	guard := func(time.Time) error { return nil }
	if _, _, e := s.UpdateLinuxMountWatches(ctx, in, &c, false, clock, guard); e != nil {
		t.Fatal(e)
	}
	now = now.Add(30 * time.Second)
	in.Generation = &linuxmountwatch.Generation{Sequence: 2, ID: "sample_" + strings.Repeat("2", 32), CapturedAt: now, ReceivedAt: now}
	state, _, e := s.UpdateLinuxMountWatches(ctx, in, nil, true, clock, guard)
	if e != nil || state.Check.Bad != 1 {
		t.Fatal("not pending", e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if e = s.InterruptLinuxMountWatch(canceled, in.DeviceID); e == nil || !s.linuxMountWatchBlocked.Load() {
		t.Fatal("failed downgrade did not block")
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now = now.Add(30 * time.Second)
	in.Generation = &linuxmountwatch.Generation{Sequence: 3, ID: "sample_" + strings.Repeat("3", 32), CapturedAt: now, ReceivedAt: now}
	state, _, e = s.UpdateLinuxMountWatches(ctx, in, nil, true, clock, guard)
	if e != nil || state.Check.Bad != 1 || len(state.Incidents) != 0 {
		t.Fatal("restart resumed unreset confidence", e)
	}
}
