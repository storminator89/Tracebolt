package main

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstore"
	"testing"
	"time"
)

func TestWindowsEventMaintenanceBoundsAndWarningThrottle(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	offsets := []time.Duration{0, 59 * time.Second, time.Minute, -time.Second, 2 * time.Minute, 3 * time.Minute}
	ticks := make(chan time.Time, len(offsets))
	for range offsets {
		ticks <- base.Add(24 * time.Hour)
	}
	close(ticks)
	index, warnings := 0, 0
	var contexts []context.Context
	err := windowsEventMaintenanceLoop(context.Background(), func(ctx context.Context, at time.Time) error {
		contexts = append(contexts, ctx)
		if !at.Equal(base.Add(offsets[index])) {
			t.Fatal("used ticker timestamp instead of fresh authority clock")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 500*time.Millisecond {
			t.Fatal("maintenance step lacks bounded context")
		}
		index++
		if index == 5 {
			return enrollmentstore.ErrBusy
		}
		if index == 6 {
			return nil
		}
		return errors.New("synthetic failure must not reach warning output")
	}, func() time.Time { return base.Add(offsets[index]) }, ticks, func() { warnings++ })
	if err != nil || index != len(offsets) || warnings != 3 {
		t.Fatal("maintenance scheduling or finite warning throttle changed", err, index, warnings)
	}
	for _, ctx := range contexts {
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("step context retained after cleanup")
		}
	}
}

func TestWindowsEventMaintenanceCancellationAndInvalidConfiguration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time, 2)
	ticks <- time.Now()
	ticks <- time.Now()
	calls, warnings := 0, 0
	err := windowsEventMaintenanceLoop(ctx, func(step context.Context, _ time.Time) error {
		calls++
		cancel()
		if !errors.Is(step.Err(), context.Canceled) {
			t.Fatal("parent cancellation not propagated")
		}
		return errors.New("shutdown")
	}, time.Now, ticks, func() { warnings++ })
	if err != nil || calls != 1 || warnings != 0 {
		t.Fatal("shutdown did not synchronously stop maintenance", err, calls, warnings)
	}
	if err := runWindowsEventMaintenance(context.Background(), nil, nil); !errors.Is(err, enrollmentservice.ErrConfiguration) {
		t.Fatal("nil service accepted")
	}
	noop := func(context.Context, time.Time) error { return nil }
	for _, err := range []error{
		windowsEventMaintenanceLoop(nil, noop, time.Now, ticks, nil),
		windowsEventMaintenanceLoop(context.Background(), nil, time.Now, ticks, nil),
		windowsEventMaintenanceLoop(context.Background(), noop, nil, ticks, nil),
		windowsEventMaintenanceLoop(context.Background(), noop, time.Now, nil, nil),
	} {
		if !errors.Is(err, enrollmentservice.ErrConfiguration) {
			t.Fatal("invalid loop configuration accepted")
		}
	}
}
