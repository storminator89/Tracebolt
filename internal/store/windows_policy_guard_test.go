package store

import (
	"context"
	"errors"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsresource"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestWindowsPercentagePolicyFinalGuardPreservesState(t *testing.T) {
	for _, metric := range []string{"disk", "cpu", "memory"} {
		t.Run(metric, func(t *testing.T) {
			s, err := Open(filepath.Join(t.TempDir(), "guard.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx := context.Background()
			in := capacityInput(1, 0, 95)
			for _, rejectAt := range []int{1, 2} {
				calls := 0
				guard := func() error {
					calls++
					if calls == rejectAt {
						return windowscapacity.ErrInvalid
					}
					return nil
				}
				if metric == "disk" {
					_, err = s.ConfigureWindowsCapacity(ctx, in, true, 90, 0, contactAt, guard)
				} else {
					_, err = s.ConfigureWindowsResource(ctx, in, windowsresource.Kind(metric), true, 90, 0, contactAt, guard)
				}
				if !errors.Is(err, windowscapacity.ErrInvalid) || calls != rejectAt {
					t.Fatal("guard not used at transaction boundary", err, calls)
				}
				disks, e := s.WindowsCapacityStates(ctx)
				if e != nil || len(disks) != 0 {
					t.Fatal("failed guard persisted disk")
				}
				resources, e := s.WindowsResourceStates(ctx)
				if e != nil || len(resources) != 0 {
					t.Fatal("failed guard persisted resources")
				}
			}
		})
	}
}

func TestWindowsPercentagePolicyGuardAfterConnectionWait(t *testing.T) {
	for _, metric := range []string{"disk", "cpu", "memory"} {
		t.Run(metric, func(t *testing.T) {
			s, err := Open(filepath.Join(t.TempDir(), "wait.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			connection, err := s.db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			var live atomic.Bool
			live.Store(true)
			var calls atomic.Int32
			guard := func() error {
				calls.Add(1)
				if !live.Load() {
					return windowscapacity.ErrInvalid
				}
				return nil
			}
			before := s.db.Stats().WaitCount
			done := make(chan error, 1)
			in := capacityInput(1, 0, 95)
			go func() {
				var e error
				if metric == "disk" {
					_, e = s.ConfigureWindowsCapacity(ctx, in, true, 90, 0, contactAt, guard)
				} else {
					_, e = s.ConfigureWindowsResource(ctx, in, windowsresource.Kind(metric), true, 90, 0, contactAt, guard)
				}
				done <- e
			}()
			for s.db.Stats().WaitCount == before && ctx.Err() == nil {
				time.Sleep(time.Millisecond)
			}
			if ctx.Err() != nil || calls.Load() != 0 {
				t.Fatal("fixture did not block before guard")
			}
			live.Store(false)
			if err = connection.Close(); err != nil {
				t.Fatal(err)
			}
			if err = <-done; !errors.Is(err, windowscapacity.ErrInvalid) {
				t.Fatal("stale authority survived connection wait", err)
			}
			disks, _ := s.WindowsCapacityStates(ctx)
			resources, _ := s.WindowsResourceStates(ctx)
			if len(disks) != 0 || len(resources) != 0 {
				t.Fatal("expired authority changed state")
			}
		})
	}
}
