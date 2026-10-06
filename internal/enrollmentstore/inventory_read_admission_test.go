package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// Actual maintenance holds the existing admission slot while waiting for the
// sole SQLite connection. Only synthetic rows and temporary stores are used.
func TestPackageMetadataReadWaitsBehindMaintenance(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := completeGeneration(t, snap.Approval.DeviceID, 1, 257, at)
	promoteComplete(t, s, snap, cert, b, m, chunks, at)
	held, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	before := s.db.Stats().WaitCount
	maintained := make(chan error, 1)
	go func() { _, err := s.MaintainInventoryStep(ctx, 0, at); maintained <- err }()
	for s.db.Stats().WaitCount == before {
		select {
		case <-ctx.Done():
			t.Fatal("maintenance did not queue")
		case <-time.After(time.Millisecond):
		}
	}
	type result struct {
		view InventoryStatus
		err  error
	}
	read := make(chan result, 1)
	copied := *s
	go func() { view, err := copied.InventoryView(ctx, snap.Approval.DeviceID, at); read <- result{view, err} }()
	waitSystemMetadataReader(t, s, ctx)
	if view, err := s.SystemView(ctx, snap.Approval.DeviceID, at); !errors.Is(err, ErrInventoryBusy) || !reflect.DeepEqual(view, SystemView{}) {
		t.Fatal("system reader exceeded shared waiter budget", err)
	}
	if view, err := s.InventoryView(ctx, snap.Approval.DeviceID, at); !errors.Is(err, ErrInventoryBusy) || !reflect.DeepEqual(view, InventoryStatus{}) {
		t.Fatal("package reader exceeded shared waiter budget", err)
	}
	select {
	case result := <-read:
		t.Fatal("package read did not wait", result.err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-maintained; err != nil {
		t.Fatal(err)
	}
	out := <-read
	if out.err != nil || out.view.Complete == nil || out.view.CompleteBinding != b || !out.view.Complete.Manifest.CollectedAt.Equal(at) || !out.view.Complete.CompletedAt.Equal(at) || !out.view.Complete.ExpiresAt.Equal(at.Add(inventoryledger.ObservationTTL)) {
		t.Fatal("authorized original package metadata lost", out.err)
	}
	if len(s.inventoryCalls) != 0 || len(s.systemMetadataReads) != 0 {
		t.Fatal("admission permit leaked")
	}
}

func TestPackageMetadataReadCancellationTimeoutAndSQLWait(t *testing.T) {
	for _, crossing := range []string{"cancel", "timeout", "sql_cancel"} {
		t.Run(crossing, func(t *testing.T) {
			_, s, _, snap, _ := completeFixture(t)
			defer s.Close()
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			var release func()
			if crossing == "sql_cancel" {
				held, err := s.db.Conn(ctx)
				if err != nil {
					t.Fatal(err)
				}
				release = func() { held.Close() }
			} else {
				var err error
				release, err = s.inventoryAdmission(ctx)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer release()
			readCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				view, err := s.InventoryView(readCtx, snap.Approval.DeviceID, time.Unix(testNow+10, 0).UTC())
				if !reflect.DeepEqual(view, InventoryStatus{}) {
					done <- ErrStorage
					return
				}
				done <- err
			}()
			waitSystemMetadataReader(t, s, ctx)
			want := error(context.Canceled)
			if crossing == "timeout" {
				want = ErrInventoryBusy
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatal("wrong bounded admission result", err)
				}
			case <-ctx.Done():
				t.Fatal("read did not stop")
			}
			if len(s.systemMetadataReads) != 0 || crossing == "sql_cancel" && len(s.inventoryCalls) != 0 {
				t.Fatal("canceled read retained permits")
			}
		})
	}
}

func TestPackageMetadataReadRechecksAuthorityAndOriginalExpiry(t *testing.T) {
	for _, boundary := range []string{"admission", "sql_wait", "commit", "output", "rollback"} {
		for _, horizon := range []string{"retention", "staging", "certificate"} {
			t.Run(boundary+"/"+horizon, func(t *testing.T) {
				_, s, _, snap, cert := systemLongFixture(t)
				defer s.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				at := time.Unix(testNow+10, 0).UTC()
				b, m, chunks := completeGeneration(t, snap.Approval.DeviceID, 1, 1, at)
				expiry := at.Add(inventoryledger.ObservationTTL)
				if horizon == "staging" {
					stageComplete(t, s, snap, cert, b, m, chunks, at)
					expiry = at.Add(inventoryledger.StagingTTL)
				} else {
					promoteComplete(t, s, snap, cert, b, m, chunks, at)
				}
				if horizon == "certificate" {
					expiry = time.Unix(snap.Intent.NotAfter, 0).UTC()
				}
				initial := expiry.Add(-time.Nanosecond)
				clock := &overviewFixtureClock{}
				clock.set(initial)
				var calls atomic.Int64
				now := clock.now
				if boundary == "commit" || boundary == "rollback" {
					now = func() time.Time {
						if calls.Add(1) > 1 {
							if boundary == "rollback" {
								return at
							}
							return expiry
						}
						return initial
					}
				}
				readCtx := WithSystemViewClock(ctx, now)
				var view InventoryStatus
				var err error
				call := func() error { view, err = s.InventoryView(readCtx, snap.Approval.DeviceID, initial); return err }
				switch boundary {
				case "admission":
					held, e := s.inventoryAdmission(ctx)
					if e != nil {
						t.Fatal(e)
					}
					done := make(chan error, 1)
					go func() { done <- call() }()
					waitSystemMetadataReader(t, s, ctx)
					if clock.calls.Load() != 0 {
						t.Fatal("clock sampled before admission")
					}
					clock.set(expiry)
					held()
					err = <-done
				case "sql_wait":
					err = afterOverviewConnectionWait(t, s, func() {
						if clock.calls.Load() != 0 {
							t.Error("clock sampled before SQL authority")
						}
						clock.set(expiry)
					}, call)
				default:
					err = call()
				}
				if boundary == "output" && err == nil {
					view, err = view.RecheckAt(expiry)
				}
				if horizon == "certificate" && boundary != "rollback" {
					if !errors.Is(err, enrollmentstate.ErrExpired) || !reflect.DeepEqual(view, InventoryStatus{}) {
						t.Fatal("expired authority escaped", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				observed := view.Complete
				if horizon == "staging" {
					observed = view.Transfer
				}
				want := "expired"
				if boundary == "rollback" && horizon == "staging" {
					want = "pending"
				} else if boundary == "rollback" && horizon == "retention" {
					want = "complete"
				}
				if observed == nil || observed.State != want || !observed.Manifest.CollectedAt.Equal(at) || !observed.StartedAt.Equal(at) {
					t.Fatal("original metadata or age lost")
				}
				if horizon == "retention" && (!observed.CompletedAt.Equal(at) || !observed.ExpiresAt.Equal(at.Add(inventoryledger.ObservationTTL))) {
					t.Fatal("read refreshed completion or retention")
				}
				if boundary == "rollback" {
					if !view.ServerNow.Equal(initial) {
						t.Fatal("clock rollback moved output backward")
					}
					return
				}
				if !view.ServerNow.Equal(expiry) {
					t.Fatal("stale output clock")
				}
			})
		}
	}
}

func TestPackageMetadataQueuedReadObservesRevocation(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := completeGeneration(t, snap.Approval.DeviceID, 1, 1, at)
	promoteComplete(t, s, snap, cert, b, m, chunks, at)
	held, err := s.inventoryAdmission(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		v, e := s.InventoryView(WithSystemViewClock(ctx, func() time.Time { return at.Add(2 * time.Second) }), snap.Approval.DeviceID, at)
		if !reflect.DeepEqual(v, InventoryStatus{}) {
			done <- ErrStorage
			return
		}
		done <- e
	}()
	waitSystemMetadataReader(t, s, ctx)
	command := control(snap, 50)
	command.Now = at.Add(time.Second).Unix()
	if _, err := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: command, State: enrollmentstate.Revoked}); err != nil {
		held()
		t.Fatal(err)
	}
	held()
	if err := <-done; !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal("queued read used old authority", err)
	}
}
