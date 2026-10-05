package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// A held ordinary DB read makes periodic maintenance reserve inventory admission
// before it can do any work. A normal metadata read must get the released slot,
// rather than depending on the phase of a later HTTP retry.
func TestSystemMetadataReadWaitsBehindMaintenance(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	at := time.Unix(testNow+10, 0).UTC()
	raw := systemRaw(t, 1, systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 1, at))
	if _, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at); err != nil {
		t.Fatal("seed")
	}
	held, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal("hold")
	}
	defer held.Close()
	before := s.db.Stats().WaitCount
	maintained := make(chan error, 1)
	go func() { _, err := s.MaintainInventoryStep(ctx, 0, at); maintained <- err }()
	for s.db.Stats().WaitCount == before {
		select {
		case <-ctx.Done():
			t.Fatal("maintenance did not wait")
		case <-time.After(time.Millisecond):
		}
	}
	type result struct {
		view SystemView
		err  error
	}
	read := make(chan result, 1)
	go func() { view, err := s.SystemView(ctx, snap.Approval.DeviceID, at); read <- result{view, err} }()
	select {
	case result := <-read:
		t.Fatalf("metadata read failed instead of waiting for bounded maintenance: %v", result.err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := held.Close(); err != nil {
		t.Fatal("release")
	}
	if err := <-maintained; err != nil {
		t.Fatal("maintenance")
	}
	select {
	case result := <-read:
		if result.err != nil || result.view.Status != "fresh" || result.view.Sequence == nil || *result.view.Sequence != 1 || result.view.Latest == nil || !result.view.Latest.CollectedAt.Equal(at) {
			t.Fatal("authorized original observation lost", result.err)
		}
	case <-ctx.Done():
		t.Fatal("metadata read did not resume")
	}
}

func waitSystemMetadataReader(t *testing.T, s *Store, ctx context.Context) {
	t.Helper()
	for len(s.systemMetadataReads) == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("reader did not enter bounded admission")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestSystemMetadataAdmissionIsSingleSharedWaiterAndHandsOff(t *testing.T) {
	_, s, _, snap, _ := completeFixture(t)
	copied := *s
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	held, err := s.inventoryAdmission(ctx)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(testNow+10, 0).UTC()
	done := make(chan error, 1)
	go func() {
		view, err := copied.SystemView(ctx, snap.Approval.DeviceID, at)
		if err == nil && view.Status != "awaiting" {
			err = ErrStorage
		}
		done <- err
	}()
	waitSystemMetadataReader(t, s, ctx)
	if view, err := s.SystemView(ctx, snap.Approval.DeviceID, at); !errors.Is(err, ErrInventoryBusy) || !reflect.DeepEqual(view, SystemView{}) {
		t.Fatal("excess read entered queue", err)
	}
	if release, err := s.inventoryAdmission(ctx); !errors.Is(err, ErrInventoryBusy) || release != nil {
		t.Fatal("second active inventory operation admitted")
	}
	// The registered reader takes the existing slot as soon as it is released.
	held()
	if err := <-done; err != nil {
		t.Fatal("read did not take released slot", err)
	}
	if len(s.systemMetadataReads) != 0 || len(s.inventoryCalls) != 0 {
		t.Fatal("read admission leaked")
	}
	if _, err := s.SystemView(ctx, snap.Approval.DeviceID, at); err != nil {
		t.Fatal("later read did not recover", err)
	}
}

func TestSystemMetadataAdmissionCancellationAndTimeout(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "wait_budget"} {
		t.Run(mode, func(t *testing.T) {
			_, s, _, snap, _ := completeFixture(t)
			held, err := s.inventoryAdmission(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer held()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 25*time.Millisecond)
				defer stop()
			}
			at := time.Unix(testNow+10, 0).UTC()
			type outcome struct {
				view SystemView
				err  error
			}
			done := make(chan outcome, 1)
			started := time.Now()
			go func() { view, err := s.SystemView(ctx, snap.Approval.DeviceID, at); done <- outcome{view, err} }()
			if mode == "cancel" {
				waitSystemMetadataReader(t, s, ctx)
				cancel()
			}
			select {
			case out := <-done:
				want := error(ErrInventoryBusy)
				if mode == "cancel" {
					want = context.Canceled
				}
				if mode == "deadline" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(out.err, want) || !reflect.DeepEqual(out.view, SystemView{}) {
					t.Fatal("wrong admission result", out.err)
				}
				if mode == "wait_budget" && time.Since(started) < systemMetadataAdmissionWait {
					t.Fatal("wait budget was bypassed")
				}
				if len(s.systemMetadataReads) != 0 || len(s.inventoryCalls) != 1 {
					t.Fatal("waiter leaked or released another operation")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("admission wait did not stop")
			}
		})
	}
}

func TestSystemMetadataWaitKeepsAuthorityAndOriginalAge(t *testing.T) {
	for _, crossing := range []string{"freshness", "retention", "certificate", "revocation"} {
		t.Run(crossing, func(t *testing.T) {
			_, s, _, snap, cert := systemLongFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			at := time.Unix(testNow+10, 0).UTC()
			if crossing == "certificate" {
				at = time.Unix(snap.Intent.NotAfter, 0).UTC().Add(-time.Minute)
			}
			if _, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), systemRaw(t, 1, systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 1, at)), at); err != nil {
				t.Fatal("seed", err)
			}
			clock := &overviewFixtureClock{}
			clock.set(at)
			readCtx := WithSystemViewClock(ctx, clock.now)
			held, err := s.inventoryAdmission(ctx)
			if err != nil {
				t.Fatal(err)
			}
			type outcome struct {
				view SystemView
				err  error
			}
			done := make(chan outcome, 1)
			go func() { view, err := s.SystemView(readCtx, snap.Approval.DeviceID, at); done <- outcome{view, err} }()
			waitSystemMetadataReader(t, s, ctx)
			if clock.calls.Load() != 0 {
				t.Fatal("authority clock sampled before admission")
			}
			expected := "expired"
			switch crossing {
			case "freshness":
				clock.set(at.Add(SystemMaxAge + time.Nanosecond))
				expected = "stale"
			case "retention":
				clock.set(at.Add(SystemRetention))
			case "certificate":
				clock.set(time.Unix(snap.Intent.NotAfter, 0).UTC())
			case "revocation":
				command := control(snap, 50)
				command.Now = at.Add(time.Second).Unix()
				if _, err := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: command, State: enrollmentstate.Revoked}); err != nil {
					t.Fatal("revoke", err)
				}
				clock.set(at.Add(2 * time.Second))
				expected = "revoked"
			}
			held()
			out := <-done
			if out.err != nil || out.view.Status != expected || out.view.Sequence == nil || *out.view.Sequence != 1 || out.view.ReceivedAt == nil || !out.view.ReceivedAt.Equal(at) {
				t.Fatal("wait used stale authority or refreshed original receipt", out.err)
			}
			if expected == "stale" {
				if out.view.Latest == nil || !out.view.Latest.CollectedAt.Equal(at) || out.view.LastComplete.Services == nil || out.view.LastComplete.Services.Status != "stale" {
					t.Fatal("wait refreshed capture or stale sections")
				}
			} else if out.view.Latest != nil || out.view.LastComplete.Services != nil || out.view.LastComplete.Sockets != nil {
				t.Fatal("expired or revoked metadata escaped")
			}
		})
	}
}

func TestSystemMetadataRechecksClockAfterSQLAndCommit(t *testing.T) {
	for _, crossing := range []string{"sql_wait", "commit", "output", "rollback"} {
		t.Run(crossing, func(t *testing.T) {
			_, s, _, snap, cert := systemLongFixture(t)
			at := time.Unix(testNow+10, 0).UTC()
			ctx := context.Background()
			if _, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), systemRaw(t, 1, systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 1, at)), at); err != nil {
				t.Fatal("seed", err)
			}
			expiry := at.Add(SystemRetention)
			initial := expiry.Add(-time.Nanosecond)
			var calls atomic.Int64
			clock := &overviewFixtureClock{}
			clock.set(initial)
			now := clock.now
			if crossing == "commit" {
				now = func() time.Time {
					if calls.Add(1) > 1 {
						return expiry
					}
					return initial
				}
			}
			if crossing == "rollback" {
				now = func() time.Time {
					if calls.Add(1) > 1 {
						return at
					}
					return initial
				}
			}
			readCtx := WithSystemViewClock(ctx, now)
			var view SystemView
			var err error
			if crossing == "sql_wait" {
				err = afterOverviewConnectionWait(t, s, func() {
					if clock.calls.Load() != 0 {
						t.Error("clock sampled before SQL authority")
					}
					clock.set(expiry)
				}, func() error { view, err = s.SystemView(readCtx, snap.Approval.DeviceID, initial); return err })
			} else {
				view, err = s.SystemView(readCtx, snap.Approval.DeviceID, initial)
			}
			if err != nil {
				t.Fatal(err)
			}
			if crossing == "output" {
				view, err = view.RecheckAt(expiry)
				if err != nil {
					t.Fatal(err)
				}
			}
			if crossing == "rollback" {
				if !view.ServerNow.Equal(initial) || view.Status != "stale" {
					t.Fatal("clock rollback revived age")
				}
				return
			}
			if view.Status != "expired" || view.Latest != nil || view.LastComplete.Services != nil || view.LastComplete.Sockets != nil || !view.ServerNow.Equal(expiry) {
				t.Fatal("expired metadata escaped final output")
			}
		})
	}
}

func TestSystemMetadataPermitCoversSQLWaitAndCancellation(t *testing.T) {
	_, s, _, snap, _ := completeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	held, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	readCtx, stop := context.WithCancel(ctx)
	defer stop()
	before := s.db.Stats().WaitCount
	type outcome struct {
		view SystemView
		err  error
	}
	done := make(chan outcome, 1)
	at := time.Unix(testNow+10, 0).UTC()
	go func() { view, err := s.SystemView(readCtx, snap.Approval.DeviceID, at); done <- outcome{view, err} }()
	for s.db.Stats().WaitCount == before {
		select {
		case <-ctx.Done():
			t.Fatal("reader did not queue for SQL")
		case <-time.After(time.Millisecond):
		}
	}
	if len(s.inventoryCalls) != 1 || len(s.systemMetadataReads) != 1 {
		t.Fatal("reader did not retain both permits through SQL wait")
	}
	if view, err := s.SystemView(ctx, snap.Approval.DeviceID, at); !errors.Is(err, ErrInventoryBusy) || !reflect.DeepEqual(view, SystemView{}) {
		t.Fatal("second reader entered SQL queue", err)
	}
	stop()
	result := <-done
	if !errors.Is(result.err, context.Canceled) || !reflect.DeepEqual(result.view, SystemView{}) || len(s.inventoryCalls) != 0 || len(s.systemMetadataReads) != 0 {
		t.Fatal("canceled SQL wait leaked provisional output or permits", result.err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemView(ctx, snap.Approval.DeviceID, at); err != nil {
		t.Fatal("read failed after canceled predecessor", err)
	}
}

func TestSystemMetadataHandoffPrecedesNewNonblockingInventoryWork(t *testing.T) {
	_, s, _, snap, _ := completeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sql, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sql.Close()
	release, err := s.inventoryAdmission(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	at := time.Unix(testNow+10, 0).UTC()
	go func() { _, err := s.SystemView(ctx, snap.Approval.DeviceID, at); done <- err }()
	waitSystemMetadataReader(t, s, ctx)
	select {
	case <-done:
		t.Fatal("reader escaped occupied gate")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	// The held SQL connection keeps the handed-off reader active while new
	// nonblocking work probes the gate; that work cannot overtake the reader.
	for i := 0; i < 100; i++ {
		if other, err := s.inventoryAdmission(ctx); !errors.Is(err, ErrInventoryBusy) || other != nil {
			if other != nil {
				other()
			}
			t.Fatal("new work overtook the queued reader")
		}
	}
	if err := sql.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal("handed-off reader failed", err)
	}
}
