package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"testing"
	"time"
)

// Deterministic synthetic check of the shared, bounded read admission used by
// simultaneously restored dashboard panels. No collector or network is used.
func TestOperationalAndPackageViewsShareBoundedAdmission(t *testing.T) {
	_, s, _ := fixtureStore(t)
	ctx := context.Background()
	conn, e := s.db.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	queued, cancel := context.WithCancel(ctx)
	defer cancel()
	before := s.db.Stats().WaitCount
	done := make(chan error, 1)
	now := time.Unix(testNow, 0).UTC()
	go func() { _, e := s.OperationalView(queued, id("agent", 1), now); done <- e }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for s.db.Stats().WaitCount == before {
		select {
		case e := <-done:
			t.Fatal("read did not reach occupied connection", e)
		case <-deadline.C:
			t.Fatal("read did not enter connection queue")
		case <-time.After(time.Millisecond):
		}
	}
	view, e := s.PackageView(ctx, id("agent", 1), now)
	if e != ErrOperationalBusy || view.SchemaVersion != "" || view.Snapshot != nil {
		t.Fatal("competing read did not return empty typed busy result", e)
	}
	cancel()
	select {
	case e = <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal("queued read cancellation", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled read stuck")
	}
	if len(s.operationalReads) != 0 {
		t.Fatal("read retained admission after cancellation")
	}
	if e = conn.Close(); e != nil {
		t.Fatal(e)
	}
	// The later request is admitted and observes the real missing identity,
	// rather than a stale busy slot or a fabricated successful empty inventory.
	if _, e = s.PackageView(ctx, id("agent", 1), now); !errors.Is(e, enrollmentstate.ErrNotFound) {
		t.Fatal("read admission did not recover", e)
	}
}
