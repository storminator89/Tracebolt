package managerstatus

import (
	"context"
	"testing"
	"time"
)

func TestWorkerActualCompletionRecoveryStalenessAndStop(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	w, err := NewWorker(time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal("fixture rejected")
	}
	if w.Check(context.Background()).State != Starting {
		t.Fatal("unstarted loop appeared healthy")
	}
	w.Start()
	w.Begin()
	if got := w.Check(context.Background()); got.State != Starting || got.Work.Used != 1 {
		t.Fatal("in-flight work incorrectly proves completion")
	}
	w.Complete(Busy)
	if got := w.Check(context.Background()); got.State != Busy || got.Work.Completed != 1 || got.Work.Failed != 1 || got.Work.LastSucceededUnixMillis != 0 {
		t.Fatal("failure was not observed")
	}
	w.Begin()
	w.Complete(OK)
	got := w.Check(context.Background())
	if got.State != OK || got.Work.Completed != 2 || got.Work.Failed != 1 || got.Work.LastCompletedUnixMillis != now.UnixMilli() || got.Work.LastSucceededUnixMillis != now.UnixMilli() {
		t.Fatal("actual recovery not recorded")
	}
	got.Work.Failed = 99
	if w.Check(context.Background()).Work.Failed != 1 {
		t.Fatal("display mutation changed worker state")
	}
	now = now.Add(7 * time.Second)
	if w.Check(context.Background()).State != Stale {
		t.Fatal("quiet loop stayed healthy indefinitely")
	}
	w.Begin()
	w.Complete(OK)
	if w.Check(context.Background()).State != OK {
		t.Fatal("fresh completion did not recover")
	}
	now = now.Add(-time.Second)
	if w.Check(context.Background()).State != Invalid {
		t.Fatal("backward clock appeared healthy")
	}
	w.Stop()
	w.Start()
	w.Begin()
	w.Complete(OK)
	if got := w.Check(context.Background()); got.State != Stopped || got.Work.Used != 0 {
		t.Fatal("stopped lifecycle resurrected")
	}
}

func TestWorkerMinuteIntervalIsExplicitAndBounded(t *testing.T) {
	now := time.Now()
	for _, interval := range []time.Duration{0, time.Millisecond, 2 * time.Minute} {
		if _, err := NewWorker(interval, nil); err == nil {
			t.Fatal("unbounded interval accepted")
		}
	}
	w, _ := NewWorker(time.Minute, func() time.Time { return now })
	w.Start()
	w.Complete(OK)
	now = now.Add(124 * time.Second)
	if w.Check(context.Background()).State != OK {
		t.Fatal("minute maintenance became stale early")
	}
	now = now.Add(time.Second)
	if w.Check(context.Background()).State != Stale {
		t.Fatal("minute maintenance freshness not bounded")
	}
}

func TestWorkerUnknownOutcomeAndCanceledReadFailClosed(t *testing.T) {
	w, _ := NewWorker(time.Second, nil)
	w.Start()
	w.Complete(State("secret-error-or-device-sentinel"))
	if got := w.Check(context.Background()); got.State != Invalid || got.Work.Failed != 1 {
		t.Fatal("unknown outcome became metadata")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if w.Check(ctx).State != Timeout {
		t.Fatal("canceled read was admitted")
	}
}
