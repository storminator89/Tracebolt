package windowsupdateexecutor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestServiceDrainWaitsForActualNativeOwner(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	a := newAdapter(func(context.Context) (comRuntime, error) { close(entered); <-release; return nil, ErrUnavailable }, time.Now)
	a.prepareLimit = 10 * time.Millisecond
	done := make(chan error, 1)
	go func() { _, e := a.PrepareExact(context.Background(), selection); done <- e }()
	<-entered
	if e := <-done; e == nil {
		t.Fatal("bounded native caller should be uncertain")
	}
	a.StopAdmission()
	if _, e := a.PrepareExact(context.Background(), selection); !errors.Is(e, ErrClosed) {
		t.Fatal("service admitted during stop", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if e := a.Drain(ctx); !errors.Is(e, ErrUncertain) {
		t.Fatal("timeout claimed drained", e)
	}
	drained := make(chan error, 1)
	go func() { drained <- a.Drain(context.Background()) }()
	select {
	case <-drained:
		t.Fatal("service stopped while native thread lives")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	if e := <-drained; e != nil {
		t.Fatal(e)
	}
	if _, e := a.PrepareExact(context.Background(), selection); !errors.Is(e, ErrClosed) {
		t.Fatal("drain reopened admission")
	}
}
