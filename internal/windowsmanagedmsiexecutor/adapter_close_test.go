package windowsmanagedmsiexecutor

import (
	"errors"
	"testing"
	"time"
)

func TestManagedCompletedAbandonedOwnerReturnsCloseError(t *testing.T) {
	want := errors.New("fixture custody close")
	a := &Adapter{}
	p := &prepared{owner: a, stop: make(chan struct{}), done: make(chan struct{}), abandoned: true, closeErr: want}
	close(p.done)
	if e := p.Close(); !errors.Is(e, want) {
		t.Fatal("completed owner cleanup hidden", e)
	}
}
func TestManagedCloseTimerCompletionRaceReturnsCloseError(t *testing.T) {
	want := errors.New("fixture custody close")
	a := &Adapter{}
	p := &prepared{owner: a, stop: make(chan struct{}), done: make(chan struct{}), closeErr: want}
	a.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	time.Sleep(closeLimit + 50*time.Millisecond)
	close(p.done)
	a.mu.Unlock()
	select {
	case e := <-done:
		if !errors.Is(e, want) {
			t.Fatal("timer/completion cleanup hidden", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close stuck")
	}
}
