package managerstatus

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Worker records actual fixed-loop steps. Warning silence is never health.
// It carries no task, target, identity, error text or authority information.
type Worker struct {
	mu                         sync.Mutex
	now                        func() time.Time
	maxAge                     time.Duration
	running, stopped, inflight bool
	state                      State
	last                       time.Time
	completed, failed          uint64
	lastSuccess                time.Time
}

func NewWorker(interval time.Duration, now func() time.Time) (*Worker, error) {
	if interval < time.Second || interval > time.Minute {
		return nil, errors.New("invalid manager maintenance interval")
	}
	if now == nil {
		now = time.Now
	}
	return &Worker{now: now, maxAge: 2*interval + 5*time.Second, state: Starting}, nil
}
func (w *Worker) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.stopped {
		w.running = true
	}
}
func (w *Worker) Begin() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.running && !w.stopped {
		w.inflight = true
	}
}
func (w *Worker) Complete(state State) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.running || w.stopped {
		return
	}
	valid := false
	for _, known := range states {
		if state == known {
			valid = true
			break
		}
	}
	if !valid {
		state = Invalid
	}
	at := w.now()
	if at.Before(w.last) {
		state = Invalid
		at = w.last
	}
	w.last, w.state, w.inflight = at, state, false
	increment(&w.completed)
	if state == OK {
		w.lastSuccess = at
	} else {
		increment(&w.failed)
	}
}
func (w *Worker) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped, w.running, w.inflight = true, false, false
	w.state = Stopped
}
func (w *Worker) Check(ctx context.Context) ProbeResult {
	if w == nil || ctx == nil {
		return ProbeResult{State: Invalid}
	}
	if err := ctx.Err(); err != nil {
		return ProbeResult{State: Classify(err)}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	state := w.state
	if w.stopped {
		state = Stopped
	} else if !w.running || w.last.IsZero() {
		state = Starting
	} else if w.now().Before(w.last) {
		state = Invalid
	} else if w.now().Sub(w.last) >= w.maxAge {
		state = Stale
	}
	work := &WorkMetrics{Limit: 1, Completed: w.completed, Failed: w.failed}
	if w.inflight {
		work.Used = 1
	}
	if !w.last.IsZero() {
		work.LastCompletedUnixMillis = w.last.UTC().UnixMilli()
	}
	if !w.lastSuccess.IsZero() {
		work.LastSucceededUnixMillis = w.lastSuccess.UTC().UnixMilli()
	}
	return ProbeResult{State: state, Work: work}
}
