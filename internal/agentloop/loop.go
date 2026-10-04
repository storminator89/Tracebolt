package agentloop

import (
	"context"
	"math/rand/v2"
	"time"
)

// Run starts the first attempt immediately, then waits after each completed
// attempt. There is no ticker, catch-up queue, detached attempt, or automatic
// enrollment. Each Run owns its own schedule; the caller must prevent multiple
// Run calls for the same agent and preserve the sender's exclusive state lock.
//
// Retry waits double from min(Interval, MaxBackoff) and cap at MaxBackoff. Success
// resets the failure count. All waits use up to 10% downward jitter, with a 15s
// floor. A terminal result, invalid callback result, or failed dependency stops
// the loop. The caller's cancellation is cooperative, not a hard process kill.
func Run(ctx context.Context, cfg Config, deps Dependencies) (Summary, error) {
	var summary Summary
	if cfg.Interval == 0 {
		cfg.Interval = DefaultInterval
	}
	if ctx == nil || deps.Attempt == nil || cfg.Interval < MinInterval || cfg.Interval > MaxInterval {
		summary.Reason = InvalidConfig
		return summary, ErrConfiguration
	}
	if deps.Clock == nil {
		deps.Clock = realClock{}
	}
	deps.Clock = &monotonicClock{Clock: deps.Clock}
	if deps.Random == nil {
		deps.Random = rand.Int64N
	}
	finish := func(reason StopReason, err error) (Summary, error) {
		summary.Reason = reason
		if !observe(deps.Observe, Event{Phase: Stopped, Attempt: summary.Attempts, Outcome: summary.LastOutcome, ConsecutiveFailures: summary.ConsecutiveFailures, Reason: reason}) {
			summary.Reason = ObserverFailed
			return summary, ErrObserver
		}
		return summary, err
	}
	stopForContext := func() (Summary, error) {
		if ctx.Err() == context.DeadlineExceeded {
			return finish(Deadline, context.DeadlineExceeded)
		}
		return finish(Cancelled, context.Canceled)
	}
	observerFailed := func() (Summary, error) {
		// Do not call a failing status sink again, including for the final event.
		summary.Reason = ObserverFailed
		return summary, ErrObserver
	}
	for {
		if ctx.Err() != nil {
			return stopForContext()
		}
		nextAttempt := increment(summary.Attempts)
		if !observe(deps.Observe, Event{Phase: Starting, Attempt: nextAttempt, ConsecutiveFailures: summary.ConsecutiveFailures}) {
			return observerFailed()
		}
		// An observer may have requested cancellation while handling the event.
		if ctx.Err() != nil {
			return stopForContext()
		}
		start, ok := now(deps.Clock)
		if !ok {
			return finish(DependencyFailed, ErrDependency)
		}
		if ctx.Err() != nil {
			return stopForContext()
		}
		summary.Attempts = nextAttempt
		result, ok := attempt(deps.Attempt, ctx)
		if ctx.Err() != nil {
			return stopForContext()
		}
		if !ok {
			return finish(AttemptFailed, ErrAttempt)
		}
		if !valid(result) {
			return finish(InvalidResult, ErrResult)
		}
		end, ok := now(deps.Clock)
		if !ok || end.Before(start) {
			return finish(DependencyFailed, ErrDependency)
		}
		summary.LastOutcome = result.Outcome
		if result.Outcome == Success {
			summary.ConsecutiveFailures = 0
		} else if result.Outcome == Retryable && summary.ConsecutiveFailures < 255 {
			summary.ConsecutiveFailures++
		}
		elapsed := min(end.Sub(start), MaxInterval)
		if !observe(deps.Observe, Event{Phase: Finished, Attempt: summary.Attempts, Outcome: result.Outcome, ConsecutiveFailures: summary.ConsecutiveFailures, Elapsed: elapsed, Metadata: result.Metadata}) {
			return observerFailed()
		}
		if ctx.Err() != nil {
			return stopForContext()
		}
		switch result.Outcome {
		case Configuration:
			return finish(InvalidConfig, ErrConfiguration)
		case State:
			return finish(InvalidState, ErrState)
		case Revoked:
			return finish(AuthorizationRevoked, ErrRevoked)
		}
		base := cfg.Interval
		if result.Outcome == Retryable {
			base = backoff(cfg.Interval, summary.ConsecutiveFailures)
		}
		delay, ok := jitter(base, deps.Random)
		if !ok {
			return finish(DependencyFailed, ErrDependency)
		}
		if !observe(deps.Observe, Event{Phase: Waiting, Attempt: summary.Attempts, Outcome: result.Outcome, ConsecutiveFailures: summary.ConsecutiveFailures, Delay: delay}) {
			return observerFailed()
		}
		if ctx.Err() != nil {
			return stopForContext()
		}
		ok = wait(ctx, deps.Clock, delay)
		if ctx.Err() != nil {
			return stopForContext()
		}
		if !ok {
			return finish(DependencyFailed, ErrDependency)
		}
	}
}

func valid(r Result) bool {
	switch r.Outcome {
	case Success, Retryable, Configuration, State, Revoked:
	default:
		return false
	}
	a, u := r.Metadata.AvailablePercentageFields, r.Metadata.UnavailablePercentageFields
	switch r.Metadata.InventoryStatus {
	case "":
		if r.Metadata.InventorySequence != 0 || r.Metadata.InventoryOperations != 0 {
			return false
		}
	case "not_due", "pending_retained":
	case "acknowledged", "failure_acknowledged", "aborted":
		if r.Metadata.InventorySequence == 0 {
			return false
		}
	default:
		return false
	}
	if r.Metadata.InventoryOperations > 64 {
		return false
	}
	switch r.Metadata.SystemStatus {
	case "":
		if r.Metadata.SystemSequence != 0 || r.Metadata.SystemRetriedPending || r.Metadata.SystemDiscardedStale {
			return false
		}
	case "pending_retained":
	case "acknowledged":
		if r.Metadata.SystemSequence == 0 {
			return false
		}
	default:
		return false
	}
	return a <= 3 && u <= 3 && int(a)+int(u) <= 3
}

func increment(n uint64) uint64 {
	if n != ^uint64(0) {
		n++
	}
	return n
}

func backoff(interval time.Duration, failures uint8) time.Duration {
	delay := min(interval, MaxBackoff)
	for n := uint8(1); n < failures && delay < MaxBackoff; n++ {
		delay = min(delay*2, MaxBackoff)
	}
	return delay
}

func jitter(base time.Duration, random func(int64) int64) (delay time.Duration, ok bool) {
	defer func() { _ = recover() }()
	span := min(base/10, base-MinInterval)
	if span == 0 {
		return base, true
	}
	offset := random(int64(span) + 1)
	if offset < 0 || offset > int64(span) {
		return 0, false
	}
	return base - time.Duration(offset), true
}

func attempt(fn Attempt, ctx context.Context) (result Result, ok bool) {
	defer func() { _ = recover() }()
	return fn(ctx), true
}

func observe(fn func(Event) error, event Event) (ok bool) {
	if fn == nil {
		return true
	}
	defer func() { _ = recover() }()
	return fn(event) == nil
}

func now(clock Clock) (at time.Time, ok bool) {
	defer func() { _ = recover() }()
	return clock.Now(), true
}

func wait(ctx context.Context, clock Clock, delay time.Duration) (ok bool) {
	// Recover only at the injected dependency boundary. No panic value is ever
	// formatted, logged, returned, or given to the observer.
	defer func() { _ = recover() }()
	start, validStart := now(clock)
	if !validStart || ctx.Err() != nil {
		return false
	}
	timer := clock.NewTimer(delay)
	if timer == nil {
		return false
	}
	defer func() {
		if !stop(timer) {
			ok = false
		}
	}()
	ch := timer.C()
	if ch == nil || ctx.Err() != nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case _, open := <-ch:
		end, validEnd := now(clock)
		// A broken seam must not create an immediate retry/catch-up storm.
		return open && validEnd && end.Sub(start) >= delay
	}
}

func stop(timer Timer) (ok bool) {
	defer func() { _ = recover() }()
	timer.Stop()
	return true
}

type realClock struct{}

func (realClock) Now() time.Time                 { return time.Now() }
func (realClock) NewTimer(d time.Duration) Timer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ *time.Timer }

func (t realTimer) C() <-chan time.Time { return t.Timer.C }

// Check the complete sequence, including boundaries between attempts and waits.
// A regression must not disguise an early timer fire as a long elapsed wait.
type monotonicClock struct {
	Clock
	last time.Time
	seen bool
}

func (c *monotonicClock) Now() time.Time {
	at := c.Clock.Now()
	if c.seen && at.Before(c.last) {
		panic("agent loop clock moved backwards")
	}
	c.last, c.seen = at, true
	return at
}
