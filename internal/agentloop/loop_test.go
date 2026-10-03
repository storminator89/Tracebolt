package agentloop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests never sleep, perform a real collection, touch sender state, create
// credentials, or access an endpoint. An advancing fake clock fires fake timers.
type fakeClock struct {
	mu        sync.Mutex
	at        time.Time
	timers    []*fakeTimer
	nowCalls  int
	nowHook   func(int, time.Time) time.Time
	timerHook func(time.Duration, *fakeTimer)
}

func newClock() *fakeClock {
	return &fakeClock{at: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	c.nowCalls++
	n, at, hook := c.nowCalls, c.at, c.nowHook
	c.mu.Unlock()
	if hook != nil {
		return hook(n, at)
	}
	return at
}

func (c *fakeClock) advance(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
	return c.at
}

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	timer := &fakeTimer{ch: make(chan time.Time, 1), delay: d, started: c.at}
	c.timers = append(c.timers, timer)
	hook := c.timerHook
	c.mu.Unlock()
	if hook != nil {
		hook(d, timer)
	} else {
		timer.ch <- c.advance(d)
	}
	return timer
}

type fakeTimer struct {
	ch        chan time.Time
	delay     time.Duration
	started   time.Time
	stops     atomic.Int32
	panicC    bool
	panicStop bool
}

func (t *fakeTimer) C() <-chan time.Time {
	if t.panicC {
		panic(secret)
	}
	return t.ch
}

func (t *fakeTimer) Stop() bool {
	t.stops.Add(1)
	if t.panicStop {
		panic(secret)
	}
	return true
}

const secret = "SECRET-private-key-reading-hostname.invalid"

func noJitter(int64) int64 { return 0 }

func depsFor(clock Clock, fn Attempt, events *[]Event) Dependencies {
	d := Dependencies{Clock: clock, Attempt: fn, Random: noJitter}
	if events != nil {
		d.Observe = func(e Event) error { *events = append(*events, e); return nil }
	}
	return d
}

func assertStoppedTimers(t *testing.T, c *fakeClock) {
	t.Helper()
	for i, timer := range c.timers {
		if got := timer.stops.Load(); got != 1 {
			t.Fatalf("timer %d stopped %d times; want once", i, got)
		}
	}
}

func TestRepeatedSuccessAndSafeMetadata(t *testing.T) {
	c := newClock()
	var events []Event
	calls := 0
	metadata := Metadata{Sequence: 71, Duplicate: true, RetriedPending: true, DiscardedStale: true, AvailablePercentageFields: 2, UnavailablePercentageFields: 1}
	summary, err := Run(context.Background(), Config{}, depsFor(c, func(context.Context) Result {
		calls++
		if calls == 4 {
			return Result{Outcome: State}
		}
		return Result{Outcome: Success, Metadata: metadata}
	}, &events))
	if err != ErrState || summary.Attempts != 4 || summary.Reason != InvalidState || summary.LastOutcome != State || summary.ConsecutiveFailures != 0 {
		t.Fatalf("unexpected result: %+v %v", summary, err)
	}
	if len(c.timers) != 3 || len(events) != 12 {
		t.Fatalf("timers=%d events=%d", len(c.timers), len(events))
	}
	for i, timer := range c.timers {
		if timer.delay != DefaultInterval {
			t.Fatalf("timer %d delay=%v", i, timer.delay)
		}
		start, finished, waiting := events[i*3], events[i*3+1], events[i*3+2]
		if start.Phase != Starting || finished.Phase != Finished || waiting.Phase != Waiting || finished.Metadata != metadata || finished.Outcome != Success || waiting.Delay != DefaultInterval {
			t.Fatalf("bad events: %+v %+v %+v", start, finished, waiting)
		}
	}
	if events[len(events)-1].Phase != Stopped || events[len(events)-1].Reason != InvalidState {
		t.Fatal("terminal event missing")
	}
	assertStoppedTimers(t, c)
}

func TestRetryBackoffCapAndReset(t *testing.T) {
	c := newClock()
	outcomes := []Outcome{Retryable, Retryable, Retryable, Retryable, Retryable, Retryable, Retryable, Success, Retryable, State}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, MaxBackoff, MaxBackoff, MaxBackoff, DefaultInterval, DefaultInterval}
	i := 0
	var events []Event
	summary, err := Run(context.Background(), Config{}, depsFor(c, func(context.Context) Result {
		r := Result{Outcome: outcomes[i]}
		i++
		return r
	}, &events))
	if err != ErrState || summary.Attempts != uint64(len(outcomes)) || summary.ConsecutiveFailures != 1 {
		t.Fatalf("unexpected result: %+v %v", summary, err)
	}
	if len(c.timers) != len(want) {
		t.Fatalf("got %d timers", len(c.timers))
	}
	for i, delay := range want {
		if c.timers[i].delay != delay {
			t.Errorf("timer %d=%v, want %v", i, c.timers[i].delay, delay)
		}
	}
	if events[7*3+1].ConsecutiveFailures != 0 || events[8*3+1].ConsecutiveFailures != 1 {
		t.Fatal("success did not reset failure counter")
	}
	assertStoppedTimers(t, c)
}

func TestJitterBoundsAndLongIntervalRetryCap(t *testing.T) {
	for _, interval := range []time.Duration{MinInterval, 16 * time.Second, DefaultInterval, MaxBackoff, MaxInterval} {
		for _, outcome := range []Outcome{Success, Retryable} {
			for _, highJitter := range []bool{false, true} {
				t.Run(fmt.Sprintf("%v/%s/max=%v", interval, outcome, highJitter), func(t *testing.T) {
					c := newClock()
					calls := 0
					d := depsFor(c, func(context.Context) Result {
						calls++
						if calls == 1 {
							return Result{Outcome: outcome}
						}
						return Result{Outcome: State}
					}, nil)
					d.Random = func(n int64) int64 {
						if highJitter {
							return n - 1
						}
						return 0
					}
					_, err := Run(context.Background(), Config{Interval: interval}, d)
					if err != ErrState || len(c.timers) != 1 {
						t.Fatalf("unexpected result: %v, %d timers", err, len(c.timers))
					}
					base := interval
					if outcome == Retryable {
						base = min(base, MaxBackoff)
					}
					want := base
					if highJitter {
						want = max(MinInterval, base-base/10)
					}
					if c.timers[0].delay != want {
						t.Fatalf("delay=%v want=%v", c.timers[0].delay, want)
					}
					assertStoppedTimers(t, c)
				})
			}
		}
	}
}

func TestCountersAndBackoffCannotOverflow(t *testing.T) {
	if increment(^uint64(0)) != ^uint64(0) || increment(42) != 43 {
		t.Fatal("attempt counter overflow")
	}
	for n := 1; n <= 255; n++ {
		for _, interval := range []time.Duration{MinInterval, DefaultInterval, MaxInterval} {
			if got := backoff(interval, uint8(n)); got < MinInterval || got > MaxBackoff {
				t.Fatalf("invalid backoff %v for count %d", got, n)
			}
		}
	}
	c := newClock()
	calls := 0
	summary, err := Run(context.Background(), Config{Interval: MinInterval}, depsFor(c, func(context.Context) Result {
		calls++
		if calls == 301 {
			return Result{Outcome: State}
		}
		return Result{Outcome: Retryable}
	}, nil))
	if err != ErrState || summary.Attempts != 301 || summary.ConsecutiveFailures != 255 || c.timers[299].delay != MaxBackoff {
		t.Fatalf("counter did not saturate: %+v %v", summary, err)
	}
	assertStoppedTimers(t, c)
}

func TestCancellationBeforeAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := newClock()
	var events []Event
	summary, err := Run(ctx, Config{}, depsFor(c, func(context.Context) Result {
		t.Fatal("attempt ran after cancellation")
		return Result{}
	}, &events))
	if err != context.Canceled || summary.Attempts != 0 || summary.Reason != Cancelled || len(c.timers) != 0 || len(events) != 1 || events[0].Phase != Stopped {
		t.Fatalf("unexpected cancellation: %+v %v %+v", summary, err, events)
	}
}

func TestCancellationAtEveryObserverBoundary(t *testing.T) {
	for _, phase := range []Phase{Starting, Finished, Waiting} {
		t.Run(string(phase), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := newClock()
			calls := 0
			d := depsFor(c, func(context.Context) Result { calls++; return Result{Outcome: Success} }, nil)
			d.Observe = func(e Event) error {
				if e.Phase == phase {
					cancel()
				}
				return nil
			}
			summary, err := Run(ctx, Config{}, d)
			wantCalls := 1
			if phase == Starting {
				wantCalls = 0
			}
			if err != context.Canceled || summary.Attempts != uint64(wantCalls) || calls != wantCalls || len(c.timers) != 0 {
				t.Fatalf("bad cancellation: %+v %v calls=%d", summary, err, calls)
			}
		})
	}
}

func TestCancellationDuringWaitAndReadyTimer(t *testing.T) {
	for _, alsoFire := range []bool{false, true} {
		t.Run(fmt.Sprint(alsoFire), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := newClock()
			c.timerHook = func(d time.Duration, timer *fakeTimer) {
				if alsoFire {
					timer.ch <- c.advance(d)
				}
				cancel()
			}
			calls := 0
			summary, err := Run(ctx, Config{}, depsFor(c, func(context.Context) Result { calls++; return Result{Outcome: Retryable} }, nil))
			if err != context.Canceled || summary.Attempts != 1 || calls != 1 || len(c.timers) != 1 {
				t.Fatalf("unexpected result: %+v %v calls=%d", summary, err, calls)
			}
			assertStoppedTimers(t, c)
		})
	}
}

type observedDoneContext struct {
	context.Context
	selected chan struct{}
	once     sync.Once
}

func (c *observedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.selected) })
	return c.Context.Done()
}

func TestCancellationWakesAnExistingWait(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &observedDoneContext{Context: base, selected: make(chan struct{})}
	c := newClock()
	c.timerHook = func(time.Duration, *fakeTimer) {} // Leave the fake timer pending.
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, Config{}, depsFor(c, func(context.Context) Result { return Result{Outcome: Success} }, nil))
		done <- err
	}()
	<-ctx.selected // The loop has passed the pre-select cancellation check.
	cancel()
	if err := <-done; err != context.Canceled || len(c.timers) != 1 {
		t.Fatalf("wait did not cancel: %v", err)
	}
	assertStoppedTimers(t, c)
}

func TestCancellationFromClockPreventsAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newClock()
	c.nowHook = func(_ int, at time.Time) time.Time { cancel(); return at }
	s, err := Run(ctx, Config{}, depsFor(c, func(context.Context) Result { t.Fatal("attempt ran after cancellation"); return Result{} }, nil))
	if err != context.Canceled || s.Attempts != 0 || len(c.timers) != 0 {
		t.Fatalf("unexpected cancellation: %+v %v", s, err)
	}
}

func TestCancellationIsCooperativeInFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newClock()
	entered, sawCancel, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	type completion struct {
		summary Summary
		err     error
	}
	done := make(chan completion, 1)
	go func() {
		s, err := Run(ctx, Config{}, depsFor(c, func(attemptContext context.Context) Result {
			if attemptContext != ctx {
				panic("unexpected context")
			}
			close(entered)
			<-attemptContext.Done()
			close(sawCancel)
			<-release // Deliberately ignores cancellation until the test permits return.
			return Result{Outcome: Success}
		}, nil))
		done <- completion{s, err}
	}()
	<-entered
	cancel()
	<-sawCancel
	select {
	case <-done:
		t.Fatal("loop returned while callback was still in flight")
	default:
	}
	close(release)
	got := <-done
	if got.err != context.Canceled || got.summary.Attempts != 1 || got.summary.LastOutcome != "" || len(c.timers) != 0 {
		t.Fatalf("unexpected cancellation result: %+v %v", got.summary, got.err)
	}
}

func TestDeadlineAndCancellationCauseAreSafe(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Time{})
	defer cancel()
	s, err := Run(ctx, Config{}, depsFor(newClock(), func(context.Context) Result { t.Fatal("attempt ran"); return Result{} }, nil))
	if err != context.DeadlineExceeded || s.Reason != Deadline || s.Attempts != 0 {
		t.Fatalf("unexpected deadline: %+v %v", s, err)
	}
	causeCtx, causeCancel := context.WithCancelCause(context.Background())
	causeCancel(errors.New(secret))
	s, err = Run(causeCtx, Config{}, depsFor(newClock(), func(context.Context) Result { return Result{} }, nil))
	if err != context.Canceled || s.Reason != Cancelled || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe cancellation result: %+v %v", s, err)
	}
}

func TestSlowAttemptsNeverOverlapOrCatchUp(t *testing.T) {
	c := newClock()
	initial := c.Now()
	active, calls := 0, 0
	var starts []time.Time
	var events []Event
	s, err := Run(context.Background(), Config{}, depsFor(c, func(context.Context) Result {
		active++
		defer func() { active-- }()
		if active != 1 {
			t.Fatal("overlapping callbacks")
		}
		calls++
		starts = append(starts, c.Now())
		c.advance(2 * time.Hour)
		if calls == 4 {
			return Result{Outcome: State}
		}
		return Result{Outcome: Success}
	}, &events))
	if err != ErrState || s.Attempts != 4 || len(c.timers) != 3 {
		t.Fatalf("unexpected result: %+v %v", s, err)
	}
	for i, at := range starts {
		want := initial.Add(time.Duration(i) * (2*time.Hour + DefaultInterval))
		if !at.Equal(want) {
			t.Fatalf("attempt %d started at %v, want %v", i, at, want)
		}
	}
	for i, timer := range c.timers {
		if !timer.started.Equal(starts[i].Add(2*time.Hour)) || events[i*3+1].Elapsed != MaxInterval {
			t.Fatal("timer did not start after callback completion or elapsed was not capped")
		}
	}
	assertStoppedTimers(t, c)
}

func TestTerminalOutcomesStopWithoutRetry(t *testing.T) {
	for _, tc := range []struct {
		outcome Outcome
		reason  StopReason
		err     error
	}{
		{Configuration, InvalidConfig, ErrConfiguration}, {State, InvalidState, ErrState}, {Revoked, AuthorizationRevoked, ErrRevoked},
	} {
		t.Run(string(tc.outcome), func(t *testing.T) {
			c := newClock()
			var events []Event
			d := depsFor(c, func(context.Context) Result { return Result{Outcome: tc.outcome} }, &events)
			d.Random = func(int64) int64 { t.Fatal("terminal outcome requested jitter"); return 0 }
			s, err := Run(context.Background(), Config{}, d)
			if err != tc.err || s.Reason != tc.reason || s.Attempts != 1 || s.LastOutcome != tc.outcome || len(c.timers) != 0 || len(events) != 3 || events[2].Phase != Stopped {
				t.Fatalf("unexpected terminal result: %+v %v %+v", s, err, events)
			}
		})
	}
}

func TestInvalidConfigurationHasNoSideEffects(t *testing.T) {
	for _, interval := range []time.Duration{-1, 1, MinInterval - 1, MaxInterval + 1, time.Duration(1<<63 - 1)} {
		t.Run(interval.String(), func(t *testing.T) {
			d := Dependencies{Attempt: func(context.Context) Result { t.Fatal("attempt called"); return Result{} }, Observe: func(Event) error { t.Fatal("observer called"); return nil }, Random: func(int64) int64 { t.Fatal("random called"); return 0 }}
			s, err := Run(context.Background(), Config{Interval: interval}, d)
			if err != ErrConfiguration || s.Reason != InvalidConfig || s.Attempts != 0 {
				t.Fatalf("unexpected invalid config result: %+v %v", s, err)
			}
		})
	}
	for _, tc := range []struct {
		ctx context.Context
		d   Dependencies
	}{{nil, Dependencies{Attempt: func(context.Context) Result { return Result{Outcome: Success} }}}, {context.Background(), Dependencies{}}} {
		if s, err := Run(tc.ctx, Config{}, tc.d); err != ErrConfiguration || s.Reason != InvalidConfig {
			t.Fatalf("nil configuration accepted: %+v %v", s, err)
		}
	}
}

func TestInvalidResultsNeverEscape(t *testing.T) {
	for _, result := range []Result{
		{}, {Outcome: Outcome(secret)}, {Outcome: Success, Metadata: Metadata{AvailablePercentageFields: 4}},
		{Outcome: Success, Metadata: Metadata{UnavailablePercentageFields: 255}},
		{Outcome: Success, Metadata: Metadata{AvailablePercentageFields: 2, UnavailablePercentageFields: 2}},
		{Outcome: Revoked, Metadata: Metadata{AvailablePercentageFields: 255, UnavailablePercentageFields: 255}},
	} {
		c := newClock()
		var events []Event
		s, err := Run(context.Background(), Config{}, depsFor(c, func(context.Context) Result { return result }, &events))
		if err != ErrResult || s.Reason != InvalidResult || s.LastOutcome != "" || len(c.timers) != 0 || len(events) != 2 {
			t.Fatalf("invalid result escaped: %+v %v %+v", s, err, events)
		}
		assertRedacted(t, s, err, events)
	}
}

// Error must never even be called on an observer's raw error or panic value.
type unsafeError struct{}

func (unsafeError) Error() string { panic("raw error was formatted") }

func assertRedacted(t *testing.T, summary Summary, err error, events []Event) {
	t.Helper()
	raw, e := json.Marshal(struct {
		Summary Summary
		Events  []Event
	}{summary, events})
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(fmt.Sprint(err), secret) || len(raw) > 4096 {
		t.Fatal("status contained unsafe or unexpectedly large output")
	}
}

func TestAttemptPanicsStopSafely(t *testing.T) {
	for _, value := range []any{secret, unsafeError{}, nil} {
		c := newClock()
		var events []Event
		s, err := Run(context.Background(), Config{}, depsFor(c, func(context.Context) Result { panic(value) }, &events))
		if err != ErrAttempt || s.Reason != AttemptFailed || s.Attempts != 1 || len(c.timers) != 0 || len(events) != 2 {
			t.Fatalf("bad callback failure: %+v %v", s, err)
		}
		assertRedacted(t, s, err, events)
	}
}

func TestObserverFailuresStopWithoutRecursion(t *testing.T) {
	for _, phase := range []Phase{Starting, Finished, Waiting, Stopped} {
		for _, panics := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/panic=%v", phase, panics), func(t *testing.T) {
				c := newClock()
				var events []Event
				failed := false
				d := depsFor(c, func(context.Context) Result {
					if phase == Stopped {
						return Result{Outcome: State}
					}
					return Result{Outcome: Success}
				}, nil)
				d.Observe = func(e Event) error {
					if failed {
						t.Fatal("failed observer called again")
					}
					events = append(events, e)
					if e.Phase == phase {
						failed = true
						if panics {
							panic(unsafeError{})
						}
						return unsafeError{}
					}
					return nil
				}
				s, err := Run(context.Background(), Config{}, d)
				if !failed || err != ErrObserver || s.Reason != ObserverFailed || len(c.timers) != 0 {
					t.Fatalf("bad observer failure: %+v %v", s, err)
				}
				assertRedacted(t, s, err, events)
			})
		}
	}
}

func TestRandomFailuresStopSafely(t *testing.T) {
	for _, random := range []func(int64) int64{func(int64) int64 { return -1 }, func(n int64) int64 { return n }, func(int64) int64 { panic(unsafeError{}) }} {
		c := newClock()
		var events []Event
		d := depsFor(c, func(context.Context) Result { return Result{Outcome: Success} }, &events)
		d.Random = random
		s, err := Run(context.Background(), Config{}, d)
		if err != ErrDependency || s.Reason != DependencyFailed || s.Attempts != 1 || len(c.timers) != 0 {
			t.Fatalf("bad random failure: %+v %v", s, err)
		}
		assertRedacted(t, s, err, events)
	}
}

func TestClockFailuresStopSafely(t *testing.T) {
	for _, failAt := range []int{1, 2, 3, 4} {
		for _, backwards := range []bool{false, true} {
			if failAt == 1 && backwards {
				continue
			}
			t.Run(fmt.Sprintf("call=%d/backwards=%v", failAt, backwards), func(t *testing.T) {
				c := newClock()
				c.nowHook = func(n int, at time.Time) time.Time {
					if n == failAt {
						if backwards {
							return at.Add(-24 * time.Hour)
						}
						panic(unsafeError{})
					}
					return at
				}
				var events []Event
				s, err := Run(context.Background(), Config{}, depsFor(c, func(context.Context) Result { return Result{Outcome: Success} }, &events))
				if err != ErrDependency || s.Reason != DependencyFailed || s.Attempts > 1 {
					t.Fatalf("bad clock failure: %+v %v", s, err)
				}
				assertRedacted(t, s, err, events)
				assertStoppedTimers(t, c)
			})
		}
	}
}

func TestBrokenTimersCannotCreateBusyLoop(t *testing.T) {
	for _, mode := range []string{"factory-panic", "nil-channel", "closed-channel", "channel-panic", "stop-panic", "early-fire", "backwards-fire"} {
		t.Run(mode, func(t *testing.T) {
			c := newClock()
			c.timerHook = func(d time.Duration, timer *fakeTimer) {
				switch mode {
				case "factory-panic":
					panic(unsafeError{})
				case "nil-channel":
					timer.ch = nil
				case "closed-channel":
					close(timer.ch)
				case "channel-panic":
					timer.panicC = true
				case "stop-panic":
					timer.panicStop = true
					timer.ch <- c.advance(d)
				case "early-fire":
					timer.ch <- c.Now()
				case "backwards-fire":
					timer.ch <- c.advance(-d)
				}
			}
			var events []Event
			s, err := Run(context.Background(), Config{}, depsFor(c, func(context.Context) Result { return Result{Outcome: Retryable} }, &events))
			if err != ErrDependency || s.Reason != DependencyFailed || s.Attempts != 1 || len(c.timers) != 1 {
				t.Fatalf("broken timer repeated: %+v %v timers=%d", s, err, len(c.timers))
			}
			assertRedacted(t, s, err, events)
			if mode != "factory-panic" {
				assertStoppedTimers(t, c)
			}
		})
	}
}

type nilTimerClock struct {
	*fakeClock
	typed bool
}

func (c nilTimerClock) NewTimer(time.Duration) Timer {
	if c.typed {
		var timer *fakeTimer
		return timer
	}
	return nil
}

func TestNilTimerAndTypedNilClockAreRejected(t *testing.T) {
	var missingClock *fakeClock
	for _, c := range []Clock{nilTimerClock{fakeClock: newClock()}, nilTimerClock{fakeClock: newClock(), typed: true}, missingClock} {
		s, err := Run(context.Background(), Config{}, depsFor(c, func(context.Context) Result { return Result{Outcome: Retryable} }, nil))
		if err != ErrDependency || s.Reason != DependencyFailed || s.Attempts > 1 {
			t.Fatalf("nil dependency accepted: %+v %v", s, err)
		}
	}
}
