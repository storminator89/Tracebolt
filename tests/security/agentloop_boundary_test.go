package security_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/agentloop"
	"strings"
	"testing"
	"time"
)

// Independent public-contract checks for the scheduler only. This fixture does
// not collect telemetry, perform network I/O, open sender state, or use real
// timers. A callback's sequence and delivery flags remain adapter-owned facts.
type loopBoundaryClock struct {
	at        time.Time
	timers    []*loopBoundaryTimer
	newTimer  func(time.Duration, *loopBoundaryTimer)
	inAttempt bool
	badStart  bool
}

type loopBoundaryTimer struct {
	ch     chan time.Time
	delay  time.Duration
	start  time.Time
	stops  int
	onStop func()
}

func newLoopBoundaryClock() *loopBoundaryClock {
	return &loopBoundaryClock{at: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)}
}

func (c *loopBoundaryClock) Now() time.Time { return c.at }

func (c *loopBoundaryClock) NewTimer(delay time.Duration) agentloop.Timer {
	if c.inAttempt {
		c.badStart = true
	}
	timer := &loopBoundaryTimer{ch: make(chan time.Time, 1), delay: delay, start: c.at}
	c.timers = append(c.timers, timer)
	if c.newTimer != nil {
		c.newTimer(delay, timer)
	} else {
		c.at = c.at.Add(delay)
		timer.ch <- c.at
	}
	return timer
}

func (t *loopBoundaryTimer) C() <-chan time.Time { return t.ch }

func (t *loopBoundaryTimer) Stop() bool {
	t.stops++
	if t.onStop != nil {
		t.onStop()
	}
	return false // Expired timers legitimately return false, without an error.
}

func checkLoopBoundaryTimers(t *testing.T, c *loopBoundaryClock) {
	t.Helper()
	if c.badStart {
		t.Fatal("timer started before the attempt finished")
	}
	for i, timer := range c.timers {
		if timer.stops != 1 {
			t.Fatalf("timer %d stopped %d times", i, timer.stops)
		}
	}
}

func TestIndependentAgentLoopWaitsAfterWholeAttemptAndObserver(t *testing.T) {
	c := newLoopBoundaryClock()
	initial := c.at
	var starts []time.Time
	active, maxActive := 0, 0
	s, err := agentloop.Run(context.Background(), agentloop.Config{}, agentloop.Dependencies{
		Clock:  c,
		Random: func(int64) int64 { return 0 },
		Attempt: func(context.Context) agentloop.Result {
			active++
			maxActive = max(maxActive, active)
			c.inAttempt = true
			defer func() { active--; c.inAttempt = false }()
			starts = append(starts, c.at)
			// Stand-ins for two sequential stages of one adapter attempt. The
			// scheduler cannot create a collection/send overlap between them.
			c.at = c.at.Add(2 * time.Hour)
			c.at = c.at.Add(3 * time.Minute)
			if len(starts) == 4 {
				return agentloop.Result{Outcome: agentloop.State}
			}
			return agentloop.Result{Outcome: agentloop.Success}
		},
		Observe: func(e agentloop.Event) error {
			switch e.Phase {
			case agentloop.Finished:
				if e.Elapsed != agentloop.MaxInterval {
					t.Error("long callback duration was not capped")
				}
				c.at = c.at.Add(7 * time.Minute)
			case agentloop.Waiting:
				c.at = c.at.Add(11 * time.Minute)
			}
			return nil
		},
	})
	if err != agentloop.ErrState || s.Attempts != 4 || maxActive != 1 || active != 0 || len(c.timers) != 3 {
		t.Fatalf("unexpected sequential result: %+v %v", s, err)
	}
	period := 2*time.Hour + 21*time.Minute + agentloop.DefaultInterval
	for i, start := range starts {
		if !start.Equal(initial.Add(time.Duration(i) * period)) {
			t.Errorf("attempt %d caught up instead of waiting after completion", i)
		}
	}
	checkLoopBoundaryTimers(t, c)
}

func TestIndependentAgentLoopRetryBoundsAcrossSaturationAndReset(t *testing.T) {
	for _, interval := range []time.Duration{agentloop.MinInterval, agentloop.MinInterval + 1, 16 * time.Second, agentloop.MaxBackoff + 1, agentloop.MaxInterval} {
		for _, maxJitter := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/max-jitter=%t", interval, maxJitter), func(t *testing.T) {
				c := newLoopBoundaryClock()
				calls := 0
				s, err := agentloop.Run(context.Background(), agentloop.Config{Interval: interval}, agentloop.Dependencies{
					Clock: c,
					Random: func(n int64) int64 {
						if maxJitter {
							return n - 1
						}
						return 0
					},
					Attempt: func(context.Context) agentloop.Result {
						calls++
						switch calls {
						case 301:
							return agentloop.Result{Outcome: agentloop.Success}
						case 303:
							return agentloop.Result{Outcome: agentloop.Revoked}
						default:
							return agentloop.Result{Outcome: agentloop.Retryable}
						}
					},
				})
				if err != agentloop.ErrRevoked || s.Attempts != 303 || s.ConsecutiveFailures != 1 || len(c.timers) != 302 {
					t.Fatalf("retry saturation/reset failed: %+v %v", s, err)
				}
				base := min(interval, agentloop.MaxBackoff)
				for i, timer := range c.timers {
					if i == 300 {
						base = interval
					}
					if i == 301 {
						base = min(interval, agentloop.MaxBackoff)
					}
					want := base
					if maxJitter {
						want = max(agentloop.MinInterval, base-base/10)
					}
					if timer.delay != want {
						t.Fatalf("timer %d: got %s, want %s", i, timer.delay, want)
					}
					if i < 299 {
						base = min(2*base, agentloop.MaxBackoff)
					}
				}
				checkLoopBoundaryTimers(t, c)
			})
		}
	}
}

func TestIndependentAgentLoopPreservesOnlyAdapterDeliveryClaims(t *testing.T) {
	c := newLoopBoundaryClock()
	results := []agentloop.Result{
		{Outcome: agentloop.Success, Metadata: agentloop.Metadata{Sequence: 40}},
		{Outcome: agentloop.Retryable, Metadata: agentloop.Metadata{Sequence: 41}},
		{Outcome: agentloop.Retryable, Metadata: agentloop.Metadata{Sequence: 41, RetriedPending: true}},
		{Outcome: agentloop.Success, Metadata: agentloop.Metadata{Sequence: 41, RetriedPending: true, Duplicate: true}},
		{Outcome: agentloop.Success, Metadata: agentloop.Metadata{Sequence: 43, DiscardedStale: true}},
		{Outcome: agentloop.State},
	}
	var finished []agentloop.Event
	calls := 0
	s, err := agentloop.Run(context.Background(), agentloop.Config{}, agentloop.Dependencies{
		Clock:  c,
		Random: func(int64) int64 { return 0 },
		Attempt: func(context.Context) agentloop.Result {
			r := results[calls]
			calls++
			return r
		},
		Observe: func(e agentloop.Event) error {
			if e.Phase == agentloop.Finished {
				finished = append(finished, e)
			}
			return nil
		},
	})
	if err != agentloop.ErrState || s.Attempts != uint64(len(results)) || len(finished) != len(results) {
		t.Fatalf("delivery status did not finish: %+v %v", s, err)
	}
	for i, e := range finished {
		if e.Outcome != results[i].Outcome || e.Metadata != results[i].Metadata {
			t.Fatalf("callback %d delivery result was invented or rewritten", i)
		}
	}
	if finished[1].ConsecutiveFailures != 1 || finished[2].ConsecutiveFailures != 2 || finished[3].ConsecutiveFailures != 0 {
		t.Fatal("retry status retained a previous successful state")
	}
	checkLoopBoundaryTimers(t, c)
}

func TestIndependentAgentLoopCancellationDuringTimerStopPreventsNextAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newLoopBoundaryClock()
	c.newTimer = func(d time.Duration, timer *loopBoundaryTimer) {
		c.at = c.at.Add(d)
		timer.ch <- c.at
		timer.onStop = cancel
	}
	calls := 0
	s, err := agentloop.Run(ctx, agentloop.Config{}, agentloop.Dependencies{
		Clock:   c,
		Random:  func(int64) int64 { return 0 },
		Attempt: func(context.Context) agentloop.Result { calls++; return agentloop.Result{Outcome: agentloop.Retryable} },
	})
	if err != context.Canceled || s.Reason != agentloop.Cancelled || calls != 1 || s.Attempts != 1 {
		t.Fatalf("cancellation at timer cleanup allowed another callback: %+v %v", s, err)
	}
	checkLoopBoundaryTimers(t, c)
}

func TestIndependentAgentLoopFailureDoesNotFormatCallbackSecrets(t *testing.T) {
	const secret = "PRIVATE-ADAPTER-PAYLOAD-MUST-NOT-ESCAPE"
	for _, failure := range []string{"panic", "invalid-outcome", "invalid-metadata", "observer-error"} {
		t.Run(failure, func(t *testing.T) {
			c := newLoopBoundaryClock()
			var events []agentloop.Event
			calls := 0
			s, err := agentloop.Run(context.Background(), agentloop.Config{}, agentloop.Dependencies{
				Clock:  c,
				Random: func(int64) int64 { return 0 },
				Attempt: func(context.Context) agentloop.Result {
					calls++
					if calls == 1 {
						return agentloop.Result{Outcome: agentloop.Retryable}
					}
					switch failure {
					case "panic":
						panic(secret)
					case "invalid-outcome":
						return agentloop.Result{Outcome: agentloop.Outcome(secret)}
					case "invalid-metadata":
						return agentloop.Result{Outcome: agentloop.Success, Metadata: agentloop.Metadata{AvailablePercentageFields: 2, UnavailablePercentageFields: 2}}
					default:
						return agentloop.Result{Outcome: agentloop.Retryable}
					}
				},
				Observe: func(e agentloop.Event) error {
					events = append(events, e)
					if failure == "observer-error" && e.Phase == agentloop.Finished && e.Attempt == 2 {
						return errors.New(secret)
					}
					return nil
				},
			})
			wantErr := map[string]error{"panic": agentloop.ErrAttempt, "invalid-outcome": agentloop.ErrResult, "invalid-metadata": agentloop.ErrResult, "observer-error": agentloop.ErrObserver}[failure]
			if err != wantErr || s.Attempts != 2 || s.LastOutcome != agentloop.Retryable || len(c.timers) != 1 {
				t.Fatalf("unsafe failure behavior: %+v %v", s, err)
			}
			encoded, marshalErr := json.Marshal(struct {
				Summary agentloop.Summary
				Events  []agentloop.Event
			}{s, events})
			if marshalErr != nil || strings.Contains(string(encoded), secret) || strings.Contains(fmt.Sprint(err), secret) {
				t.Fatal("untrusted callback content escaped the fixed status boundary")
			}
			checkLoopBoundaryTimers(t, c)
		})
	}
}
