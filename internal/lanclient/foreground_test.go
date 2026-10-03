//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"localrmm/internal/agentloop"
	"localrmm/internal/lanclientstate"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type instantClock struct {
	at    time.Time
	waits []time.Duration
}
type instantTimer struct{ ch chan time.Time }

func (c *instantClock) Now() time.Time { return c.at }
func (c *instantClock) NewTimer(d time.Duration) agentloop.Timer {
	c.waits = append(c.waits, d)
	c.at = c.at.Add(d)
	ch := make(chan time.Time, 1)
	ch <- c.at
	return &instantTimer{ch}
}
func (t *instantTimer) C() <-chan time.Time { return t.ch }
func (*instantTimer) Stop() bool            { return false }
func TestForegroundKeepsExclusiveLockAcrossWaits(t *testing.T) {
	f := integrationFixture(t, "tls", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := &instantClock{at: time.Now()}
	finished := 0
	summary, e := runForeground(ctx, f.material, 15*time.Second, func(event agentloop.Event) error {
		if event.Phase == agentloop.Waiting {
			competing, err := lanclientstate.Open(f.material.config.StateDirectory, f.material.binding)
			if err == nil {
				competing.Close()
				t.Fatal("exclusive lock released during wait")
			}
		}
		if event.Phase == agentloop.Finished {
			finished++
			if event.Outcome != agentloop.Success || event.Metadata.Sequence != uint64(finished) {
				t.Fatal("unexpected report progression")
			}
			if finished == 2 {
				cancel()
			}
		}
		return nil
	}, clock, func(int64) int64 { return 0 })
	if !errors.Is(e, context.Canceled) || summary.Attempts != 2 || finished != 2 || len(clock.waits) != 1 || clock.waits[0] != 15*time.Second {
		t.Fatal("foreground cadence/cancellation failed")
	}
	state, e := lanclientstate.Open(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal("lock not released after stop")
	}
	defer state.Close()
	if next, e := state.NextSequence(); e != nil || next != 3 {
		t.Fatal("foreground sequence not durable")
	}
}
func TestForegroundExactPendingRetryThenContinues(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			var mu sync.Mutex
			var bodies [][]byte
			f := integrationFixture(t, profile, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					raw, _ := io.ReadAll(io.LimitReader(r.Body, MaxFrameBytes+1))
					r.Body = io.NopCloser(bytes.NewReader(raw))
					mu.Lock()
					bodies = append(bodies, bytes.Clone(raw))
					first := len(bodies) == 1
					mu.Unlock()
					if first {
						rec := httptest.NewRecorder()
						next.ServeHTTP(rec, r)
						if rec.Code != 200 {
							t.Error("first fixture commit failed")
						}
						conn, _, e := w.(http.Hijacker).Hijack()
						if e != nil {
							t.Error("fixture response loss")
							return
						}
						conn.Close()
						return
					}
					next.ServeHTTP(w, r)
				})
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			clock := &instantClock{at: time.Now()}
			var results []agentloop.Event
			summary, e := runForeground(ctx, f.material, 15*time.Second, func(event agentloop.Event) error {
				if event.Phase == agentloop.Finished {
					results = append(results, event)
					if len(results) == 3 {
						cancel()
					}
				}
				return nil
			}, clock, func(int64) int64 { return 0 })
			if !errors.Is(e, context.Canceled) || summary.Attempts != 3 || len(results) != 3 {
				t.Fatal("foreground completion")
			}
			if results[0].Outcome != agentloop.Retryable || results[1].Outcome != agentloop.Success || !results[1].Metadata.Duplicate || !results[1].Metadata.RetriedPending || results[1].Metadata.Sequence != 1 || results[2].Metadata.Sequence != 2 {
				t.Fatal("pending transition changed")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(bodies) != 3 || !bytes.Equal(bodies[0], bodies[1]) || bytes.Equal(bodies[1], bodies[2]) {
				t.Fatal("exact pending bytes not retained")
			}
		})
	}
}
func TestForegroundInvalidConfigDoesNotOpenState(t *testing.T) {
	if _, e := RunForeground(context.Background(), Material{}, time.Second, nil); !errors.Is(e, agentloop.ErrConfiguration) {
		t.Fatal("invalid foreground material")
	}
}
