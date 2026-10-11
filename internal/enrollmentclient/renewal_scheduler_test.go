package enrollmentclient

import (
	"context"
	"errors"
	"localrmm/internal/agentloop"
	"sync/atomic"
	"testing"
	"time"
)

func TestRenewalSchedulerOnlyQuiescesAtActualCutover(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var running atomic.Bool
	var starts, checks, activations, joins atomic.Int32
	_, e := runRenewalScheduler(ctx, renewalSchedulerDependencies{
		cycle: func(_ context.Context, activate bool) (time.Duration, error) {
			if activate {
				if running.Load() {
					t.Error("activation raced active sender")
				}
				if activations.Add(1) == 2 && joins.Load() != 1 {
					t.Error("activation preceded complete sender join")
				}
				if activations.Load() == 1 {
					return time.Millisecond, nil
				}
				return time.Hour, nil
			}
			if !running.Load() {
				t.Error("unchanged checks discarded the active memory-only result window")
			}
			if checks.Add(1) < 3 {
				return time.Millisecond, nil
			}
			return 0, errRenewalCutover
		},
		sender: func(ctx context.Context) (agentloop.Summary, error) {
			if running.Swap(true) {
				t.Error("sender lifetimes overlap")
			}
			if starts.Add(1) == 2 {
				cancel()
			}
			<-ctx.Done()
			// The runtime must await helper cleanup as well as parent cancellation.
			time.Sleep(time.Millisecond)
			joins.Add(1)
			running.Store(false)
			return agentloop.Summary{Attempts: 1}, ctx.Err()
		},
	})
	if !errors.Is(e, context.Canceled) || starts.Load() != 2 || checks.Load() != 3 || activations.Load() != 2 || joins.Load() != 2 || running.Load() {
		t.Fatalf("cutover lifecycle starts=%d checks=%d activations=%d joins=%d error=%v", starts.Load(), checks.Load(), activations.Load(), joins.Load(), e)
	}
}

func TestRenewalSchedulerFailureJoinsBeforeReturning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var joined atomic.Bool
	_, e := runRenewalScheduler(ctx, renewalSchedulerDependencies{
		cycle: func(_ context.Context, activate bool) (time.Duration, error) {
			if activate {
				return time.Millisecond, nil
			}
			return 0, ErrState
		},
		sender: func(ctx context.Context) (agentloop.Summary, error) {
			<-ctx.Done()
			joined.Store(true)
			return agentloop.Summary{}, ctx.Err()
		},
	})
	if !errors.Is(e, ErrState) || !joined.Load() {
		t.Fatal("failed preparation returned before joined sender", e)
	}
}
