package windowsusersoftwarelocal

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOwnStartupPendingThenRunning(t *testing.T) {
	calls := 0
	checks := 0
	e := awaitOwnServiceReady(context.Background(), 77, func() error { checks++; return nil }, func() (ownServiceStatus, error) {
		calls++
		if calls == 1 {
			return ownServiceStatus{true, serviceStartPending, 0}, nil
		}
		return ownServiceStatus{true, serviceRunning, 77}, nil
	}, func(context.Context, time.Duration) error { return nil })
	if e != nil || calls != 2 || checks != 2 {
		t.Fatalf("startup not awaited: %v %d %d", e, calls, checks)
	}
}
func TestOwnStartupRejectsCancelDeadlineIdentityAndPIDDrift(t *testing.T) {
	for _, kind := range []string{"cancel", "deadline", "identity", "other_pid", "stopped", "shared", "running_zero"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel" {
				cancel()
			}
			identity := func() error {
				if kind == "identity" {
					return ErrBinding
				}
				return nil
			}
			query := func() (ownServiceStatus, error) {
				s := ownServiceStatus{true, serviceStartPending, 77}
				switch kind {
				case "other_pid":
					s.PID = 78
				case "stopped":
					s.State = 1
				case "shared":
					s.OwnProcess = false
				case "running_zero":
					s.State = serviceRunning
					s.PID = 0
				}
				return s, nil
			}
			e := awaitOwnServiceReady(ctx, 77, identity, query, func(context.Context, time.Duration) error { return context.DeadlineExceeded })
			if e == nil {
				t.Fatal("invalid startup accepted")
			}
			if kind == "cancel" && !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
			if kind == "deadline" && !errors.Is(e, context.DeadlineExceeded) {
				t.Fatal(e)
			}
		})
	}
}
