package windowsusersoftwarelocal

import (
	"context"
	"time"
)

const serviceStartPending uint32 = 2
const serviceRunning uint32 = 4

type ownServiceStatus struct {
	OwnProcess bool
	State, PID uint32
}

// Only our already verified service process may wait through SCM startup.
// QueryServiceStatusEx permits an unspecified (zero) PID while StartPending.
// Client proof never uses this relaxation; its SCM proof stays strictly Running.
func awaitOwnServiceReady(parent context.Context, pid uint32, identity func() error, query func() (ownServiceStatus, error), wait func(context.Context, time.Duration) error) error {
	if parent == nil || pid == 0 || identity == nil || query == nil || wait == nil {
		return ErrBinding
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := identity(); e != nil {
			return e
		}
		s, e := query()
		if e != nil || !s.OwnProcess {
			return ErrBinding
		}
		if s.State == serviceRunning {
			if s.PID != pid {
				return ErrBinding
			}
			return nil
		}
		if s.State != serviceStartPending || s.PID != 0 && s.PID != pid {
			return ErrBinding
		}
		if e = wait(ctx, 50*time.Millisecond); e != nil {
			return e
		}
	}
}
func waitReady(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
