package freshgate

import (
	"context"
	"localrmm/internal/windowsservice"
)

type OwnedStopSteps struct {
	Check   func() bool
	Inspect func() (windowsservice.State, error)
	Stop    func() error
	Pause   func(context.Context) error
}

// StopOwned applies at most one approved Stop after exact-owned readback.
// Pending SCM transitions are observed within the ORIGINAL cleanup deadline;
// foreign/unknown state and ambiguous mutation errors never trigger a retry.
func StopOwned(ctx context.Context, s OwnedStopSteps) error {
	if ctx == nil || s.Check == nil || s.Inspect == nil || s.Stop == nil || s.Pause == nil {
		return ErrGuard
	}
	requested := false
	for {
		if ctx.Err() != nil || !s.Check() {
			return ErrGuard
		}
		state, e := s.Inspect()
		if e != nil {
			return ErrGuard
		}
		switch state {
		case windowsservice.Stopped:
			return nil
		case windowsservice.StartPending, windowsservice.StopPending:
		case windowsservice.Running:
			if !requested {
				if ctx.Err() != nil || !s.Check() {
					return ErrGuard
				}
				requested = true
				if s.Stop() != nil {
					return ErrGuard
				}
			}
		default:
			return ErrGuard
		}
		if ctx.Err() != nil || !s.Check() || s.Pause(ctx) != nil {
			return ErrGuard
		}
	}
}
