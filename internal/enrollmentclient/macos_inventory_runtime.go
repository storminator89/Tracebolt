package enrollmentclient

import (
	"context"
	"errors"
	"localrmm/internal/agentloop"
	"localrmm/internal/lanclient"
	sender "localrmm/internal/macosinventorysender"
	state "localrmm/internal/macosinventorystate"
	"path/filepath"
	"time"
)

func openMacOSInventoryCoordinator(path string) (*sender.Coordinator, bool, error) {
	s, e := openMacOSInventoryEnrollment(path)
	if e != nil {
		return nil, false, e
	}
	c, _, enable, e := s.macOSInventoryOriginal()
	renewable := s.l.Bootstrap.RenewalPolicy != ""
	closeErr := closeMacOSInventoryEnrollment(s)
	if e != nil || closeErr != nil {
		return nil, false, ErrState
	}
	storage, raw, e := sender.OpenExistingStorage(c.StateDirectory, enable)
	if e != nil {
		return nil, false, ErrState
	}
	restored, e := state.Restore(storage, enable, raw, time.Now().UTC())
	if e != nil {
		_ = storage.Close()
		return nil, false, ErrState
	}
	coordinator, e := sender.NewNative(restored, enable, &macOSInventoryAuthority{path: path}, storage.Close)
	if e != nil {
		restored.Close()
		_ = storage.Close()
		return nil, false, e
	}
	return coordinator, renewable, nil
}

// ValidateMacOSInventoryHandoff is existing-only and read-only: no restore,
// collection, network, initialization or repair is performed.
func ValidateMacOSInventoryHandoff(path string) error {
	s, e := openMacOSInventoryEnrollment(path)
	if e != nil {
		return e
	}
	defer closeMacOSInventoryEnrollment(s)
	c, _, enable, e := s.macOSInventoryOriginal()
	if e != nil {
		return e
	}
	return validateMacOSInventoryStorage(c.StateDirectory, enable)
}

// RunMacOSInventoryOnce selects only the new inventory coordinator.
func RunMacOSInventoryOnce(ctx context.Context, path string) (result error) {
	if ctx == nil {
		return ErrState
	}
	c, _, e := openMacOSInventoryCoordinator(path)
	if e != nil {
		return e
	}
	defer func() {
		if e := c.Close(); e != nil {
			result = e
		}
	}()
	return c.Cycle(ctx)
}

// RunMacOSInventoryForeground uses one-minute cadence regardless of the basic
// sender's default. Renewal joins Close before validating existing storage and
// publishing the current-leaf manifest. Expired/revoked authority keeps only
// retention maintenance running until the foreground owner is stopped.
func RunMacOSInventoryForeground(ctx context.Context, path string, interval time.Duration, observe func(agentloop.Event) error) (agentloop.Summary, error) {
	if ctx == nil || interval != 30*time.Second && interval != time.Minute {
		return agentloop.Summary{}, ErrBootstrap
	}
	s, e := openMacOSInventoryEnrollment(path)
	if e != nil {
		return agentloop.Summary{}, e
	}
	renewable := s.l.Bootstrap.RenewalPolicy != ""
	if closeMacOSInventoryEnrollment(s) != nil {
		return agentloop.Summary{}, ErrState
	}
	run := func(ctx context.Context, maintenance bool) (summary agentloop.Summary, result error) {
		c, _, e := openMacOSInventoryCoordinator(path)
		if e != nil {
			return summary, e
		}
		defer func() {
			if e := c.Close(); e != nil {
				result = e
			}
		}()
		return runMacOSInventoryLoop(ctx, c, maintenance, observe)
	}
	if !renewable {
		return run(ctx, false)
	}
	summary, e := runRenewalScheduler(ctx, renewalSchedulerDependencies{
		cycle: func(ctx context.Context, activate bool) (time.Duration, error) {
			d, e := runRenewalCycleMode(ctx, filepath.Dir(path), activate)
			if errors.Is(e, ErrLocked) {
				return time.Minute, nil
			}
			return d, e
		},
		sender: func(ctx context.Context) (agentloop.Summary, error) { return run(ctx, false) },
	})
	if (errors.Is(e, ErrTerminal) || errors.Is(e, ErrState) && macOSInventoryAuthorityExhausted(path, time.Now().UTC())) && ctx.Err() == nil {
		maintained, err := run(ctx, true)
		maintained.Attempts += summary.Attempts
		return maintained, err
	}
	return summary, e
}

type macOSInventoryRunner interface {
	Cycle(context.Context) error
	Maintain(context.Context) (state.Status, error)
}

func runMacOSInventoryLoop(ctx context.Context, c macOSInventoryRunner, maintenance bool, observe func(agentloop.Event) error) (agentloop.Summary, error) {
	return runMacOSInventoryLoopWithWait(ctx, c, maintenance, observe, pause)
}
func runMacOSInventoryLoopWithWait(ctx context.Context, c macOSInventoryRunner, maintenance bool, observe func(agentloop.Event) error, wait func(context.Context, time.Duration) error) (agentloop.Summary, error) {
	var summary agentloop.Summary
	if ctx == nil || c == nil || wait == nil {
		return summary, ErrState
	}
	for {
		if ctx.Err() != nil {
			return summary, ctx.Err()
		}
		// Always maintain, including terminal disable or expired local authority.
		if _, e := c.Maintain(ctx); e != nil {
			return summary, e
		}
		outcome := agentloop.Retryable
		if !maintenance {
			attempt, cancel := context.WithTimeout(ctx, 45*time.Second)
			e := c.Cycle(attempt)
			cancel()
			if e == nil {
				outcome = agentloop.Success
			} else if !errors.Is(e, sender.ErrAuthority) && !errors.Is(e, sender.ErrTransport) && !errors.Is(e, sender.ErrCollection) && !errors.Is(e, state.ErrPacing) && !errors.Is(e, state.ErrExpired) && !errors.Is(e, context.DeadlineExceeded) && !errors.Is(e, context.Canceled) {
				return summary, e
			}
		}
		summary.Attempts++
		summary.LastOutcome = outcome
		if observe != nil && observe(agentloop.Event{Phase: agentloop.Finished, Attempt: summary.Attempts, Outcome: outcome}) != nil {
			return summary, agentloop.ErrObserver
		}
		if e := wait(ctx, time.Minute); e != nil {
			return summary, e
		}
	}
}

// Explicit dispatch helpers keep basic command behavior unchanged.
func ValidateMacOSHandoff(path string) error {
	inventory, e := lanclient.IsMacOSInventoryConfig(path)
	if e != nil {
		return e
	}
	if inventory {
		return ValidateMacOSInventoryHandoff(path)
	}
	return lanclient.ValidateGuidedHandoff(path)
}
func RunMacOSForeground(ctx context.Context, path string, interval time.Duration, observe func(agentloop.Event) error) (agentloop.Summary, error) {
	inventory, e := lanclient.IsMacOSInventoryConfig(path)
	if e != nil {
		return agentloop.Summary{}, e
	}
	if inventory {
		return RunMacOSInventoryForeground(ctx, path, interval, observe)
	}
	return RunRenewableForeground(ctx, path, interval, observe)
}
