package main

import (
	"context"
	"errors"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/windowsservice"
)

type pendingHooks struct {
	identity     func() error
	inspect      func() (enrollmentclient.ServiceState, error)
	resume       func(context.Context) error
	stopDeadline func() error
	markReady    func() (enrollmentclient.ServiceState, error)
	sender       func(context.Context, string) error
	wait         func(context.Context) error
}

// cooperativePendingOutcome accepts only nil or a chain whose every leaf is
// a cooperative session/transport cancellation. Mixed authority errors and
// unknown leaf errors are never converted into successful SCM shutdown.
func cooperativePendingOutcome(err error) (ok bool) {
	if err == nil {
		return true
	}
	diagnostic := windowsservice.Diagnostic(err)
	if diagnostic.Phase != windowsservice.PhaseUnknown && diagnostic.Reason != windowsservice.ReasonInterrupted {
		return false
	}
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	queue := []error{err}
	for budget := 64; len(queue) > 0 && budget > 0; budget-- {
		current := queue[0]
		queue = queue[1:]
		if current == nil {
			return false
		}
		switch current {
		case context.Canceled, context.DeadlineExceeded, enrollmentclient.ErrTransport:
			continue
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() error }:
			next := wrapped.Unwrap()
			if next == nil {
				return false
			}
			queue = append(queue, next)
		case interface{ Unwrap() []error }:
			next := wrapped.Unwrap()
			if len(next) == 0 || len(next) > budget-len(queue) {
				return false
			}
			queue = append(queue, next...)
		default:
			return false
		}
	}
	return len(queue) == 0
}

// runPendingWindows reopens and validates the same retained identity before each
// attempt. A 15-minute transport timeout is not the original approval deadline.
// This coordinator never creates keys or extends that retained authority.
func runPendingWindows(ctx context.Context, configPath string, ready func(), h pendingHooks) error {
	if ctx == nil || configPath == "" || ready == nil || h.identity == nil || h.inspect == nil || h.resume == nil || h.stopDeadline == nil || h.markReady == nil || h.sender == nil || h.wait == nil {
		return marked(windowsservice.PhasePendingApproval, windowsservice.ReasonInvalidConfiguration, nil)
	}
	signaled, backoff := false, false
	deadlineFailure := func(err error) error {
		if markErr := h.stopDeadline(); markErr != nil && (!errors.Is(markErr, enrollmentclient.ErrServiceDeadline) || errors.Is(markErr, enrollmentclient.ErrState)) {
			return marked(windowsservice.PhaseRetainedState, windowsservice.ReasonStateRejected, markErr)
		}
		return marked(windowsservice.PhasePendingApproval, windowsservice.ReasonApprovalExpired, err)
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := h.identity(); err != nil {
			return marked(windowsservice.PhaseRuntimeIdentity, windowsservice.ReasonIdentityRejected, err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		state, err := h.inspect()
		if err != nil {
			// A concurrent Stop must not hide an observed authority/storage failure.
			if errors.Is(err, enrollmentclient.ErrServiceDeadline) {
				return deadlineFailure(err)
			}
			if errors.Is(err, enrollmentclient.ErrTerminal) {
				return marked(windowsservice.PhasePendingApproval, windowsservice.ReasonEnrollmentTerminal, err)
			}
			if ctx.Err() != nil && cooperativePendingOutcome(err) {
				return ctx.Err()
			}
			return marked(windowsservice.PhaseRetainedState, windowsservice.ReasonStateRejected, err)
		}
		if state.ConfigPath != configPath || state.HTTPTest {
			return marked(windowsservice.PhaseRetainedState, windowsservice.ReasonInvalidConfiguration, nil)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !signaled {
			ready()
			signaled = true
		}
		if state.Ready {
			handoff, err := h.markReady()
			if err != nil {
				if ctx.Err() != nil && cooperativePendingOutcome(err) {
					return ctx.Err()
				}
				return marked(windowsservice.PhaseHandoff, windowsservice.ReasonHandoffInvalid, err)
			}
			if !handoff.Ready || handoff.ConfigPath != configPath || handoff.HTTPTest {
				return marked(windowsservice.PhaseHandoff, windowsservice.ReasonHandoffInvalid, nil)
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			err = h.sender(ctx, configPath)
			if ctx.Err() != nil && cooperativePendingOutcome(err) {
				return ctx.Err()
			}
			if err != nil {
				return marked(windowsservice.PhaseSender, windowsservice.ReasonSenderFailed, err)
			}
			return nil
		}
		if backoff {
			if err := h.wait(ctx); err != nil {
				if ctx.Err() != nil && cooperativePendingOutcome(err) {
					return ctx.Err()
				}
				return marked(windowsservice.PhasePendingApproval, windowsservice.ReasonOperationFailed, err)
			}
			backoff = false
			// Reinspect after sleeping: expiry, terminal state or lost identity must
			// stop before another manager operation, even if sleep itself succeeded.
			continue
		}
		err = h.resume(ctx)
		// Diagnose immutable expiry and terminal authority first, then cancellation.
		if errors.Is(err, enrollmentclient.ErrServiceDeadline) {
			return deadlineFailure(err)
		}
		if errors.Is(err, enrollmentclient.ErrTerminal) {
			return marked(windowsservice.PhasePendingApproval, windowsservice.ReasonEnrollmentTerminal, err)
		}
		if ctx.Err() != nil && cooperativePendingOutcome(err) {
			return ctx.Err()
		}
		switch {
		case err == nil:
			// Reinspect and mark handoff before creating a sender. If still pending,
			// wait rather than spinning on a success return without ready evidence.
			backoff = true
		case cooperativePendingOutcome(err) && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, enrollmentclient.ErrTransport)):
			backoff = true
		default:
			return marked(windowsservice.PhasePendingApproval, windowsservice.ReasonEnrollmentFailed, err)
		}
	}
}
