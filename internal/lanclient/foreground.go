package lanclient

import (
	"context"
	"errors"
	"localrmm/internal/agentloop"
	"time"
)

// RunForeground retains the private state ledger's exclusive OS lock for the
// entire foreground lifetime, including sleep/backoff. It never installs a
// service, re-enrolls, changes a credential or queues additional observations.
// Each metric attempt has a cooperative 20s context. The complete profile adds
// one serialized service/socket observation and one inventory burst, each with
// its own20s budget. The package burst additionally has a64-operation cap.
// Synchronous OS I/O and observers
// still require a supervisor for a hard process deadline.
func RunForeground(ctx context.Context, m Material, interval time.Duration, observe func(agentloop.Event) error) (agentloop.Summary, error) {
	return runForeground(ctx, m, interval, observe, nil, nil)
}
func runForeground(ctx context.Context, m Material, interval time.Duration, observe func(agentloop.Event) error, clock agentloop.Clock, random func(int64) int64) (agentloop.Summary, error) {
	if ctx == nil || !m.valid() || (interval != 0 && (interval < agentloop.MinInterval || interval > agentloop.MaxInterval)) {
		return agentloop.Summary{Reason: agentloop.InvalidConfig}, agentloop.ErrConfiguration
	}
	if ctx.Err() != nil {
		reason := agentloop.Cancelled
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			reason = agentloop.Deadline
		}
		return agentloop.Summary{Reason: reason}, ctx.Err()
	}
	state, e := openSenderState(m)
	if e != nil {
		return agentloop.Summary{Reason: agentloop.InvalidState}, agentloop.ErrState
	}
	defer state.Close()
	var inventory *inventorySender
	var system *systemSender
	if m.config.complete() {
		inventory, e = openInventorySender(m)
		if e != nil {
			return agentloop.Summary{Reason: agentloop.InvalidState}, agentloop.ErrState
		}
		defer inventory.Close()
		system, e = openSystemSender(m)
		if e != nil {
			return agentloop.Summary{Reason: agentloop.InvalidState}, agentloop.ErrState
		}
		defer system.Close()
	}
	return agentloop.Run(ctx, agentloop.Config{Interval: interval}, agentloop.Dependencies{Clock: clock, Random: random, Observe: observe, Attempt: func(parent context.Context) agentloop.Result {
		report, err := runPreparedAttemptWithSystem(parent, m, state, system, inventory, runUsingState)
		outcome := agentloop.Retryable
		switch {
		case err == nil:
			outcome = agentloop.Success
		case errors.Is(err, ErrConfiguration):
			outcome = agentloop.Configuration
		case errors.Is(err, ErrState):
			outcome = agentloop.State
		}
		// Transport/receipt failures retain exact pending data. A generic transport
		// error cannot establish revocation and never triggers automatic enrollment.
		return agentloop.Result{Outcome: outcome, Metadata: agentloop.Metadata{Sequence: report.Sequence, Duplicate: report.Duplicate, RetriedPending: report.RetriedPending, DiscardedStale: report.DiscardedStale, AvailablePercentageFields: uint8(report.AvailablePercentageFields), UnavailablePercentageFields: uint8(report.UnavailablePercentageFields), InventoryStatus: report.InventoryStatus, InventorySequence: report.InventorySequence, InventoryOperations: report.InventoryOperations, SystemStatus: report.SystemStatus, SystemSequence: report.SystemSequence, SystemRetriedPending: report.SystemRetriedPending, SystemDiscardedStale: report.SystemDiscardedStale}}
	}})
}
