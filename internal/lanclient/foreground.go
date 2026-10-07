package lanclient

import (
	"context"
	"errors"
	"localrmm/internal/agentloop"
	"runtime"
	"time"
)

// RunForeground retains the private state ledger's exclusive OS lock for the
// entire foreground lifetime, including sleep/backoff. It never installs a
// service, re-enrolls, changes a credential or queues additional observations.
// Each metric attempt has its own cooperative 20s context. The complete profile
// adds serialized system and package work with separate existing 20s budgets;
// package delivery has a 64-operation cap. Separate full-update consent adds
// another 20s/64-operation burst on its independent six-hour capture domain.
// Explicit local overview consent adds
// one shared 20s/64-operation process-and-volume burst, followed by the existing
// journal stage. These are per-stage limits, not a hard overall cycle deadline.
// Synchronous OS I/O and observers still require a supervisor for a hard limit.
// A separately preprovisioned action-client grant enables an independent joined
// controlled-action poll loop; default telemetry remains read-only.
func RunForeground(ctx context.Context, m Material, interval time.Duration, observe func(agentloop.Event) error) (agentloop.Summary, error) {
	return runForeground(ctx, m, interval, observe, nil, nil)
}
func runForeground(ctx context.Context, m Material, interval time.Duration, observe func(agentloop.Event) error, clock agentloop.Clock, random func(int64) int64) (agentloop.Summary, error) {
	if ctx == nil || !m.valid() || !m.config.platformAllowed(runtime.GOOS) || (interval != 0 && (interval < agentloop.MinInterval || interval > agentloop.MaxInterval)) {
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
	var updates *inventorySender
	if m.config.complete() {
		updates, e = openCompleteUpdatesSender(m)
		if e != nil {
			return agentloop.Summary{Reason: agentloop.InvalidState}, agentloop.ErrState
		}
		defer updates.Close()
	}
	var overview *overviewSender
	if m.config.complete() {
		overview, e = openOverviewSender(m)
		if e != nil {
			return agentloop.Summary{Reason: agentloop.InvalidState}, agentloop.ErrState
		}
		defer overview.Close()
	}
	var journal *journalSender
	if m.config.complete() {
		journal = openJournalSender(m)
		defer journal.Close()
	}
	// Controlled actions use a distinct, default-off root-local grant and loop.
	// Keep them outside the read-only telemetry scheduler callback. The sender
	// ownership lock is held first and until both loops have finished.
	if m.config.complete() {
		actions := openActionSender(m)
		actionContext, stopActions := context.WithCancel(ctx)
		actionsDone := make(chan struct{})
		go func() { defer close(actionsDone); runActionLoop(actionContext, actions) }()
		defer func() { stopActions(); <-actionsDone; actions.Close() }()
	}
	return agentloop.Run(ctx, agentloop.Config{Interval: interval}, agentloop.Dependencies{Clock: clock, Random: random, Observe: observe, Attempt: func(parent context.Context) agentloop.Result {
		journal.prune()
		report, err := runPreparedAttemptWithSystem(parent, m, state, system, inventory, runUsingState)
		if err == nil {
			err = runCompleteUpdatesAttempt(parent, updates, &report)
		}
		if err == nil {
			err = runOverviewAndJournal(parent, overview, &report, func(ctx context.Context) string {
				status := journal.prune()
				if journal != nil {
					status = runJournalAttempt(ctx, journal)
				}
				return status
			})
		}
		if err != nil {
			report.JournalStatus = journal.prune()
		}
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
		return agentloop.Result{Outcome: outcome, Metadata: agentloop.Metadata{CachedUpdatesStatus: report.CachedUpdatesStatus, CachedUpdatesSequence: report.CachedUpdatesSequence, CachedUpdatesOperations: report.CachedUpdatesOperations, ProcessesStatus: report.ProcessesStatus, ProcessesSequence: report.ProcessesSequence, VolumesStatus: report.VolumesStatus, VolumesSequence: report.VolumesSequence, OverviewOperations: report.OverviewOperations, JournalStatus: report.JournalStatus, Sequence: report.Sequence, Duplicate: report.Duplicate, RetriedPending: report.RetriedPending, DiscardedStale: report.DiscardedStale, AvailablePercentageFields: uint8(report.AvailablePercentageFields), UnavailablePercentageFields: uint8(report.UnavailablePercentageFields), InventoryStatus: report.InventoryStatus, InventorySequence: report.InventorySequence, InventoryOperations: report.InventoryOperations, SystemStatus: report.SystemStatus, SystemSequence: report.SystemSequence, SystemRetriedPending: report.SystemRetriedPending, SystemDiscardedStale: report.SystemDiscardedStale}}
	}})
}
