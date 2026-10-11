package main

import (
	"context"
	"errors"
	"time"

	"localrmm/internal/windowsservice"
)

// receiptStore is deliberately read/verify/close only. Existing native stores
// own the cross-process exclusive lock; this coordinator creates no lock file,
// schema, grant, or process-global reentrant lock.
type receiptStore interface {
	Read(string) ([]byte, error)
	Verify() error
	Close() error
}
type receiptOpener func() (windowsservice.Layout, receiptStore, error)

// withReceiptLease keeps receipt ownership and all following effects in the
// same exclusive session. Every production receipt-dependent CLI path and GUI
// removal uses this boundary; fresh setup holds its original journal instead.
func withReceiptLease(ctx context.Context, open receiptOpener, perform func(installReceipt, receiptStore) (any, error)) (result any, err error) {
	if ctx == nil || open == nil || perform == nil {
		return nil, errLifecycle
	}
	if err = lifecycleContextError(ctx); err != nil {
		return nil, err
	}
	layout, store, err := open()
	if store != nil {
		defer func() {
			releaseErr := joinLifecycleErrors(receiptLeaseFailure(store.Close()), lifecycleContextError(ctx))
			priorErr := err
			err = joinLifecycleErrors(err, releaseErr)
			if releaseErr != nil {
				if r, ok := result.(windowsservice.RestartResult); ok {
					if priorErr == nil {
						r.Phase = "lease-release"
					}
					r.Outcome = "intervention-required"
					result = r
				}
			}
		}()
	}
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errLifecycle
	}
	if err = lifecycleContextError(ctx); err != nil {
		return nil, err
	}
	raw, err := store.Read("receipt.json")
	defer clear(raw)
	if err != nil {
		return nil, receiptLeaseFailure(err)
	}
	receipt, err := decodeInstallReceipt(raw, layout)
	if err != nil {
		return nil, err
	}
	if err = store.Verify(); err != nil {
		return nil, receiptLeaseFailure(err)
	}
	if err = lifecycleContextError(ctx); err != nil {
		return nil, err
	}
	result, err = perform(receipt, store)
	verifyErr := joinLifecycleErrors(receiptLeaseFailure(store.Verify()), lifecycleContextError(ctx))
	priorErr := err
	err = joinLifecycleErrors(err, verifyErr)
	if verifyErr != nil {
		if r, ok := result.(windowsservice.RestartResult); ok {
			if priorErr == nil {
				r.Phase = "lease-verify"
			}
			r.Outcome = "intervention-required"
			result = r
		}
	}
	return result, err
}

type serviceLifecycleSteps struct {
	start, stop, uninstall func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error)
	restart                func(context.Context, windowsservice.Receipt, windowsservice.LifecycleLease) (windowsservice.RestartResult, error)
}

func serviceLifecycleOperation(ctx context.Context, mode string, r windowsservice.Receipt, lease windowsservice.LifecycleLease, s serviceLifecycleSteps) (any, error) {
	switch mode {
	case "start":
		if s.start != nil {
			return s.start(ctx, r)
		}
	case "stop":
		if s.stop != nil {
			return s.stop(ctx, r)
		}
	case "uninstall":
		if s.uninstall != nil {
			return s.uninstall(ctx, r)
		}
	case "restart":
		if s.restart != nil {
			return s.restart(ctx, r, lease)
		}
	}
	return nil, errLifecycle
}

// Keep the original concrete error when cleanup succeeds. When both fail, the
// first branch is the operation; safe diagnostic walkers preserve that order.
func joinLifecycleErrors(primary, secondary error) error {
	if primary == nil {
		return secondary
	}
	if secondary == nil {
		return primary
	}
	return errors.Join(primary, secondary)
}

// A synchronous call can return after its deadline before a timer's goroutine
// gets CPU. Check the deadline itself as well as cooperative cancellation.
func lifecycleContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func receiptLeaseFailure(err error) error {
	if err == nil {
		return nil
	}
	return marked(windowsservice.PhaseReceipt, windowsservice.ReasonStateRejected, err)
}
