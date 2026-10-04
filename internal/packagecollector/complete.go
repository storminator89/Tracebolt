package packagecollector

import (
	"context"
	"errors"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	"sync/atomic"
	"time"
)

var ErrCompleteSource = errors.New("complete_package_source_failed")

type completeSourceError struct{ reason linuxpackages.Reason }

func (e completeSourceError) Error() string { return "complete_package_source_" + string(e.reason) }
func (e completeSourceError) Unwrap() error { return ErrCompleteSource }

// CompleteFailureReason exposes only the fixed source reason, never an OS or
// parser message. Unrecognized errors are a generic read failure.
func CompleteFailureReason(err error) linuxpackages.Reason {
	var failure completeSourceError
	if errors.As(err, &failure) {
		return failure.reason
	}
	return linuxpackages.ReasonReadFailed
}

// CollectComplete returns all supported rows from one successful full dpkg
// source parse, before selected-row Trim. It is not yet wired into any runtime
// profile or transport. It shares source protection and single-flight admission
// with Collect. Build's sourceErr parameter must receive this operation's error.
// Valid dpkg scope may coexist with unknown release applicability; detected
// replacement of either source invalidates the whole generation.
func CollectComplete(ctx context.Context, generationID string, at time.Time) (fullinventory.SourceInventory, error) {
	return collectCompleteWith(ctx, generationID, at, &admitted, newSystemProvider)
}

func collectCompleteWith(ctx context.Context, generationID string, at time.Time, slot *atomic.Bool, factory providerFactory) (fullinventory.SourceInventory, error) {
	full, err := collectWithFinalizer(ctx, generationID, at, slot, factory, func(s linuxpackages.Snapshot, start time.Time) (linuxpackages.Snapshot, error) {
		s.DurationMS = time.Since(start).Milliseconds()
		return s, nil
	})
	if err != nil {
		return fullinventory.SourceInventory{}, errInvalidInput
	}
	if full.Release.Reason == linuxpackages.ReasonSourceChanged {
		return fullinventory.SourceInventory{}, completeSourceError{linuxpackages.ReasonSourceChanged}
	}
	if full.Inventory.Quality != linuxpackages.Healthy || !full.Inventory.Complete || !full.Inventory.CountExact || full.Inventory.Truncated || full.Inventory.Items == nil {
		reason := full.Inventory.Reason
		if reason == linuxpackages.ReasonNone {
			reason = linuxpackages.ReasonInvalidSource
		}
		return fullinventory.SourceInventory{}, completeSourceError{reason}
	}
	if ctx.Err() != nil {
		return fullinventory.SourceInventory{}, completeSourceError{linuxpackages.ReasonTimeout}
	}
	return fullinventory.SourceInventory{GenerationID: full.GenerationID, CollectedAt: full.CollectedAt, DurationMS: full.DurationMS, Release: full.Release, Rows: full.Inventory.Items}, nil
}
