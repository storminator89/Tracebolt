// Package packagecollector reads only the fixed Linux release and dpkg sources.
// It is isolated from runtime profiles, transport, persistence and assessment.
package packagecollector

import (
	"context"
	"errors"
	"io"
	"localrmm/internal/linuxpackages"
	"sync/atomic"
	"time"
)

type sourceKind uint8

const (
	releaseSource sourceKind = iota
	inventorySource
)

type source interface {
	io.Reader
	recheck() error
	close()
}
type sourceProvider interface {
	open(sourceKind) (source, error)
	close()
}
type providerFactory func() (sourceProvider, error)

type fixedError string

func (e fixedError) Error() string { return string(e) }

const errInvalidInput fixedError = "package_collector_invalid_input"

type sourceFailure linuxpackages.Reason

func (e sourceFailure) Error() string { return string(e) }

// The admission slot is the only shared mutable collector state. It is never
// replaced by a test hook; inert tests supply a distinct slot and provider.
var admitted atomic.Bool

// Collect captures one agent-visible attempt. Invalid caller identity/time (or
// nil context) returns a fixed error before any source access. Source failures,
// unsupported builds, cancellation and concurrent admission return valid explicit
// unavailable snapshots. Cancellation is cooperative: no goroutine abandons a
// synchronous filesystem operation, and the slot is held until work returns.
func Collect(ctx context.Context, generationID string, at time.Time) (linuxpackages.Snapshot, error) {
	return collectWith(ctx, generationID, at, &admitted, newSystemProvider)
}

func collectWith(ctx context.Context, generationID string, at time.Time, slot *atomic.Bool, factory providerFactory) (linuxpackages.Snapshot, error) {
	start := time.Now()
	s := unavailable(generationID, at, linuxpackages.ReasonNotImplemented)
	if ctx == nil || linuxpackages.Validate(s) != nil {
		return linuxpackages.Snapshot{}, errInvalidInput
	}
	if ctx.Err() != nil {
		return finish(unavailable(generationID, at, linuxpackages.ReasonTimeout), start)
	}
	if !slot.CompareAndSwap(false, true) {
		return finish(unavailable(generationID, at, linuxpackages.ReasonCollectorBusy), start)
	}
	defer slot.Store(false)
	if ctx.Err() != nil {
		return finish(unavailable(generationID, at, linuxpackages.ReasonTimeout), start)
	}
	p, err := factory()
	if err != nil {
		if ctx.Err() != nil {
			return finish(unavailable(generationID, at, linuxpackages.ReasonTimeout), start)
		}
		return finish(unavailable(generationID, at, failureReason(err)), start)
	}
	// Resources are closed synchronously before final export and slot release.
	var release, inventory source
	closeAll := func() {
		if release != nil {
			release.close()
			release = nil
		}
		if inventory != nil {
			inventory.close()
			inventory = nil
		}
		p.close()
	}
	if ctx.Err() == nil {
		release, err = p.open(releaseSource)
		if err != nil {
			s.Release = releaseUnavailable(failureReason(err))
		} else {
			fields, parseErr := linuxpackages.ParseOSRelease(ctx, &contextReader{ctx, release})
			if parseErr != nil {
				s.Release = releaseUnavailable(parseReason(parseErr))
			} else {
				s.Release = linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Fields: fields}
			}
			if checkErr := release.recheck(); checkErr != nil {
				s.Release = releaseUnavailable(failureReason(checkErr))
			}
		}
	}
	if ctx.Err() == nil {
		inventory, err = p.open(inventorySource)
		if err != nil {
			s.Inventory = inventoryUnavailable(failureReason(err))
		} else {
			rows, parseErr := linuxpackages.ParseDpkgStatus(ctx, &contextReader{ctx, inventory})
			if parseErr != nil {
				s.Inventory = inventoryUnavailable(parseReason(parseErr))
			} else {
				observed, installed := uint64(len(rows)), uint64(0)
				for _, row := range rows {
					if row.InstallState == "installed" {
						installed++
					}
				}
				s.Inventory = linuxpackages.Inventory{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone,
					Complete: true, CountExact: true, ObservedCount: &observed, InstalledCount: &installed, Items: rows}
			}
			if checkErr := inventory.recheck(); checkErr != nil {
				s.Inventory = inventoryUnavailable(failureReason(checkErr))
			}
		}
	}
	// Recheck both sources only after the complete two-source attempt. A release
	// replacement during the dpkg read must not survive in the returned snapshot.
	if release != nil {
		if err := release.recheck(); err != nil {
			s.Release = releaseUnavailable(failureReason(err))
		}
	}
	if inventory != nil {
		if err := inventory.recheck(); err != nil {
			s.Inventory = inventoryUnavailable(failureReason(err))
		}
	}
	closeAll()
	if ctx.Err() != nil {
		s = unavailable(generationID, at, linuxpackages.ReasonTimeout)
	}
	s, err = finish(s, start)
	if ctx.Err() != nil {
		return finish(unavailable(generationID, at, linuxpackages.ReasonTimeout), start)
	}
	return s, err
}

func finish(s linuxpackages.Snapshot, start time.Time) (linuxpackages.Snapshot, error) {
	s.DurationMS = time.Since(start).Milliseconds()
	trimmed, err := linuxpackages.Trim(s)
	if err != nil {
		return linuxpackages.Snapshot{}, err
	}
	// Include first-pass sorting/trimming in elapsed time, then reapply the byte
	// cap because the decimal duration may have grown. This last export's own
	// execution time is necessarily outside its captured duration.
	trimmed.DurationMS = time.Since(start).Milliseconds()
	return linuxpackages.Trim(trimmed)
}

func unavailable(generationID string, at time.Time, reason linuxpackages.Reason) linuxpackages.Snapshot {
	return linuxpackages.Snapshot{SchemaVersion: linuxpackages.SchemaVersion, Scope: linuxpackages.SnapshotScope,
		GenerationID: generationID, CollectedAt: at, Release: releaseUnavailable(reason), Inventory: inventoryUnavailable(reason)}
}
func quality(reason linuxpackages.Reason) linuxpackages.Quality {
	if reason == linuxpackages.ReasonPermissionDenied {
		return linuxpackages.Denied
	}
	return linuxpackages.Unknown
}
func releaseUnavailable(reason linuxpackages.Reason) linuxpackages.ReleaseObservation {
	return linuxpackages.ReleaseObservation{Quality: quality(reason), Reason: reason}
}
func inventoryUnavailable(reason linuxpackages.Reason) linuxpackages.Inventory {
	return linuxpackages.Inventory{Quality: quality(reason), Reason: reason, Items: []linuxpackages.PackageRow{}}
}
func failureReason(err error) linuxpackages.Reason {
	var failure sourceFailure
	if errors.As(err, &failure) {
		switch linuxpackages.Reason(failure) {
		case linuxpackages.ReasonSourceMissing, linuxpackages.ReasonPermissionDenied, linuxpackages.ReasonInvalidSource,
			linuxpackages.ReasonReadFailed, linuxpackages.ReasonSourceChanged, linuxpackages.ReasonNotSupported:
			return linuxpackages.Reason(failure)
		}
	}
	return linuxpackages.ReasonReadFailed
}
func parseReason(err error) linuxpackages.Reason {
	switch {
	case errors.Is(err, linuxpackages.ErrReleaseInvalid), errors.Is(err, linuxpackages.ErrReleaseLimit),
		errors.Is(err, linuxpackages.ErrDpkgInvalid), errors.Is(err, linuxpackages.ErrDpkgLimit), errors.Is(err, linuxpackages.ErrDpkgEmpty):
		return linuxpackages.ReasonInvalidSource
	default:
		return linuxpackages.ReasonReadFailed
	}
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.r.Read(p)
	if contextErr := r.ctx.Err(); contextErr != nil {
		return n, contextErr
	}
	return n, err
}
