package windowsstorageio

import (
	"context"
	"errors"
)

type PerfDiskSource func(context.Context) (PerfDisk, error)

// CollectNative is synchronous and must run only inside the owning isolated
// worker. The worker's process deadline also bounds blocked native calls.
func CollectNative(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSource(ctx, r, nativePerfDisk)
}
func Collect(ctx context.Context, r Request) (Snapshot, error) { return CollectNative(ctx, r) }
func CollectWithSource(ctx context.Context, r Request, source PerfDiskSource) (Snapshot, error) {
	if ctx == nil {
		return Snapshot{}, ErrInvalid
	}
	if _, e := EncodeConsent(r.Consent, r.SenderBinding); e != nil {
		return Snapshot{}, e
	}
	if !r.Consent.Enabled {
		return Snapshot{}, ErrDisabled
	}
	s := Empty(r, ErrUnavailable.Error())
	if Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if source != nil {
		p, e := source(ctx)
		if e != nil {
			p = EmptyPerfDisk(SafeReason(e))
		}
		if !validPerfDisk(p) {
			p = EmptyPerfDisk(ErrMetadata.Error())
		}
		if p.SampleStartedAt != nil && p.SampleStartedAt.Before(r.CollectedAt) {
			p = EmptyPerfDisk(ErrTimebase.Error())
		}
		s.PerfDisk = p
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	return s, Validate(s)
}
func SafeReason(e error) string {
	for _, known := range []error{ErrDenied, ErrUnsupported, ErrMetadata, ErrBounds, ErrBudget, ErrMissing, ErrReset, ErrTimebase, ErrUnavailable} {
		if errors.Is(e, known) {
			return known.Error()
		}
	}
	if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return ErrBudget.Error()
	}
	return ErrUnavailable.Error()
}
