package journalview

import (
	"context"
	"sync/atomic"
	"time"
)

var admitted atomic.Bool

// Collect is an unintegrated source boundary, not permission to read a host.
// Runtime callers must first require a separately approved local journal-read
// grant under their stopped, reviewed numeric identity. Existing telemetry or
// system-inventory consent does not authorize journal message content.
func Collect(ctx context.Context, q Query, now time.Time) (Snapshot, error) {
	return collectWith(ctx, q, now, &admitted, newSystemProvider)
}

// CollectWithProvider never constructs the real provider or executes a command.
// It is synchronous, including cancellation and source/resource cleanup.
func CollectWithProvider(ctx context.Context, q Query, now time.Time, p Provider) (Snapshot, error) {
	if p == nil {
		return Snapshot{}, ErrInvalidInput
	}
	return collectWith(ctx, q, now, &admitted, func() (Provider, error) { return p, nil })
}
func collectWith(ctx context.Context, q Query, now time.Time, slot *atomic.Bool, factory func() (Provider, error)) (Snapshot, error) {
	if ctx == nil || slot == nil || factory == nil || ValidateQuery(q, now) != nil {
		return Snapshot{}, ErrInvalidInput
	}
	s := empty(q, now)
	if ctx.Err() != nil {
		return mark(s, ReasonTimeout), nil
	}
	if !slot.CompareAndSwap(false, true) {
		return mark(s, ReasonCollectorBusy), nil
	}
	defer slot.Store(false)
	ctx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()
	p, err := factory()
	if err != nil {
		return mark(s, failureReason(err)), nil
	}
	if p == nil {
		return mark(s, ReasonInvalidSource), nil
	}
	r, reason, err := p.Open(ctx, q)
	if err != nil {
		if r != nil {
			r.Close()
		}
		return mark(s, failureReason(err)), nil
	}
	if r == nil {
		return mark(s, ReasonInvalidSource), nil
	}
	if reason != ReasonNone && reason != ReasonByteLimit && reason != ReasonVisibilityRestricted {
		r.Close()
		return mark(s, ReasonInvalidSource), nil
	}
	s, err = parse(ctx, q, now, r, reason)
	closeErr := r.Close()
	if err != nil {
		return Snapshot{}, err
	}
	if ctx.Err() != nil {
		return mark(s, ReasonTimeout), nil
	}
	if closeErr != nil {
		return mark(s, ReasonReadFailed), nil
	}
	return s, nil
}
