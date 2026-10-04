package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/overviewledger"
	"time"
)

type overviewClockKey struct{}
type overviewTrustedClock struct{ now func() time.Time }

// WithOverviewClock is installed only by trusted service/ingress code. The key
// and value types are private; request JSON/headers cannot supply this clock.
// Direct deterministic Store fixtures may explicitly omit the hook and use their
// supplied trusted timestamp. Production overview entry points install it.
func WithOverviewClock(ctx context.Context, trustedNow func() time.Time) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, overviewClockKey{}, overviewTrustedClock{now: trustedNow})
}

// Sample only after BEGIN/load at the action boundary, and again after COMMIT
// for row/metadata output. max prevents a later in-request clock rollback from
// reviving authority or a cursor already past its previously observed boundary.
func overviewNow(ctx context.Context, floor time.Time) (time.Time, error) {
	if ctx == nil || !validStoreTime(floor) {
		return time.Time{}, enrollmentstate.ErrInvalid
	}
	floor = floor.UTC()
	clock, ok := ctx.Value(overviewClockKey{}).(overviewTrustedClock)
	if !ok {
		return floor, nil
	}
	if clock.now == nil {
		return time.Time{}, enrollmentstate.ErrInvalid
	}
	now := clock.now().UTC()
	if !validStoreTime(now) {
		return time.Time{}, enrollmentstate.ErrInvalid
	}
	if now.After(floor) {
		return now, nil
	}
	return floor, nil
}

// This unexported result boundary is set only by a committed Store operation.
// No public wire field can manufacture/extend an output lifetime.
type overviewOutputBoundary struct {
	checkedAt, expiresAt time.Time
	expired              error
}

func overviewBoundary(checked time.Time, notAfter int64) overviewOutputBoundary {
	return overviewOutputBoundary{checkedAt: checked, expiresAt: time.Unix(notAfter, 0).UTC(), expired: enrollmentstate.ErrExpired}
}
func (b *overviewOutputBoundary) limit(at time.Time, err error) {
	if at.Before(b.expiresAt) {
		b.expiresAt = at
		b.expired = err
	}
}
func (b overviewOutputBoundary) validate(now time.Time) error {
	if !validStoreTime(now) || !validStoreTime(b.checkedAt) || !validStoreTime(b.expiresAt) || b.expired == nil {
		return ErrStorage
	}
	now = now.UTC()
	if now.Before(b.checkedAt) {
		now = b.checkedAt
	}
	if !now.Before(b.expiresAt) {
		return b.expired
	}
	return nil
}
func (out OverviewPageResult) ValidateAt(now time.Time) error { return out.boundary.validate(now) }
func (out OverviewStatus) ValidateAt(now time.Time) error     { return out.boundary.validate(now) }
func statusOutputBoundary(out OverviewStatus, notAfter int64) overviewOutputBoundary {
	b := overviewBoundary(out.ServerNow, notAfter)
	for _, section := range []OverviewSectionStatus{out.Processes, out.Volumes} {
		for _, state := range []*overviewledger.GenerationStatus{section.Complete, section.Transfer} {
			if state != nil && (state.State == "complete" || state.State == "pending") {
				b.limit(state.ExpiresAt, overviewledger.ErrExpired)
			}
		}
	}
	return b
}
