package health

import (
	"context"
	"time"
)

type maintenanceClockKey struct{}
type maintenanceTrustedClock struct{ now func() time.Time }

// WithMaintenanceClock is installed only by the trusted monitor/worker, never
// from a request. Sample again after serialized storage admission, not before it.
func WithMaintenanceClock(ctx context.Context, now func() time.Time) context.Context {
	return context.WithValue(ctx, maintenanceClockKey{}, maintenanceTrustedClock{now})
}
func MaintenanceNow(ctx context.Context, floor time.Time) (time.Time, error) {
	floor = floor.UTC()
	if !maintenanceTime(floor) {
		return time.Time{}, ErrInvalid
	}
	c, ok := ctx.Value(maintenanceClockKey{}).(maintenanceTrustedClock)
	if !ok {
		return floor, nil
	}
	if c.now == nil {
		return time.Time{}, ErrInvalid
	}
	now := c.now().UTC()
	if !maintenanceTime(now) || now.Before(floor) {
		return time.Time{}, ErrInvalid
	}
	return now, nil
}
