package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentstate"
	"time"
)

// System, package, overview, endpoint-identity and complete-update metadata,
// plus journal status, share one total waiting/read permit through a short
// maintenance burst. Keep it until the whole read finishes: further readers
// cannot build a queue behind it.
// The existing gate still permits exactly one inventory operation, and all
// writers/maintenance retain their nonblocking admission policy.
const systemMetadataAdmissionWait = 750 * time.Millisecond

func (s *Store) systemReadAdmission(ctx context.Context) (func(), error) {
	if s == nil || s.storeState == nil || ctx == nil {
		return nil, enrollmentstate.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !completeProfile(s.config.Binding.CollectionProfile) {
		return nil, enrollmentstate.ErrProof
	}
	select {
	case s.systemMetadataReads <- struct{}{}:
	default:
		return nil, ErrInventoryBusy
	}
	dropReader := func() { <-s.systemMetadataReads }
	deadline := time.Now().Add(systemMetadataAdmissionWait)
	timer := time.NewTimer(systemMetadataAdmissionWait)
	defer timer.Stop()
	select {
	case s.inventoryCalls <- struct{}{}:
		release := func() { <-s.inventoryCalls; dropReader() }
		if err := ctx.Err(); err != nil {
			release()
			return nil, err
		}
		if !time.Now().Before(deadline) {
			release()
			return nil, ErrInventoryBusy
		}
		return release, nil
	case <-ctx.Done():
		dropReader()
		return nil, ctx.Err()
	case <-timer.C:
		dropReader()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, ErrInventoryBusy
	}
}

type systemViewClockKey struct{}
type systemViewTrustedClock struct{ now func() time.Time }

// WithSystemViewClock supplies the shared metadata-read clock. It is installed
// by the trusted service, never by request
// fields. Direct deterministic Store fixtures retain their explicit timestamp.
func WithSystemViewClock(ctx context.Context, now func() time.Time) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, systemViewClockKey{}, systemViewTrustedClock{now})
}

func systemViewNow(ctx context.Context, floor time.Time) (time.Time, error) {
	if ctx == nil || !validStoreTime(floor) {
		return time.Time{}, enrollmentstate.ErrInvalid
	}
	floor = floor.UTC()
	clock, ok := ctx.Value(systemViewClockKey{}).(systemViewTrustedClock)
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

type systemViewReadState struct {
	checkedAt           time.Time
	certificateNotAfter int64
	observationAt       time.Time
}

// RecheckAt ages only the already authorized immutable metadata. It never
// refreshes collection/receipt times or manufactures data. Recheck after COMMIT
// and just before API output; a clock rollback cannot revive expired values.
func (v SystemView) RecheckAt(now time.Time) (SystemView, error) {
	if v.readState == nil || !validStoreTime(now) || !validStoreTime(v.readState.checkedAt) || !validStoreTime(v.ServerNow) {
		return SystemView{}, ErrStorage
	}
	now = now.UTC()
	if now.Before(v.readState.checkedAt) {
		now = v.readState.checkedAt
	}
	if now.Before(v.ServerNow) {
		now = v.ServerNow
	}
	v.ServerNow = now
	if v.Status == "revoked" {
		return v, nil
	}
	if v.readState.certificateNotAfter > 0 && now.Unix() >= v.readState.certificateNotAfter {
		v.Status = "expired"
		v.Latest = nil
		v.LastComplete = SystemLastComplete{}
		return v, nil
	}
	if !v.readState.observationAt.IsZero() {
		v.Status = systemAge(v.readState.observationAt, now)
		if v.Status == "expired" {
			v.Latest = nil
		}
		age := func(section *SystemSectionSummary) *SystemSectionSummary {
			if section == nil {
				return nil
			}
			copy := *section
			copy.Status = systemAge(copy.Meta.ObservedAt, now)
			if copy.Status == "expired" {
				return nil
			}
			return &copy
		}
		v.LastComplete.Services = age(v.LastComplete.Services)
		v.LastComplete.Sockets = age(v.LastComplete.Sockets)
	}
	return v, nil
}
