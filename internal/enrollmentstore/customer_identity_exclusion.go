package enrollmentstore

import (
	"context"
	"os"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

// The caller compares identities with os.SameFile before nesting source locks.
// Never return the store path in API responses or logs.
func (s *Store) CustomerEnrollmentLeaseIdentity() (os.FileInfo, error) {
	if s == nil || s.storeState == nil || s.checkPath() != nil {
		return nil, ErrStorage
	}
	return s.info, nil
}

// WithCustomerIdentityExclusion holds this source's enrollment transaction
// while a caller verifies and commits metadata for another source. All stored
// identities, including terminal states, are checked. No state is changed.
// All callers must acquire sources in their existing stable order, then the
// operator store; a callback must not re-enter an already held enrollment store.
func (s *Store) WithCustomerIdentityExclusion(ctx context.Context, ids []string, clock func() time.Time, fn func(func(time.Time) error) error) error {
	if s == nil || s.storeState == nil || ctx == nil || clock == nil || fn == nil || len(ids) < 1 || len(ids) > 25 {
		return enrollmentstate.ErrInvalid
	}
	wanted := map[string]bool{}
	for _, id := range ids {
		if !enrollmentcrypto.ValidID(id, "agent_") || wanted[id] {
			return enrollmentstate.ErrInvalid
		}
		wanted[id] = true
	}
	started := clock().UTC()
	if !validStoreTime(started) {
		return enrollmentstate.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error {
		for _, snap := range t.engine.Snapshots() {
			if wanted[snap.Approval.DeviceID] {
				return enrollmentstate.ErrConflict
			}
		}
		last := started
		guard := func(minimum time.Time) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			now := clock().UTC()
			if !validStoreTime(now) || now.Before(started) || now.Before(last) || now.Before(minimum) || now.Sub(started) > 5*time.Second {
				return enrollmentstate.ErrConflict
			}
			last = now
			return nil
		}
		if err := guard(started); err != nil {
			return err
		}
		return fn(guard)
	})
}
