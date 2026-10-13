package store

import (
	"context"
	"database/sql"
	"time"

	"localrmm/internal/windowsservicehealth"
)

// configureWindowsServiceGuarded shares the existing service ledger transaction.
// The caller holds the enrollment-to-operator lease. No enrollment reads occur
// while SQLite is held; guard only checks that lease, live session and time.
// The optional internal selection guard adds a transaction-bound constraint.
func (s *Store) configureWindowsServiceGuarded(ctx context.Context, input windowsservicehealth.Input, enabled bool, names []string, expected uint64, clock func() time.Time, guard func(time.Time) error, groupCheck func(*sql.Tx) error) (windowsservicehealth.State, error) {
	if clock == nil || guard == nil {
		return windowsservicehealth.State{}, windowsservicehealth.ErrInvalid
	}
	var original *windowsservicehealth.State
	var appliedAt time.Time
	check := func(tx *sql.Tx) error {
		if groupCheck != nil {
			if err := groupCheck(tx); err != nil {
				return err
			}
		}

		before := clock().UTC()
		if err := guard(before); err != nil {
			return err
		}
		// The authority callback may consume time. Check selection freshness
		// against the clock after that callback, never its earlier sample.
		now := clock().UTC()
		if now.Before(before) {
			return windowsservicehealth.ErrInvalid
		}
		if original != nil {
			if now.Before(appliedAt) {
				return windowsservicehealth.ErrInvalid
			}
			// Re-run admission on the original policy at final commit time. This
			// neither evaluates health nor refreshes the source capture time.
			copy := *original
			if err := copy.Configure(input, enabled, names, expected, now); err != nil {
				return err
			}
		}
		return ctx.Err()
	}
	return s.updateWindowsService(ctx, input.DeviceID, func(state *windowsservicehealth.State) error {
		copy := *state
		original = &copy
		appliedAt = clock().UTC()
		if err := guard(appliedAt); err != nil {
			return err
		}
		return state.Configure(input, enabled, names, expected, appliedAt)
	}, check)
}

func (s *Store) ConfigureWindowsServiceGuarded(ctx context.Context, input windowsservicehealth.Input, enabled bool, names []string, expected uint64, clock func() time.Time, guard func(time.Time) error) (windowsservicehealth.State, error) {
	return s.configureWindowsServiceGuarded(ctx, input, enabled, names, expected, clock, guard, nil)
}

// EvaluateWindowsCompleteServiceGuarded is the complete-source-only commit seam.
// Its caller holds the live enrollment lease; source time is never borrowed from
// the monitor's earlier read or the telemetry frame. V1 evaluation is unchanged.
func (s *Store) EvaluateWindowsCompleteServiceGuarded(ctx context.Context, input windowsservicehealth.Input, clock func() time.Time, epoch string, guard func(time.Time) error) (windowsservicehealth.State, error) {
	if !input.Complete || clock == nil || guard == nil {
		return windowsservicehealth.State{}, windowsservicehealth.ErrInvalid
	}
	var appliedAt time.Time
	check := func(*sql.Tx) error {
		at := clock().UTC()
		if !appliedAt.IsZero() && at.Before(appliedAt) {
			return windowsservicehealth.ErrInvalid
		}
		if e := guard(at); e != nil {
			return e
		}
		end := clock().UTC()
		if end.Before(at) || input.Sample.Complete != nil && !input.Sample.Complete.Source.Fresh(end) {
			return windowsservicehealth.ErrInvalid
		}
		return ctx.Err()
	}
	return s.updateWindowsService(ctx, input.DeviceID, func(state *windowsservicehealth.State) error {
		if state.SchemaVersion != windowsservicehealth.CompleteStateSchema {
			return windowsservicehealth.ErrInvalid
		}
		appliedAt = clock().UTC()
		if e := guard(appliedAt); e != nil {
			return e
		}
		at := clock().UTC()
		if at.Before(appliedAt) {
			return windowsservicehealth.ErrInvalid
		}
		appliedAt = at
		return state.Evaluate(input, at, epoch)
	}, check)
}
