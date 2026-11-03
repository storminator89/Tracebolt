package store

import (
	"context"
	"errors"
)

// CheckReadable reads existing core tables through the real pool. It never
// opens/initializes a store, begins a writer transaction, or changes rows. This
// is table readability, not full integrity, write capacity or commit durability.
func (s *Store) CheckReadable(ctx context.Context) error {
	unavailable := errors.New("operator storage read unavailable")
	if s == nil || s.db == nil || ctx == nil || ctx.Err() != nil {
		return unavailable
	}
	var devices, cases, health int
	if s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM devices LIMIT 1), EXISTS(SELECT 1 FROM cases LIMIT 1), EXISTS(SELECT 1 FROM health_devices LIMIT 1)`).Scan(&devices, &cases, &health) != nil || ctx.Err() != nil {
		return unavailable
	}
	return nil
}
