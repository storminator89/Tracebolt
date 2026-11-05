package enrollmentstore

import "context"

// CheckReadable bypasses transact deliberately: readiness must not acquire a
// writer lock or persist the trusted ledger. Only existing core tables and
// protected path identity are checked, not full ledger integrity or durability.
func (s *Store) CheckReadable(ctx context.Context) error {
	if s == nil || s.storeState == nil || s.db == nil || ctx == nil || ctx.Err() != nil || s.checkPath() != nil {
		return ErrStorage
	}
	var states, credentials int
	if s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM (SELECT id FROM enrollment_state LIMIT 2)), EXISTS(SELECT 1 FROM enrollment_credentials LIMIT 1)`).Scan(&states, &credentials) != nil || states != 1 || ctx.Err() != nil || s.checkPath() != nil {
		return ErrStorage
	}
	return nil
}
