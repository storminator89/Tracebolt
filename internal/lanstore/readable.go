package lanstore

import "context"

// CheckReadable checks existing trust/sample table readability, not semantic
// ledger integrity, future write capacity or durability. No writer transaction,
// schema initialization, credential operation or repair is performed.
func (s *Store) CheckReadable(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil || ctx.Err() != nil {
		return ErrStorage
	}
	var agents, samples int
	if s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM lan_agents LIMIT 1), EXISTS(SELECT 1 FROM lan_samples LIMIT 1)`).Scan(&agents, &samples) != nil || ctx.Err() != nil {
		return ErrStorage
	}
	return nil
}
