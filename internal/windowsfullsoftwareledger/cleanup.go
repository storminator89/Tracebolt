package windowsfullsoftwareledger

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// CleanupStep is trusted maintenance only. Every tick deletes at most 256 rows
// and 16 chunks from one noncurrent generation. Reservations remain until all
// physical records are removed; authority/grant/capture floors are never deleted.
func CleanupStep(ctx context.Context, tx Transaction, now time.Time) error {
	var device, generation string
	e := tx.QueryRowContext(ctx, `SELECT device,generation FROM wfw_generations WHERE state='garbage' ORDER BY device,generation LIMIT 1`).Scan(&device, &generation)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return ErrStorage
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM wfw_rows WHERE device=? AND generation=? AND ordinal IN (SELECT ordinal FROM wfw_rows WHERE device=? AND generation=? ORDER BY ordinal LIMIT 256)`, device, generation, device, generation); e != nil {
		return ErrStorage
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM wfw_chunks WHERE device=? AND generation=? AND ordinal IN (SELECT ordinal FROM wfw_chunks WHERE device=? AND generation=? ORDER BY ordinal LIMIT 16)`, device, generation, device, generation); e != nil {
		return ErrStorage
	}
	var remaining int
	if tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM wfw_rows WHERE device=? AND generation=?)+(SELECT count(*) FROM wfw_chunks WHERE device=? AND generation=?)`, device, generation, device, generation).Scan(&remaining) != nil {
		return ErrStorage
	}
	if remaining == 0 {
		if _, e = tx.ExecContext(ctx, `DELETE FROM wfw_generations WHERE device=? AND generation=? AND state='garbage'`, device, generation); e != nil {
			return ErrStorage
		}
	}
	return nil
}
