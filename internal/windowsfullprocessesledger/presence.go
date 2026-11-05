package windowsfullprocessesledger

import (
	"context"
	"localrmm/internal/windowsfullprocesses"
)

// Presence verifies every row before returning exact case-sensitive name counts.
// It never returns PIDs or copies the generation. Unavailable names prevent an
// absent-name conclusion but do not erase a positive match.
func Presence(ctx context.Context, tx Transaction, device string, g Generation, names []string) (map[string]int, int, error) {
	if names == nil || len(names) > 8 {
		return nil, 0, windowsfullprocesses.ErrInvalid
	}
	counts := map[string]int{}
	for _, n := range names {
		if windowsfullprocesses.ValidateRow(windowsfullprocesses.Row{Name: &n, NameQuality: "observed"}) != nil {
			return nil, 0, windowsfullprocesses.ErrInvalid
		}
		if _, ok := counts[n]; ok {
			return nil, 0, windowsfullprocesses.ErrInvalid
		}
		counts[n] = 0
	}
	if e := verifyCompleteRows(ctx, tx, device, g); e != nil {
		return nil, 0, e
	}
	var unavailable int
	if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM wfp_rows WHERE device=? AND generation=? AND name IS NULL`, device, g.Manifest.GenerationID).Scan(&unavailable); e != nil {
		return nil, 0, ErrStorage
	}
	for name := range counts {
		var count int
		if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM wfp_rows WHERE device=? AND generation=? AND name=? COLLATE BINARY`, device, g.Manifest.GenerationID, name).Scan(&count); e != nil {
			return nil, 0, ErrStorage
		}
		counts[name] = count
	}
	return counts, unavailable, nil
}
