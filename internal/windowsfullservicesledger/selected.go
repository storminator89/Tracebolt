package windowsfullservicesledger

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/windowsfullservices"
	"strings"
)

// Selected verifies the current complete generation without retaining it, then
// loads at most eight exact names. Names are byte-exact, never folded or inferred
// absent. The caller owns the live enrollment/source transaction and freshness.
func Selected(ctx context.Context, tx Transaction, device string, g Generation, names []string) ([]windowsfullservices.Row, error) {
	if len(names) > 8 {
		return nil, windowsfullservices.ErrInvalid
	}
	if err := verifyCompleteRows(ctx, tx, device, g); err != nil {
		return nil, err
	}
	out := []windowsfullservices.Row{}
	if len(names) == 0 {
		return out, nil
	}
	args := []any{device, g.Manifest.GenerationID}
	marks := []string{}
	for _, n := range names {
		args = append(args, n)
		marks = append(marks, "?")
	}
	rr, e := tx.QueryContext(ctx, `SELECT body FROM wfs_rows WHERE device=? AND generation=? AND name IN (`+strings.Join(marks, ",")+`) ORDER BY name LIMIT 9`, args...)
	if e != nil {
		return nil, ErrStorage
	}
	defer rr.Close()
	for rr.Next() {
		var raw []byte
		var row windowsfullservices.Row
		if rr.Scan(&raw) != nil || json.Unmarshal(raw, &row) != nil || windowsfullservices.ValidateRow(row) != nil {
			return nil, ErrStorage
		}
		b, _ := json.Marshal(row)
		if !bytes.Equal(b, raw) {
			return nil, ErrStorage
		}
		out = append(out, row)
	}
	if rr.Err() != nil || len(out) > len(names) {
		return nil, ErrStorage
	}
	return out, nil
}
