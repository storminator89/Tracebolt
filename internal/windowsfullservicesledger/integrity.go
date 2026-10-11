package windowsfullservicesledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/windowsfullservices"
)

// verifyCompleteRows proves canonical row/index agreement before search/count
// can claim complete absence. Work is bounded by8192 rows and8MiB canonical
// source bytes. Hashing streams the exact canonical array; no whole generation
// is retained in memory. The caller holds its authority transaction throughout.
func verifyCompleteRows(ctx context.Context, tx Transaction, device string, g Generation) error {
	rr, e := tx.QueryContext(ctx, `SELECT ordinal,body,name,identity,search,pid,state FROM wfs_rows WHERE device=? AND generation=? ORDER BY ordinal LIMIT 8193`, device, g.Manifest.GenerationID)
	if e != nil {
		return ErrStorage
	}
	defer rr.Close()
	hash := sha256.New()
	hash.Write([]byte("tracebolt.windows-complete-services.rows.v1\x00["))
	count, total := 0, 2
	previous := ""
	for rr.Next() {
		var ordinal int
		var raw []byte
		var name, identity, search string
		var pid *int64
		var state *string
		var row windowsfullservices.Row
		if rr.Scan(&ordinal, &raw, &name, &identity, &search, &pid, &state) != nil || ordinal != count || count >= windowsfullservices.MaxRows || len(raw) == 0 || len(raw) > 16384 || len(name) > 1024 || len(identity) > 1024 || len(search) > 4096 || json.Unmarshal(raw, &row) != nil || windowsfullservices.ValidateRow(row) != nil {
			return ErrStorage
		}
		canonical, _ := json.Marshal(row)
		if !bytes.Equal(raw, canonical) || row.Name != name || windowsfullservices.IdentityKey(row.Name) != identity || SearchText(row) != search || (row.PID == nil) != (pid == nil) || (row.State == nil) != (state == nil) || pid != nil && int64(*row.PID) != *pid || state != nil && *row.State != *state || count > 0 && previous >= row.Name {
			return ErrStorage
		}
		if count > 0 {
			hash.Write([]byte{','})
			total++
		}
		total += len(raw)
		if total > windowsfullservices.MaxSourceBytes || total > g.Manifest.RowsBytes {
			return ErrStorage
		}
		hash.Write(raw)
		previous = row.Name
		count++
	}
	if rr.Err() != nil || count != g.Manifest.RowCount || total != g.Manifest.RowsBytes {
		return ErrStorage
	}
	hash.Write([]byte{']'})
	if hex.EncodeToString(hash.Sum(nil)) != g.Manifest.RowsSHA256 {
		return ErrStorage
	}
	return nil
}
