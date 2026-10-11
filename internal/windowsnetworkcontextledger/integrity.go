package windowsnetworkcontextledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/windowsnetworkcontext"
)

// verifyCompleteRows proves canonical row/index agreement before search/count
// can claim complete absence. Work is bounded by 4352 rows and 2 MiB canonical
// source bytes. Hashing streams the exact canonical array; no whole generation
// is retained in memory. The caller holds its authority transaction throughout.
func verifyCompleteRows(ctx context.Context, tx Transaction, device string, g Generation) error {
	rr, e := tx.QueryContext(ctx, `SELECT ordinal,body,id,interface_index,kind,search FROM wnc_rows WHERE device=? AND generation=? ORDER BY ordinal LIMIT 4353`, device, g.Manifest.GenerationID)
	if e != nil {
		return ErrStorage
	}
	defer rr.Close()
	hash := sha256.New()
	hash.Write([]byte("tracebolt.windows-network-context.rows.v1\x00["))
	count, total := 0, 2
	var previous uint32
	for rr.Next() {
		var ordinal int
		var raw []byte
		var id, index uint32
		var search, kind string
		var row windowsnetworkcontext.Row
		if rr.Scan(&ordinal, &raw, &id, &index, &kind, &search) != nil || ordinal != count || count >= windowsnetworkcontext.MaxRows || len(raw) == 0 || len(raw) > 16384 || len(search) > 8192 || json.Unmarshal(raw, &row) != nil || windowsnetworkcontext.ValidateRow(row) != nil {
			return ErrStorage
		}
		canonical, _ := json.Marshal(row)
		if !bytes.Equal(raw, canonical) || row.ID != uint32(count+1) || row.ID != id || row.InterfaceIndex != index || row.Kind != kind || SearchText(row) != search || count > 0 && previous >= row.ID {
			return ErrStorage
		}
		if count > 0 {
			hash.Write([]byte{','})
			total++
		}
		total += len(raw)
		if total > windowsnetworkcontext.MaxSourceBytes || total > g.Manifest.RowsBytes {
			return ErrStorage
		}
		hash.Write(raw)
		previous = row.ID
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
