package windowsfullprocessesledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/windowsfullprocesses"
)

// verifyCompleteRows proves canonical row/index agreement before search/count
// can claim complete absence. Work is bounded by 32768 rows and 8 MiB canonical
// source bytes. Hashing streams the exact canonical array; no whole generation
// is retained in memory. The caller holds its authority transaction throughout.
func verifyCompleteRows(ctx context.Context, tx Transaction, device string, g Generation) error {
	rr, e := tx.QueryContext(ctx, `SELECT ordinal,body,pid,parent_pid,name,threads,search FROM wfp_rows WHERE device=? AND generation=? ORDER BY ordinal LIMIT 32769`, device, g.Manifest.GenerationID)
	if e != nil {
		return ErrStorage
	}
	defer rr.Close()
	hash := sha256.New()
	hash.Write([]byte("tracebolt.windows-complete-processes.rows.v1\x00["))
	count, total := 0, 2
	var previous uint32
	for rr.Next() {
		var ordinal int
		var raw []byte
		var pid, parentPID, threads uint32
		var search string
		var name *string
		var row windowsfullprocesses.Row
		if rr.Scan(&ordinal, &raw, &pid, &parentPID, &name, &threads, &search) != nil || ordinal != count || count >= windowsfullprocesses.MaxRows || len(raw) == 0 || len(raw) > 16384 || len(search) > 8192 || json.Unmarshal(raw, &row) != nil || windowsfullprocesses.ValidateRow(row) != nil {
			return ErrStorage
		}
		canonical, _ := json.Marshal(row)
		if !bytes.Equal(raw, canonical) || row.PID != pid || row.ParentPID != parentPID || row.Threads != threads || !sameText(row.Name, name) || SearchText(row) != search || count > 0 && previous >= row.PID {
			return ErrStorage
		}
		if count > 0 {
			hash.Write([]byte{','})
			total++
		}
		total += len(raw)
		if total > windowsfullprocesses.MaxSourceBytes || total > g.Manifest.RowsBytes {
			return ErrStorage
		}
		hash.Write(raw)
		previous = row.PID
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
