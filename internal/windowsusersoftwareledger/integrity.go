package windowsusersoftwareledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/windowsusersoftware"
)

// verifyCompleteRows proves canonical row/index agreement before search/count
// can claim complete absence. Work is bounded by 4096 rows and 4 MiB canonical
// source bytes. Hashing streams the exact canonical array; no whole generation
// is retained in memory. The caller holds its authority transaction throughout.
func verifyCompleteRows(ctx context.Context, tx Transaction, device string, g Generation) error {
	rr, e := tx.QueryContext(ctx, `SELECT ordinal,body,registration_id,source,name,version,publisher,search FROM wus_rows WHERE device=? AND generation=? ORDER BY ordinal LIMIT 4097`, device, g.Manifest.GenerationID)
	if e != nil {
		return ErrStorage
	}
	defer rr.Close()
	hash := sha256.New()
	hash.Write([]byte("tracebolt.windows-selected-user-software.rows.v1\x00["))
	count, total := 0, 2
	previous := ""
	for rr.Next() {
		var ordinal int
		var raw []byte
		var registration, view, search string
		var name, version, publisher *string
		var row windowsusersoftware.Row
		if rr.Scan(&ordinal, &raw, &registration, &view, &name, &version, &publisher, &search) != nil || ordinal != count || count >= windowsusersoftware.MaxRows || len(raw) == 0 || len(raw) > 16384 || len(search) > 8192 || json.Unmarshal(raw, &row) != nil || windowsusersoftware.ValidateRow(row) != nil || windowsusersoftware.ValidateSourceRows([]windowsusersoftware.Row{row}, g.Manifest.HKCUStatus, g.Manifest.MSIXStatus) != nil {
			return ErrStorage
		}
		canonical, _ := json.Marshal(row)
		if !bytes.Equal(raw, canonical) || row.RegistrationID != registration || row.Source != view || !sameText(row.Name, name) || !sameText(row.Version, version) || !sameText(row.Publisher, publisher) || SearchText(row) != search || count > 0 && previous >= row.RegistrationID {
			return ErrStorage
		}
		if count > 0 {
			hash.Write([]byte{','})
			total++
		}
		total += len(raw)
		if total > windowsusersoftware.MaxSourceBytes || total > g.Manifest.RowsBytes {
			return ErrStorage
		}
		hash.Write(raw)
		previous = row.RegistrationID
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
