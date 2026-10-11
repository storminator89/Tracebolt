package enrollmentstore

import (
	"context"
	"database/sql"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
)

// The independent immutable credential-used marker survives optional table
// loss. Used history authority is never recreated from a partial database.
const windowsHistoryMetaSchema = `CREATE TABLE enrollment_windows_history_meta(id INTEGER PRIMARY KEY CHECK(id=1), last_time TEXT NOT NULL) STRICT`
const windowsHistoryAuthoritySchema = `CREATE TABLE enrollment_windows_history_authority(device TEXT PRIMARY KEY NOT NULL, certificate TEXT NOT NULL, floor TEXT NOT NULL, capability_sequence TEXT NOT NULL, capability_digest TEXT NOT NULL, capability BLOB NOT NULL CHECK(length(capability)<=4096), request_present INTEGER NOT NULL CHECK(request_present IN (0,1))) STRICT`
const windowsHistoryRequestsSchema = `CREATE TABLE enrollment_windows_history_requests(device TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_windows_history_authority(device), body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=32768), result_digest TEXT NOT NULL, local_status TEXT NOT NULL) STRICT`

func windowsHistoryObjects() []inventoryledger.SchemaObject {
	return []inventoryledger.SchemaObject{{Type: "table", Name: "enrollment_windows_history_meta", SQL: windowsHistoryMetaSchema}, {Type: "table", Name: "enrollment_windows_history_authority", SQL: windowsHistoryAuthoritySchema}, {Type: "table", Name: "enrollment_windows_history_requests", SQL: windowsHistoryRequestsSchema}}
}
func windowsHistorySchemaPresent(ctx context.Context, c *sql.Conn, profile string) (bool, error) {
	var n int
	if c.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name LIKE 'enrollment_windows_history\_%' ESCAPE '\'`).Scan(&n) != nil {
		return false, ErrStorage
	}
	if n == 0 {
		return false, nil
	}
	if profile != enrollmentcrypto.CollectionProfileWindowsInventory || n != len(windowsHistoryObjects()) {
		return false, ErrStorage
	}
	var count int
	var last string
	if c.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_history_meta`).Scan(&count) != nil || count != 1 || c.QueryRowContext(ctx, `SELECT last_time FROM enrollment_windows_history_meta WHERE id=1`).Scan(&last) != nil {
		return false, ErrStorage
	}
	if last != "" {
		if _, e := windowsHistoryTime(last); e != nil {
			return false, ErrStorage
		}
	}
	if c.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_history_authority`).Scan(&count) != nil || count > 25 {
		return false, ErrStorage
	}
	if c.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_history_requests`).Scan(&count) != nil || count > 25 {
		return false, ErrStorage
	}
	return true, nil
}
func (s *Store) InitializeWindowsHistory(ctx context.Context) error {
	if s == nil || s.storeState == nil || s.config.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return enrollmentstate.ErrProof
	}
	return s.transact(ctx, func(t *transaction) error {
		present, e := windowsHistorySchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
		if e != nil || present {
			return e
		}
		for _, o := range windowsHistoryObjects() {
			if _, e = t.conn.ExecContext(ctx, o.SQL); e != nil {
				return ErrStorage
			}
		}
		if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_history_meta(id,last_time) VALUES(1,'')`); e != nil {
			return ErrStorage
		}
		return validateSchema(ctx, t.conn, s.config.Binding.CollectionProfile)
	})
}

// Immutable credential markers are independent of the optional authority tables.
// Both directions are checked, including a used identity whose rows disappeared.
func validateWindowsHistoryUsedState(ctx context.Context, t *transaction, profile string) error {
	used := map[string]string{}
	for id, c := range t.credentials {
		if !c.WindowsHistoryAuthorityInitialized {
			continue
		}
		snap, e := t.engine.Get(id)
		if e != nil || profile != enrollmentcrypto.CollectionProfileWindowsInventory || snap.Platform != "windows" || snap.Approval.DeviceID == "" {
			return ErrStorage
		}
		if _, ok := used[snap.Approval.DeviceID]; ok {
			return ErrStorage
		}
		used[snap.Approval.DeviceID] = snap.Issuance.CertificateHash
	}
	if profile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return nil
	}
	present, e := windowsHistorySchemaPresent(ctx, t.conn, profile)
	if e != nil {
		return e
	}
	if !present {
		if len(used) > 0 {
			return ErrStorage
		}
		return nil
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT device,certificate FROM enrollment_windows_history_authority ORDER BY device`)
	if e != nil {
		return ErrStorage
	}
	var devices []string
	for rows.Next() {
		var device, cert string
		if rows.Scan(&device, &cert) != nil || used[device] != cert || cert == "" {
			rows.Close()
			return ErrStorage
		}
		devices = append(devices, device)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(devices) != len(used) {
		return ErrStorage
	}
	for _, device := range devices {
		if _, e := loadWindowsHistoryAuthority(ctx, t, device); e != nil {
			return e
		}
	}
	var orphan int
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_history_requests r LEFT JOIN enrollment_windows_history_authority a ON a.device=r.device WHERE a.device IS NULL`).Scan(&orphan) != nil || orphan != 0 {
		return ErrStorage
	}
	return nil
}
