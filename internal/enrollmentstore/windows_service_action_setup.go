package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type WindowsActionSetupInspection struct {
	Config    enrollmentstate.Config
	Identity  enrollmentstate.Snapshot
	Status    string
	PublicKey ed25519.PublicKey
}

// InspectWindowsServiceActionSetup is existing-only and read-only, including
// WAL shared memory. It cannot create, recover, checkpoint or reset a database.
func InspectWindowsServiceActionSetup(ctx context.Context, path string, issuerDER []byte, device string, now time.Time) (WindowsActionSetupInspection, error) {
	zero := WindowsActionSetupInspection{}
	if ctx == nil || runtime.GOOS != "linux" {
		return zero, ErrStorage
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	absolute, err := safePath(path)
	if err != nil || privateStateDirectory(filepath.Dir(absolute)) != nil || checkFilesForProfile(absolute, enrollmentcrypto.CollectionProfileWindowsInventory) != nil {
		return zero, ErrStorage
	}
	serviceActionInspectionWriters.Lock()
	defer serviceActionInspectionWriters.Unlock()
	if serviceActionInspectionWriters.paths[absolute] != 0 {
		return zero, ErrServiceActionInspectionBusy
	}
	info, err := os.Lstat(absolute)
	if err != nil || info.Size() <= 0 || info.Size() > databaseCap(enrollmentcrypto.CollectionProfileWindowsInventory) {
		return zero, ErrStorage
	}
	u := url.URL{Scheme: "file", Path: absolute}
	q := u.Query()
	q.Set("mode", "ro")
	// This SQLite URI option forces a genuinely read-only WAL-index mapping.
	// mode=ro alone still permits changing SHM read marks.
	q.Set("readonly_shm", "1")
	immutable := false
	wal, err := os.Lstat(absolute + "-wal")
	if os.IsNotExist(err) {
		// A rollback journal requires recovery rather than a potentially stale
		// immutable read. No recovery is performed by planning.
		if _, journalErr := os.Lstat(absolute + "-journal"); !os.IsNotExist(journalErr) {
			return zero, ErrStorage
		}
		q.Set("immutable", "1")
		immutable = true
	} else if err != nil || !wal.Mode().IsRegular() {
		return zero, ErrStorage
	} else if _, err = os.Lstat(absolute + "-shm"); err != nil {
		return zero, ErrStorage
	}
	q.Set("_pragma", "busy_timeout(5000)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return zero, ErrStorage
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return zero, storageError(ctx)
	}
	defer conn.Close()
	for _, query := range []string{"PRAGMA query_only=ON", "PRAGMA trusted_schema=OFF", "BEGIN"} {
		if _, err = conn.ExecContext(ctx, query); err != nil {
			return zero, storageError(ctx)
		}
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	var size int
	if conn.QueryRowContext(ctx, `SELECT length(ledger) FROM enrollment_state WHERE id=1`).Scan(&size) != nil || size <= 0 || size > enrollmentstate.MaxTrustedLedgerBytes {
		return zero, ErrStorage
	}
	var raw []byte
	if conn.QueryRowContext(ctx, `SELECT ledger FROM enrollment_state WHERE id=1`).Scan(&raw) != nil {
		return zero, ErrStorage
	}
	config, err := enrollmentstate.TrustedLedgerConfig(raw)
	if err != nil || config.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || config.RecordLimit > 25 || validateIssuer(config, issuerDER) != nil {
		return zero, ErrStorage
	}
	s := &Store{&storeState{db: db, path: absolute, info: info, config: config, issuerDER: bytes.Clone(issuerDER)}}
	if s.checkPath() != nil {
		return zero, ErrStorage
	}
	var integrity string
	if conn.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity) != nil || integrity != "ok" {
		return zero, ErrStorage
	}
	t, err := s.load(ctx, conn)
	if err != nil || s.inventoryReadOnlyCapacity(ctx, conn) != nil {
		return zero, storageError(ctx)
	}
	snap, err := systemDevice(t, device)
	if err != nil {
		return zero, err
	}
	if _, err = s.windowsFullServicesAuthority(t, snap.InvitationID, t.currentCertificateHash(snap), now); err != nil {
		return zero, err
	}
	out := WindowsActionSetupInspection{Config: config, Identity: snap, Status: "absent"}
	present, err := windowsActionSchemaPresent(ctx, conn)
	if err != nil {
		return zero, err
	}
	if present {
		if conn.QueryRowContext(ctx, `SELECT public_key FROM enrollment_windows_action_meta WHERE id=1`).Scan(&out.PublicKey) != nil {
			return zero, ErrStorage
		}
		out.Status = "fenced"
	}

	if s.checkPath() != nil {
		return zero, ErrStorage
	}
	if immutable {
		current, err := os.Lstat(absolute)
		if err != nil || current.Size() != info.Size() || !current.ModTime().Equal(info.ModTime()) {
			return zero, ErrStorage
		}
		for _, suffix := range []string{"-wal", "-journal"} {
			if _, err := os.Lstat(absolute + suffix); !os.IsNotExist(err) {
				return zero, ErrStorage
			}
		}
	}
	return out, nil
}
