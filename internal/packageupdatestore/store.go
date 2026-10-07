// Package packageupdatestore persists protected SQLite workflow records for
// distinct native and simulation scopes. It never signs or executes packages;
// scope creation is explicit and is never a runtime fallback.
//
// Create is deliberately distinct from OpenExisting. The database contains one
// exact identity-bound record and an active-session guard. Every writable session
// durably sets that guard before returning. A crash or an uncertain record write
// leaves it set; reopening is refused rather than guessing whether to retry.
// Only Close after exclusively known-success writes clears it. This conservative
// guard also fences a crash after a successful write. There is no reset, adoption,
// migration, or reconciliation API. A valid older whole-database backup cannot be
// detected locally and is not an authorized restoration of a live identity.
package packageupdatestore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"sync"

	"localrmm/internal/packageupdate"
	_ "modernc.org/sqlite"
)

var ErrStorage = errors.New("package_update_store_unavailable_or_invalid")
var ErrLocked = errors.New("package_update_store_locked")

const schema = `CREATE TABLE package_update_state(id INTEGER PRIMARY KEY CHECK(id=1), record BLOB NOT NULL CHECK(length(record)>0 AND length(record)<=2097152), active INTEGER NOT NULL CHECK(active IN (0,1))) STRICT`
const databaseCap = 16 << 20

type Store struct{ inner *state }
type state struct {
	mu      sync.Mutex
	db      *sql.DB
	file    *protectedFile
	binding packageupdate.Binding
	hash    [sha256.Size]byte
	failed  bool
	closed  bool
	// Tests inject failures at actual transaction boundaries, including a commit
	// that completed but whose acknowledgement was lost. Never exported.
	commit func(context.Context, *sql.Conn) error
	write  func(context.Context, *sql.Conn, []byte) error
}

var _ packageupdate.DurableStore = (*Store)(nil)

func (Store) String() string               { return "packageupdatestore.Store{contents:redacted}" }
func (Store) GoString() string             { return "packageupdatestore.Store{contents:redacted}" }
func (s Store) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (Store) MarshalJSON() ([]byte, error) { return []byte(`{"contentsRedacted":true}`), nil }

// Create creates one NEW fixture database in an existing protected directory.
// An existing file, even empty, incomplete, or invalid, is never adopted. A
// failed creation deliberately leaves its file in place and cannot be retried as
// initialization. Callers must not use this as production startup or recovery.
func Create(ctx context.Context, path string, b packageupdate.Binding, now int64) (*Store, error) {
	if ctx == nil {
		return nil, packageupdate.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := packageupdate.New(b, now)
	if err != nil {
		return nil, err
	}
	raw, err := packageupdate.Encode(ctx, r)
	if err != nil {
		return nil, err
	}
	return open(ctx, path, b, raw, true)
}

// CreateNative is the separate explicit native-scope initialization seam.
// It is not called from manager startup or an operator request.
func CreateNative(ctx context.Context, path string, b packageupdate.Binding, key ed25519.PublicKey, now int64) (*Store, error) {
	r, e := packageupdate.NewNative(b, key, now)
	if e != nil {
		return nil, e
	}
	raw, e := packageupdate.Encode(ctx, r)
	if e != nil {
		return nil, e
	}
	return open(ctx, path, b, raw, true)
}

// OpenExisting never creates missing files, tables, rows, or history. It refuses
// a dirty session even when its last record appears valid and fully committed.
func OpenExisting(ctx context.Context, path string, b packageupdate.Binding) (*Store, error) {
	if ctx == nil {
		return nil, packageupdate.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := packageupdate.New(b, 1); err != nil {
		return nil, err
	}
	return open(ctx, path, b, nil, false)
}

func open(ctx context.Context, path string, b packageupdate.Binding, initial []byte, create bool) (*Store, error) {
	f, err := openProtected(path, create)
	if err != nil {
		return nil, err
	}
	if !create {
		if err := preflight(ctx, f, b); err != nil {
			_ = f.close()
			return nil, err
		}
	}
	u := url.URL{Scheme: "file", Path: f.path}
	q := u.Query()
	q.Set("mode", "rw")
	// Apply connection-local protections on every connection, including one
	// replaced internally by database/sql after a canceled read.
	for _, pragma := range []string{"busy_timeout(1000)", "trusted_schema(OFF)", "foreign_keys(ON)", "synchronous(FULL)", "max_page_count(4096)"} {
		q.Add("_pragma", pragma)
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		f.close()
		return nil, ErrStorage
	}
	db.SetMaxOpenConns(1)
	x := &state{db: db, file: f, binding: b, commit: commit, write: writeRecord}
	var conn *sql.Conn
	fail := func(err error) (*Store, error) {
		if conn != nil {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
			_ = conn.Close()
		}
		_ = db.Close()
		_ = f.close()
		return nil, err
	}
	// DELETE mode keeps the guarded state and its rollback journal in this one
	// private directory. FULL plus the persistent guard precedes every record write.
	for _, p := range []string{"PRAGMA busy_timeout=1000", "PRAGMA trusted_schema=OFF", "PRAGMA foreign_keys=ON", "PRAGMA synchronous=FULL", "PRAGMA max_page_count=4096"} {
		if _, err = db.ExecContext(ctx, p); err != nil {
			return fail(ErrStorage)
		}
	}
	var journal string
	var synchronous int
	if db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal) != nil || journal != "delete" ||
		db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous) != nil || synchronous != 2 {
		return fail(ErrStorage)
	}
	conn, err = db.Conn(ctx)
	if err != nil {
		return fail(ErrStorage)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fail(ErrStorage)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	if create {
		var count int
		if conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema").Scan(&count) != nil || count != 0 {
			return fail(ErrStorage)
		}
		for _, p := range []string{schema, "PRAGMA user_version=1"} {
			if _, err = conn.ExecContext(ctx, p); err != nil {
				return fail(ErrStorage)
			}
		}
		if _, err = conn.ExecContext(ctx, "INSERT INTO package_update_state(id,record,active) VALUES(1,?,1)", initial); err != nil {
			return fail(ErrStorage)
		}
	} else {
		raw, active, err := load(ctx, conn, b)
		if err != nil {
			return fail(err)
		}
		if active != 0 {
			return fail(packageupdate.ErrUncertain)
		}
		initial = raw
		if _, err = conn.ExecContext(ctx, "UPDATE package_update_state SET active=1 WHERE id=1 AND active=0"); err != nil {
			return fail(packageupdate.ErrUncertain)
		}
	}
	if err = f.check(); err != nil {
		return fail(ErrStorage)
	}
	if err = commit(ctx, conn); err != nil {
		return fail(packageupdate.ErrUncertain)
	}
	committed = true
	if err = f.sync(); err != nil {
		return fail(packageupdate.ErrUncertain)
	}
	if err = f.check(); err != nil {
		return fail(packageupdate.ErrUncertain)
	}
	x.hash = sha256.Sum256(initial)
	return &Store{inner: x}, nil
}

// Validate existing bytes before any mutable SQLite pragma or guard write. An
// immutable read cannot repair a damaged store or create sidecars. Protected
// opening already rejects rollback journals and WAL-mode database headers.
func preflight(ctx context.Context, f *protectedFile, b packageupdate.Binding) error {
	u := url.URL{Scheme: "file", Path: f.path}
	q := u.Query()
	q.Set("mode", "ro")
	q.Set("immutable", "1")
	q.Add("_pragma", "trusted_schema(OFF)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return ErrStorage
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, active, err := load(ctx, db, b)
	if err != nil {
		return err
	}
	if active != 0 {
		return packageupdate.ErrUncertain
	}
	return f.check()
}

func commit(ctx context.Context, c *sql.Conn) error {
	_, err := c.ExecContext(ctx, "COMMIT")
	return err
}

func writeRecord(ctx context.Context, c *sql.Conn, raw []byte) error {
	result, err := c.ExecContext(ctx, "UPDATE package_update_state SET record=? WHERE id=1 AND active=1", raw)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrStorage
	}
	return nil
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func load(ctx context.Context, q queryer, b packageupdate.Binding) ([]byte, int, error) {
	var version int
	if q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version) != nil || version != 1 {
		return nil, 0, ErrStorage
	}
	rows, err := q.QueryContext(ctx, "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name")
	if err != nil {
		return nil, 0, ErrStorage
	}
	count := 0
	for rows.Next() {
		var typ, name, table, sql string
		if rows.Scan(&typ, &name, &table, &sql) != nil || typ != "table" || name != "package_update_state" || table != name || sql != schema {
			rows.Close()
			return nil, 0, ErrStorage
		}
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil || count != 1 {
		return nil, 0, ErrStorage
	}
	var integrity string
	if q.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity) != nil || integrity != "ok" {
		return nil, 0, ErrStorage
	}
	var n, size int
	if q.QueryRowContext(ctx, "SELECT count(*),coalesce(max(length(record)),0) FROM package_update_state").Scan(&n, &size) != nil || n != 1 || size < 1 || size > packageupdate.MaxRecordBytes {
		return nil, 0, ErrStorage
	}
	var raw []byte
	var active int
	if q.QueryRowContext(ctx, "SELECT record,active FROM package_update_state WHERE id=1").Scan(&raw, &active) != nil || (active != 0 && active != 1) {
		return nil, 0, ErrStorage
	}
	r, err := packageupdate.Decode(ctx, raw)
	if err != nil || r.Binding != b {
		return nil, 0, ErrStorage
	}
	return raw, active, nil
}

func (x *state) check(ctx context.Context, b packageupdate.Binding) error {
	if ctx == nil {
		return packageupdate.ErrInvalid
	}
	if x.failed {
		return packageupdate.ErrUncertain
	}
	if x.closed {
		return packageupdate.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if b != x.binding {
		return packageupdate.ErrConflict
	}
	if x.file.check() != nil {
		x.failed = true
		return packageupdate.ErrUncertain
	}
	return nil
}

// Open returns freshly validated canonical bytes. It cannot initialize state.
func (s *Store) Open(ctx context.Context, b packageupdate.Binding) ([]byte, error) {
	if s == nil || s.inner == nil {
		return nil, packageupdate.ErrUnavailable
	}
	x := s.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.check(ctx, b); err != nil {
		return nil, err
	}
	raw, active, err := load(ctx, x.db, b)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || active != 1 || sha256.Sum256(raw) != x.hash {
		x.failed = true
		return nil, packageupdate.ErrUncertain
	}
	return bytes.Clone(raw), nil
}

// CompareAndSwap preserves all prior history, accepts only one legal revision,
// and never retries a write. Any error once the record write is attempted poisons
// all copies of the handle and leaves the durable session guard on clean Close.
func (s *Store) CompareAndSwap(ctx context.Context, b packageupdate.Binding, expectedRevision uint64, canonicalRecord []byte) error {
	if s == nil || s.inner == nil {
		return packageupdate.ErrUnavailable
	}
	if ctx == nil {
		return packageupdate.ErrInvalid
	}
	if len(canonicalRecord) == 0 || len(canonicalRecord) > packageupdate.MaxRecordBytes {
		return packageupdate.ErrInvalid
	}
	owned := bytes.Clone(canonicalRecord)
	next, err := packageupdate.Decode(ctx, owned)
	if err != nil {
		return err
	}
	if next.Binding != b {
		return packageupdate.ErrConflict
	}
	x := s.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if err = x.check(ctx, b); err != nil {
		return err
	}
	conn, err := x.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return ErrStorage
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	oldRaw, active, err := load(ctx, conn, b)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || active != 1 || sha256.Sum256(oldRaw) != x.hash {
		x.failed = true
		return packageupdate.ErrUncertain
	}
	old, err := packageupdate.Decode(ctx, oldRaw)
	if err != nil {
		x.failed = true
		return packageupdate.ErrUncertain
	}
	if old.Revision != expectedRevision {
		return packageupdate.ErrConflict
	}
	if err = packageupdate.ValidateSuccessor(ctx, old, next); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if x.file.check() != nil {
		x.failed = true
		return packageupdate.ErrUncertain
	}
	if err = x.write(ctx, conn, owned); err != nil {
		x.failed = true
		return packageupdate.ErrUncertain
	}
	if err = x.commit(ctx, conn); err != nil {
		x.failed = true
		return packageupdate.ErrUncertain
	}
	committed = true
	x.hash = sha256.Sum256(owned)
	if x.file.check() != nil || ctx.Err() != nil {
		x.failed = true
		return packageupdate.ErrUncertain
	}
	return nil
}

// Close releases the exclusive session. A poisoned session never clears its
// durable guard. Closing a healthy session changes no record or historical floor;
// even if that close is interrupted, all preceding record commits were known to
// succeed. Close never attempts reconciliation, repair, or reset.
func (s *Store) Close() error {
	if s == nil || s.inner == nil {
		return packageupdate.ErrUnavailable
	}
	x := s.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return packageupdate.ErrUnavailable
	}
	x.closed = true
	var result error
	if x.failed {
		result = packageupdate.ErrUncertain
	} else {
		raw, active, err := load(context.Background(), x.db, x.binding)
		if err != nil || active != 1 || sha256.Sum256(raw) != x.hash || x.file.check() != nil {
			x.failed = true
			result = packageupdate.ErrUncertain
		} else {
			// Guard clearing is safe only here, after every record write is acknowledged.
			// It cannot turn an ambiguous CAS into a reusable store.
			if _, err = x.db.Exec("UPDATE package_update_state SET active=0 WHERE id=1 AND active=1"); err != nil {
				result = ErrStorage
			}
		}
	}
	if err := x.db.Close(); err != nil && result == nil {
		result = ErrStorage
	}
	if err := x.file.close(); err != nil && result == nil {
		result = ErrStorage
	}
	return result
}

// retained here to keep the platform implementation's imports narrowly scoped.
func normalizedPath(path string) (string, error) {
	if path == "" {
		return "", ErrStorage
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return "", ErrStorage
	}
	return p, nil
}
