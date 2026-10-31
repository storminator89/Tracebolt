package managerstatus

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"syscall"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Classify returns a bounded diagnostic, never an error string or retry policy.
// In particular, a busy COMMIT is not evidence that retrying a mutation is safe.
func Classify(err error) State {
	if err == nil {
		return OK
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	if errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EAGAIN) {
		return Busy
	}
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return Full
	}
	if errors.Is(err, syscall.EROFS) {
		return ReadOnly
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return Denied
	}
	if errors.Is(err, syscall.EIO) {
		return IOError
	}
	if errors.Is(err, syscall.ENOMEM) || errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
		return Exhausted
	}
	var se *sqlite.Error
	if errors.As(err, &se) && se != nil {
		switch se.Code() & 0xff {
		case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
			return Busy
		case sqlite3.SQLITE_FULL:
			return Full
		case sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB:
			return Invalid
		case sqlite3.SQLITE_READONLY:
			return ReadOnly
		case sqlite3.SQLITE_PERM, sqlite3.SQLITE_AUTH:
			return Denied
		case sqlite3.SQLITE_IOERR:
			return IOError
		case sqlite3.SQLITE_NOMEM:
			return Exhausted
		}
	}
	return Unavailable
}

// SQLiteProbe reserves writer admission and validates a bounded read snapshot.
// The driver busy handler can outlive ctx; callers must bound concurrent probes
// and response waiting independently. It performs no COMMIT or data mutation. Success does NOT establish that a
// future write can allocate space, commit, or survive loss of power.
func SQLiteProbe(ctx context.Context, db *sql.DB, inspect func(context.Context, *sql.Conn) (ProbeResult, error)) (result ProbeResult) {
	result.State = Unavailable
	if ctx == nil || db == nil || inspect == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	defer func() {
		if result.Storage == nil {
			result.Storage = &StorageMetrics{}
		}
		stats := db.Stats()
		result.Storage.PoolOpen, result.Storage.PoolInUse = stats.OpenConnections, stats.InUse
		result.Storage.PoolWaitCount, result.Storage.PoolWaitMilliseconds = stats.WaitCount, stats.WaitDuration.Milliseconds()
	}()
	conn, err := db.Conn(ctx)
	if err != nil {
		result.State = Classify(err)
		return
	}
	discard := func() { _ = conn.Raw(func(any) error { return driver.ErrBadConn }); _ = conn.Close() }
	began := false
	defer func() {
		if began {
			cleanup, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_, err := conn.ExecContext(cleanup, "ROLLBACK")
			stop()
			if err != nil {
				discard()
				result.State = Unavailable
				return
			}
		}
		_ = conn.Close()
	}()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		// Even a failed BEGIN may leave driver state uncertain after cancellation.
		if Classify(err) != Busy {
			discard()
		}
		result.State = Classify(err)
		return
	}
	began = true
	storage, err := sqliteStorage(ctx, conn)
	if err != nil {
		result.State = Classify(err)
		return
	}
	result, err = inspect(ctx, conn)
	if result.Storage == nil {
		result.Storage = storage
	} else {
		result.Storage.DatabaseBytes, result.Storage.WALBytes = storage.DatabaseBytes, storage.WALBytes
	}
	if err != nil {
		result.State = Classify(err)
	}
	if ctx.Err() != nil {
		result.State = Timeout
	}
	return
}

func sqliteStorage(ctx context.Context, conn *sql.Conn) (*StorageMetrics, error) {
	// Reading actual page geometry touches the database, unlike SELECT 1.
	var pages, size int64
	if err := conn.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return nil, err
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size); err != nil {
		return nil, err
	}
	if pages < 1 || size < 512 || size > 65536 {
		return nil, errors.New("invalid database geometry")
	}
	rows, err := conn.QueryContext(ctx, "PRAGMA database_list")
	if err != nil {
		return nil, err
	}
	var path string
	for rows.Next() {
		var sequence int
		var name, file string
		if err = rows.Scan(&sequence, &name, &file); err != nil {
			break
		}
		if name == "main" {
			path = file
		}
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	result := &StorageMetrics{}
	if path == "" {
		return result, nil
	} // in-memory DB; no physical file claim
	for _, item := range []struct {
		suffix string
		value  *uint64
	}{{"", &result.DatabaseBytes}, {"-wal", &result.WALBytes}} {
		info, e := os.Lstat(path + item.suffix)
		if os.IsNotExist(e) && item.suffix != "" {
			continue
		}
		if e != nil {
			return nil, e
		}
		if !info.Mode().IsRegular() || info.Size() < 0 {
			return nil, errors.New("invalid database file")
		}
		*item.value = uint64(info.Size())
	}
	return result, nil
}
