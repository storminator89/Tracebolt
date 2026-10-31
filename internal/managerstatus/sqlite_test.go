package managerstatus

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func statusDB(t *testing.T) *sql.DB {
	t.Helper()
	db, e := sql.Open("sqlite", filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, e = db.Exec("CREATE TABLE expected(id INTEGER PRIMARY KEY, value TEXT)"); e != nil {
		t.Fatal(e)
	}
	return db
}
func statusInspect(ctx context.Context, c *sql.Conn) (ProbeResult, error) {
	var count int
	e := c.QueryRowContext(ctx, "SELECT count(*) FROM expected").Scan(&count)
	return ProbeResult{State: OK}, e
}
func TestSQLiteProbeReadOnlyReleaseAndCancellation(t *testing.T) {
	db := statusDB(t)
	for i := 0; i < 3; i++ {
		r := SQLiteProbe(context.Background(), db, statusInspect)
		if r.State != OK || r.Storage == nil || r.Storage.DatabaseBytes == 0 {
			t.Fatalf("status %#v", r)
		}
	}
	if _, e := db.Exec("INSERT INTO expected(value) VALUES('still writable')"); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := SQLiteProbe(ctx, db, statusInspect); r.State != Timeout {
		t.Fatal(r.State)
	}
	held, e := db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	before := time.Now()
	r := SQLiteProbe(ctx, db, statusInspect)
	if r.State != Timeout || time.Since(before) > time.Second {
		t.Fatal(r.State)
	}
	_ = held.Close()
	_ = db.Close()
	if r := SQLiteProbe(context.Background(), db, statusInspect); r.State != Unavailable {
		t.Fatal(r.State)
	}
}
func TestSQLiteProbeExternalWriterBusy(t *testing.T) {
	db := statusDB(t)
	var seq int
	var name, path string
	if e := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); e != nil {
		t.Fatal(e)
	}
	other, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if _, e = other.Exec("BEGIN IMMEDIATE"); e != nil {
		t.Fatal(e)
	}
	defer other.Exec("ROLLBACK")
	before := time.Now()
	r := SQLiteProbe(context.Background(), db, statusInspect)
	if r.State != Busy || time.Since(before) > time.Second {
		t.Fatal(r.State, time.Since(before))
	}
}
func TestClassifyClosedVocabularyAndActualSQLiteFull(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want State
	}{{nil, OK}, {context.Canceled, Timeout}, {context.DeadlineExceeded, Timeout}, {fmt.Errorf("private-path: %w", syscall.ENOSPC), Full}, {&os.PathError{Op: "write", Path: "secret", Err: syscall.EDQUOT}, Full}, {errors.New("secret token device path"), Unavailable}} {
		if got := Classify(tc.err); got != tc.want {
			t.Fatal(got)
		}
	}
	db := statusDB(t)
	var pages int
	if e := db.QueryRow("PRAGMA page_count").Scan(&pages); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); e != nil {
		t.Fatal(e)
	}
	_, e := db.Exec("INSERT INTO expected(value) VALUES(zeroblob(1048576))")
	if e == nil || Classify(e) != Full {
		t.Fatal("real SQLite full not classified", Classify(e))
	}
}

func TestSQLiteProbeBusyHandlerCancellation(t *testing.T) {
	db := statusDB(t)
	if _, e := db.Exec("PRAGMA busy_timeout=5000"); e != nil {
		t.Fatal(e)
	}
	var seq int
	var name, path string
	if e := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); e != nil {
		t.Fatal(e)
	}
	other, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if _, e = other.Exec("BEGIN IMMEDIATE"); e != nil {
		t.Fatal(e)
	}
	defer other.Exec("ROLLBACK")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	before := time.Now()
	r := SQLiteProbe(ctx, db, statusInspect)
	t.Logf("busy handler cancellation elapsed=%s state=%s", time.Since(before), r.State)
	if r.State != Timeout {
		t.Fatal(r.State)
	}
}

func TestSQLiteProbeCleanupFailureDiscardsConnection(t *testing.T) {
	db := statusDB(t)
	r := SQLiteProbe(context.Background(), db, func(ctx context.Context, c *sql.Conn) (ProbeResult, error) {
		// Simulate unexpected transaction loss before the helper's final cleanup.
		_, e := c.ExecContext(ctx, "ROLLBACK")
		return ProbeResult{State: OK}, e
	})
	if r.State != Unavailable {
		t.Fatal("uncertain cleanup advertised healthy", r.State)
	}
	if r.Storage.PoolOpen != 0 {
		t.Fatal("uncertain connection returned to pool")
	}
	if r := SQLiteProbe(context.Background(), db, statusInspect); r.State != OK {
		t.Fatal(r.State)
	}
}

func TestClassifyFiniteOperatingSystemErrors(t *testing.T) {
	for _, test := range []struct {
		err  error
		want State
	}{{syscall.ENOSPC, Full}, {syscall.EDQUOT, Full}, {syscall.EROFS, ReadOnly}, {syscall.EACCES, Denied}, {syscall.EPERM, Denied}, {syscall.EIO, IOError}, {syscall.ENOMEM, Exhausted}, {syscall.EMFILE, Exhausted}, {syscall.ENFILE, Exhausted}} {
		if got := Classify(&os.PathError{Op: "source-private-operation", Path: "source-private-path", Err: test.err}); got != test.want {
			t.Fatal("finite error class mismatch")
		}
	}
}
