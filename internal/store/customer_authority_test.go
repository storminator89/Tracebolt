package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"modernc.org/sqlite"
)

func authorityFixture(t *testing.T) (*Store, string, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "operator.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	manager := strings.Repeat("a", 64)
	id := "customer_" + strings.Repeat("1", 32)
	if _, err = s.SaveCustomer(context.Background(), manager, id, "First", 0, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	return s, path, manager, id
}

func TestCustomerAuthorityPinsRevisionAndHoldsWriteExclusion(t *testing.T) {
	s, path, manager, id := authorityFixture(t)
	ctx := context.Background()
	l, err := s.AcquireCustomerAuthority(ctx, manager, id, 1, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	other, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.SetMaxOpenConns(1)
	if _, err = other.Exec(`PRAGMA busy_timeout=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = other.Exec(`UPDATE customers SET body=body WHERE id=?`, id); err == nil {
		t.Fatal("customer write was not excluded")
	}
	c, err := l.Customer()
	if err != nil || c.ID != id || c.Manager != manager || c.Revision != 1 || c.Name != "First" {
		t.Fatalf("wrong pinned customer: %v", err)
	}
	l.Release()
	l.Release()
	if err = l.Check(); !errors.Is(err, ErrCustomerConflict) {
		t.Fatal("released lease remained valid", err)
	}
	if _, err = other.Exec(`UPDATE customers SET body=body WHERE id=?`, id); err != nil {
		t.Fatal("write lock remained after release", err)
	}
	if _, err = s.SaveCustomer(ctx, manager, id, "Renamed", 1, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AcquireCustomerAuthority(ctx, manager, id, 1, func() error { return nil }); !errors.Is(err, ErrCustomerConflict) {
		t.Fatal("stale revision accepted", err)
	}
	if _, err = s.AcquireCustomerAuthority(ctx, strings.Repeat("b", 64), id, 2, func() error { return nil }); !errors.Is(err, ErrCustomerConflict) {
		t.Fatal("wrong manager accepted", err)
	}
}

func TestCustomerAuthorityChecksGuardCancellationAndMalformedCatalog(t *testing.T) {
	s, _, manager, id := authorityFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	denied := errors.New("live authority lost")
	live := true
	l, err := s.AcquireCustomerAuthority(ctx, manager, id, 1, func() error {
		if !live {
			return denied
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	live = false
	if err = l.Check(); !errors.Is(err, denied) {
		t.Fatal("lost authority accepted", err)
	}
	live = true
	cancel()
	if err = l.Check(); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled lease remained valid", err)
	}
	l.Release()
	if _, err = s.db.Exec(`UPDATE customers SET body=body || ' ' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AcquireCustomerAuthority(context.Background(), manager, id, 1, func() error { return nil }); !errors.Is(err, ErrCustomerInvalid) {
		t.Fatal("malformed customer accepted", err)
	}
	// Failure must release the connection and rollback the acquired transaction.
	if _, err = s.db.Exec(`UPDATE customers SET body=trim(body) WHERE id=?`, id); err != nil {
		t.Fatal("failed acquisition retained lock", err)
	}
}

func TestCustomerAuthorityRejectsCancellationDuringGuard(t *testing.T) {
	s, _, manager, id := authorityFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	_, err := s.AcquireCustomerAuthority(ctx, manager, id, 1, func() error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal("guard canceled context but acquisition succeeded", err)
	}
	if _, err = s.SaveCustomer(context.Background(), manager, id, "After cancellation", 1, func() error { return nil }); err != nil {
		t.Fatal("failed acquisition retained lock", err)
	}
}

func TestCustomerAuthorityReleasesAfterGuardPanic(t *testing.T) {
	s, _, manager, id := authorityFixture(t)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("guard panic was unexpectedly swallowed")
			}
		}()
		_, _ = s.AcquireCustomerAuthority(context.Background(), manager, id, 1, func() error { panic("guard failure") })
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := s.SaveCustomer(ctx, manager, id, "After panic", 1, func() error { return nil }); err != nil {
		t.Fatal("panic retained the operator transaction or connection", err)
	}
}

type authorityFailedBeginConnector struct{ opens, closes atomic.Int32 }
type authorityFailedBeginDriver struct{}
type authorityFailedBeginConn struct {
	owner *authorityFailedBeginConnector
}

func (c *authorityFailedBeginConnector) Connect(context.Context) (driver.Conn, error) {
	c.opens.Add(1)
	return &authorityFailedBeginConn{owner: c}, nil
}
func (*authorityFailedBeginConnector) Driver() driver.Driver { return authorityFailedBeginDriver{} }
func (authorityFailedBeginDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("unused")
}
func (*authorityFailedBeginConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unused")
}
func (c *authorityFailedBeginConn) Close() error            { c.owner.closes.Add(1); return nil }
func (*authorityFailedBeginConn) Begin() (driver.Tx, error) { return nil, errors.New("unused") }
func (*authorityFailedBeginConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return nil, errors.New("injected uncertain begin")
}

func TestCustomerAuthorityDiscardsConnectionAfterFailedBegin(t *testing.T) {
	connector := &authorityFailedBeginConnector{}
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db}
	manager, id := strings.Repeat("a", 64), "customer_"+strings.Repeat("1", 32)
	if _, err := s.AcquireCustomerAuthority(context.Background(), manager, id, 1, func() error { return nil }); err == nil {
		t.Fatal("failed BEGIN unexpectedly succeeded")
	}
	if connector.closes.Load() != 1 {
		t.Fatal("uncertain connection was returned to the pool")
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if connector.opens.Load() != 2 {
		t.Fatal("next acquisition did not open a new connection")
	}
}

type panicAuthorityConnector struct {
	path            string
	begin, rollback atomic.Bool
	opens, closes   atomic.Int32
}

func (p *panicAuthorityConnector) Driver() driver.Driver { return &sqlite.Driver{} }
func (p *panicAuthorityConnector) Connect(context.Context) (driver.Conn, error) {
	c, err := (&sqlite.Driver{}).Open(p.path)
	if err != nil {
		return nil, err
	}
	p.opens.Add(1)
	return &panicAuthorityConn{Conn: c, owner: p}, nil
}

type panicAuthorityConn struct {
	driver.Conn
	owner *panicAuthorityConnector
}

func (c *panicAuthorityConn) Close() error { c.owner.closes.Add(1); return c.Conn.Close() }
func (c *panicAuthorityConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	x, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	if q == "ROLLBACK" && c.owner.rollback.CompareAndSwap(true, false) {
		panic("fixture before rollback")
	}
	r, err := x.ExecContext(ctx, q, args)
	if err == nil && q == "BEGIN IMMEDIATE" && c.owner.begin.CompareAndSwap(true, false) {
		panic("fixture after begin")
	}
	return r, err
}
func (c *panicAuthorityConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	x, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return x.QueryContext(ctx, q, args)
}

func TestCustomerAuthorityDiscardsOnBeginAndRollbackPanics(t *testing.T) {
	for _, phase := range []string{"begin", "rollback"} {
		t.Run(phase, func(t *testing.T) {
			_, path, manager, id := authorityFixture(t)
			connector := &panicAuthorityConnector{path: path}
			db := sql.OpenDB(connector)
			db.SetMaxOpenConns(1)
			defer db.Close()
			s := &Store{db: db}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var lease *CustomerAuthorityLease
			var err error
			if phase == "rollback" {
				lease, err = s.AcquireCustomerAuthority(ctx, manager, id, 1, func() error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				connector.rollback.Store(true)
			} else {
				connector.begin.Store(true)
			}
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				if phase == "begin" {
					_, _ = s.AcquireCustomerAuthority(ctx, manager, id, 1, func() error { return nil })
				} else {
					lease.Release()
				}
			}()
			if !panicked || connector.closes.Load() != 1 || db.Stats().InUse != 0 {
				t.Fatal("panic cleanup failed", panicked, connector.closes.Load(), db.Stats())
			}
			if lease != nil {
				if lease.Check() == nil {
					t.Fatal("released lease remained valid")
				}
				lease.Release()
			}
			again, err := s.AcquireCustomerAuthority(ctx, manager, id, 1, func() error { return nil })
			if err != nil {
				t.Fatal("reopen failed", err)
			}
			again.Release()
			if connector.opens.Load() < 2 {
				t.Fatal("connection was reused")
			}
		})
	}
}
