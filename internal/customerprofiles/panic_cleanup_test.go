package customerprofiles

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

type panicConnector struct {
	path            string
	begin, rollback atomic.Bool
	opens, closes   atomic.Int32
}

func (p *panicConnector) Driver() driver.Driver { return &sqlite.Driver{} }
func (p *panicConnector) Connect(context.Context) (driver.Conn, error) {
	c, err := (&sqlite.Driver{}).Open(p.path)
	if err != nil {
		return nil, err
	}
	p.opens.Add(1)
	return &panicConn{Conn: c, owner: p}, nil
}

type panicConn struct {
	driver.Conn
	owner *panicConnector
}

func (c *panicConn) Close() error { c.owner.closes.Add(1); return c.Conn.Close() }
func (c *panicConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if q == "ROLLBACK" && c.owner.rollback.CompareAndSwap(true, false) {
		panic("before rollback")
	}
	x, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	r, e := x.ExecContext(ctx, q, args)
	if e == nil && q == "BEGIN IMMEDIATE" && c.owner.begin.CompareAndSwap(true, false) {
		panic("after begin")
	}
	return r, e
}
func (c *panicConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	x, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return x.QueryContext(ctx, q, args)
}

type releaseAuthority struct {
	check   func() error
	release func()
}

func (a releaseAuthority) Check() error { return a.check() }
func (a releaseAuthority) Release()     { a.release() }

func TestBeginPanicDiscardsAndReopens(t *testing.T) {
	for _, op := range []string{"initialize", "get", "active"} {
		t.Run(op, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "profiles.db")
			manager := "manager_" + strings.Repeat("1", 32)
			if op != "initialize" {
				db, e := sql.Open("sqlite", path)
				if e != nil {
					t.Fatal(e)
				}
				if e = Initialize(ctx, db, manager); e != nil {
					t.Fatal(e)
				}
				db.Close()
			}
			connector := &panicConnector{path: path}
			db := sql.OpenDB(connector)
			defer db.Close()
			db.SetMaxOpenConns(1)
			s, e := New(db, manager)
			if e != nil {
				t.Fatal(e)
			}
			connector.begin.Store(true)
			func() {
				defer func() {
					if recover() == nil {
						t.Error("missing begin panic")
					}
				}()
				switch op {
				case "initialize":
					_ = Initialize(ctx, db, manager)
				case "get":
					_, _ = s.Get(ctx, "profile_"+strings.Repeat("3", 32))
				case "active":
					_, _ = s.AcquireActive(ctx, "customer_"+strings.Repeat("2", 32), "profile_"+strings.Repeat("3", 32), time.Now, guard)
				}
			}()
			if connector.closes.Load() != 1 || db.Stats().InUse != 0 {
				t.Fatal("connection leaked", db.Stats())
			}
			if op == "initialize" {
				if e = Initialize(ctx, db, manager); e != nil {
					t.Fatal(e)
				}
			} else if _, e = s.Get(ctx, "profile_"+strings.Repeat("3", 32)); !errors.Is(e, ErrInactive) {
				t.Fatal("reopened state", e)
			}
			if connector.opens.Load() < 2 {
				t.Fatal("connection not reopened")
			}
		})
	}
}

func TestRollbackPanicReleasesProfileBeforeOperator(t *testing.T) {
	for _, op := range []string{"active", "create", "retire"} {
		t.Run(op, func(t *testing.T) {
			original, base, now, p := fixture(t)
			ctx := context.Background()
			clock := func() time.Time { return *now }
			record, e := original.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), clock, guard)
			if e != nil {
				t.Fatal(e)
			}
			var seq int
			var name, path string
			if e = base.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); e != nil {
				t.Fatal(e)
			}
			connector := &panicConnector{path: path}
			db := sql.OpenDB(connector)
			defer db.Close()
			db.SetMaxOpenConns(1)
			s, e := New(db, p.ManagerInstanceID)
			if e != nil {
				t.Fatal(e)
			}
			released := false
			acquire := func(context.Context, string, string) (AuthorityLease, error) {
				return releaseAuthority{check: func() error {
					if op != "active" {
						return errors.New("deny commit")
					}
					return nil
				}, release: func() {
					released = true
					if _, e := base.Exec(`BEGIN IMMEDIATE`); e != nil {
						t.Error("profile lock held at operator release", e)
						return
					}
					if _, e := base.Exec(`ROLLBACK`); e != nil {
						t.Error(e)
					}
				}}, nil
			}
			var active *ActiveLease
			if op == "active" {
				active, e = s.AcquireActive(ctx, p.CustomerID, p.InstallerProfileID, clock, acquire)
				if e != nil {
					t.Fatal(e)
				}
			}
			connector.rollback.Store(true)
			func() {
				defer func() {
					if recover() == nil {
						t.Error("rollback panic swallowed")
					}
				}()
				switch op {
				case "active":
					active.Release()
				case "create":
					q := p
					q.InstallerProfileID = "profile_" + strings.Repeat("4", 32)
					_, _ = s.Create(ctx, raw(t, q), now.Add(time.Hour).Unix(), clock, acquire)
				case "retire":
					_, _ = s.Retire(ctx, p.CustomerID, p.InstallerProfileID, record.Digest, true, clock, acquire)
				}
			}()
			if !released || connector.closes.Load() != 1 || db.Stats().InUse != 0 {
				t.Fatal("cleanup incomplete", released, connector.closes.Load(), db.Stats())
			}
			if _, e = s.Get(ctx, p.InstallerProfileID); e != nil {
				t.Fatal("reopen failed", e)
			}
		})
	}
}
