package customerpending

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"
)

type testConnector struct {
	opens, closes atomic.Int32
	failRollback  bool
}
type testDriver struct{}
type testConn struct{ owner *testConnector }

func (c *testConnector) Connect(context.Context) (driver.Conn, error) {
	c.opens.Add(1)
	return &testConn{c}, nil
}
func (*testConnector) Driver() driver.Driver          { return testDriver{} }
func (testDriver) Open(string) (driver.Conn, error)   { return nil, errors.New("unused") }
func (*testConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *testConn) Close() error                      { c.owner.closes.Add(1); return nil }
func (*testConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }
func (c *testConn) ExecContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	if q == "ROLLBACK" && c.owner.failRollback {
		return nil, errors.New("rollback failed")
	}
	return driver.RowsAffected(0), nil
}

func TestFailedRollbackDiscardsUncertainConnection(t *testing.T) {
	for _, tc := range []struct {
		name            string
		fail, committed bool
		wantClosed      int32
	}{
		{"failed rollback", true, false, 1},
		{"successful rollback", false, false, 0},
		{"already committed", true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connector := &testConnector{failRollback: tc.fail}
			db := sql.OpenDB(connector)
			defer db.Close()
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(1)
			ctx := context.Background()
			conn, err := db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
				t.Fatal(err)
			}
			releaseTransaction(conn, tc.committed)
			if got := connector.closes.Load(); got != tc.wantClosed {
				t.Fatalf("closed connections = %d, want %d", got, tc.wantClosed)
			}
			conn, err = db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			wantOpens := int32(1) + tc.wantClosed
			if got := connector.opens.Load(); got != wantOpens {
				t.Fatalf("opened connections = %d, want %d", got, wantOpens)
			}
		})
	}
}
