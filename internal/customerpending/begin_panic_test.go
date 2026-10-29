package customerpending

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/customerclaim"
	"modernc.org/sqlite"
)

type panicBeginConnector struct {
	path          string
	panicNext     atomic.Bool
	panicRollback atomic.Bool
	opens, closes atomic.Int32
}

func (p *panicBeginConnector) Driver() driver.Driver { return &sqlite.Driver{} }
func (p *panicBeginConnector) Connect(context.Context) (driver.Conn, error) {
	c, err := (&sqlite.Driver{}).Open(p.path)
	if err != nil {
		return nil, err
	}
	p.opens.Add(1)
	return &panicBeginConn{Conn: c, owner: p}, nil
}

type panicBeginConn struct {
	driver.Conn
	owner *panicBeginConnector
}

func (c *panicBeginConn) Close() error { c.owner.closes.Add(1); return c.Conn.Close() }
func (c *panicBeginConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if query == "ROLLBACK" && c.owner.panicRollback.CompareAndSwap(true, false) {
		panic("before SQLite ROLLBACK")
	}
	x, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	result, err := x.ExecContext(ctx, query, args)
	if err == nil && (query == "BEGIN" || query == "BEGIN IMMEDIATE") && c.owner.panicNext.CompareAndSwap(true, false) {
		panic("after SQLite BEGIN")
	}
	return result, err
}
func (c *panicBeginConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	x, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return x.QueryContext(ctx, query, args)
}

func TestBeginPanicDiscardsSQLiteConnectionAndReopens(t *testing.T) {
	for _, operation := range []string{"initialize", "accept", "records", "status", "review", "original"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(1790000000, 0).UTC()
			clock := func() time.Time { return now }
			path := filepath.Join(t.TempDir(), "pending.db")
			base := openFixture(t, path)
			var r Record
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			proof := proofFixture(t, now, 1, "customer_"+strings.Repeat("2", 32), "profile_"+strings.Repeat("3", 32), key, 4)
			if operation != "initialize" {
				if err = Initialize(ctx, base); err != nil {
					t.Fatal(err)
				}
				initial, _ := New(base)
				r, err = initial.Accept(ctx, proof, clock, leaseFor(func() error { return nil }))
				if err != nil {
					t.Fatal(err)
				}
			}
			if err = base.Close(); err != nil {
				t.Fatal(err)
			}
			connector := &panicBeginConnector{path: path}
			db := sql.OpenDB(connector)
			defer db.Close()
			db.SetMaxOpenConns(1)
			s, err := New(db)
			if err != nil {
				t.Fatal(err)
			}
			connector.panicNext.Store(true)
			func() {
				defer func() {
					if recover() == nil {
						t.Error("expected driver panic")
					}
				}()
				switch operation {
				case "initialize":
					_ = Initialize(ctx, db)
				case "accept":
					_, _ = s.Accept(ctx, proof, clock, leaseFor(func() error { return nil }))
				case "records":
					_, _ = s.Records(ctx)
				case "status":
					c := customerclaim.Context{ManagerID: r.ManagerID, CustomerID: r.CustomerID, InstallerProfileID: r.InstallerProfileID, Origin: r.Origin, AgentOrigin: r.AgentOrigin, IssuerFingerprint: r.IssuerFingerprint, ClaimID: r.ClaimID, Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)), ExpiresAt: now.Unix() + 60}
					_, _ = s.AcquireStatus(ctx, c, []byte("{}"), clock, leaseFor(func() error { return nil }))
				case "review":
					_, _ = s.AcquireReview(ctx, reviewExpected(r), clock, reviewLeaseFor(func() error { return nil }))
				case "original":
					_, _ = s.AcquireOriginal(ctx, reviewExpected(r), clock, func(context.Context, customerclaim.Metadata, string) (AuthorityLease, error) {
						return testLease{func() error { return nil }}, nil
					})
				}
			}()
			if connector.closes.Load() != 1 || db.Stats().InUse != 0 {
				t.Fatal("uncertain connection not discarded", connector.closes.Load(), db.Stats())
			}
			reopenCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if operation == "initialize" {
				if err := Initialize(reopenCtx, db); err != nil {
					t.Fatal("reinitialize after failed BEGIN", err)
				}
			} else {
				rows, err := s.Records(reopenCtx)
				if err != nil || len(rows) != 1 || rows[0].ClaimID != r.ClaimID || rows[0].DeadlineAt != r.DeadlineAt {
					t.Fatal("reopened state", err)
				}
			}
			if connector.opens.Load() < 2 {
				t.Fatal("connection not reopened")
			}
		})
	}
}
