package customerpending

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRejectAlteredSchemaOnReadAndWrite(t *testing.T) {
	for name, ddl := range map[string]string{
		"extra-trigger":     `CREATE TRIGGER injected AFTER INSERT ON customer_pending_claims BEGIN DELETE FROM customer_pending_claims; END`,
		"temporary-trigger": `CREATE TEMP TRIGGER injected AFTER INSERT ON customer_pending_claims BEGIN DELETE FROM customer_pending_claims; END`,
		"extra-index":       `CREATE INDEX injected ON customer_pending_claims(body)`,
		"extra-view":        `CREATE VIEW sqliteXhidden AS SELECT * FROM customer_pending_claims`,
		"changed-table":     `ALTER TABLE customer_pending_claims ADD COLUMN unexpected TEXT`,
		"missing-table":     `DROP TABLE customer_pending_claims`,
		"wrong-version":     `PRAGMA user_version=2`,
		"attached-db":       `ATTACH DATABASE ':memory:' AS injected`,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(1790000000, 0).UTC()
			db := openFixture(t, filepath.Join(t.TempDir(), "pending.db"))
			if e := Initialize(ctx, db); e != nil {
				t.Fatal(e)
			}
			s, _ := New(db)
			if _, e := db.Exec(ddl); e != nil {
				t.Fatal(e)
			}
			if _, e := s.Records(ctx); !errors.Is(e, ErrStorage) {
				t.Fatalf("read accepted changed schema: %v", e)
			}
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			p := proofFixture(t, now, 1, "customer_"+strings.Repeat("2", 32), "profile_"+strings.Repeat("3", 32), key, 4)
			if _, e := s.Accept(ctx, p, func() time.Time { return now }, leaseFor(func() error { return nil })); !errors.Is(e, ErrStorage) {
				t.Fatalf("write accepted changed schema: %v", e)
			}
		})
	}
}

func TestFreshVersionMustBeZero(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t, filepath.Join(t.TempDir(), "pending.db"))
	if _, e := db.Exec(`PRAGMA user_version=1`); e != nil {
		t.Fatal(e)
	}
	if e := Initialize(ctx, db); !errors.Is(e, ErrStorage) {
		t.Fatalf("nonfresh version initialized: %v", e)
	}
}

func TestSchemaMutationCannotRacePendingCommit(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1790000000, 0).UTC()
	db := openFixture(t, filepath.Join(t.TempDir(), "pending.db"))
	if e := Initialize(ctx, db); e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(2)
	other, e := db.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if _, e = other.ExecContext(ctx, `PRAGMA busy_timeout=1`); e != nil {
		t.Fatal(e)
	}
	s, _ := New(db)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	proof := proofFixture(t, now, 1, "customer_"+strings.Repeat("2", 32), "profile_"+strings.Repeat("3", 32), key, 4)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	result := make(chan error, 1)
	go func() {
		_, err := s.Accept(ctx, proof, func() time.Time { return now }, leaseFor(func() error { once.Do(func() { close(entered); <-release }); return nil }))
		result <- err
	}()
	<-entered
	ddl := `CREATE TRIGGER injected AFTER INSERT ON customer_pending_claims BEGIN DELETE FROM customer_pending_claims; END`
	if _, e = other.ExecContext(ctx, ddl); e == nil {
		close(release)
		t.Fatal("DDL raced an active write transaction")
	}
	close(release)
	if e = <-result; e != nil {
		t.Fatal(e)
	}
	if _, e = other.ExecContext(ctx, ddl); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Records(ctx); !errors.Is(e, ErrStorage) {
		t.Fatal("later schema mutation accepted", e)
	}
}

func TestExtraMetadataRowFailsClosed(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1790000000, 0).UTC()
	db := openFixture(t, filepath.Join(t.TempDir(), "pending.db"))
	if e := Initialize(ctx, db); e != nil {
		t.Fatal(e)
	}
	s, _ := New(db)
	for _, q := range []string{`PRAGMA ignore_check_constraints=ON`, `INSERT INTO customer_pending_meta(id,count,last_at) VALUES(2,0,0)`, `PRAGMA ignore_check_constraints=OFF`} {
		if _, e := db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.Records(ctx); !errors.Is(e, ErrStorage) {
		t.Fatalf("read accepted extra metadata row: %v", e)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	proof := proofFixture(t, now, 1, "customer_"+strings.Repeat("2", 32), "profile_"+strings.Repeat("3", 32), key, 4)
	if _, e := s.Accept(ctx, proof, func() time.Time { return now }, leaseFor(func() error { return nil })); !errors.Is(e, ErrStorage) {
		t.Fatalf("write accepted extra metadata row: %v", e)
	}
}
