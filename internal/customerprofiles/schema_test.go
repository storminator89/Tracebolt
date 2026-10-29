package customerprofiles

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFreshVersionMustBeZero(t *testing.T) {
	db, e := sql.Open("sqlite", filepath.Join(t.TempDir(), "profiles.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(`PRAGMA user_version=1`); e != nil {
		t.Fatal(e)
	}
	if e = Initialize(context.Background(), db, "manager_"+strings.Repeat("1", 32)); !errors.Is(e, ErrStorage) {
		t.Fatalf("nonfresh version initialized: %v", e)
	}
}

func TestRejectAlteredSchemaOnReadAndWrite(t *testing.T) {
	for name, ddl := range map[string]string{
		"extra-trigger":     `CREATE TRIGGER injected AFTER INSERT ON customer_profiles_records BEGIN DELETE FROM customer_profiles_records; END`,
		"temporary-trigger": `CREATE TEMP TRIGGER injected AFTER INSERT ON customer_profiles_records BEGIN DELETE FROM customer_profiles_records; END`,
		"extra-index":       `CREATE INDEX injected ON customer_profiles_records(body)`,
		"extra-view":        `CREATE VIEW sqliteXhidden AS SELECT * FROM customer_profiles_records`,
		"changed-table":     `ALTER TABLE customer_profiles_records ADD COLUMN unexpected TEXT`,
		"missing-table":     `DROP TABLE customer_profiles_records`,
		"wrong-version":     `PRAGMA user_version=2`,
		"attached-db":       `ATTACH DATABASE ':memory:' AS injected`,
	} {
		t.Run(name, func(t *testing.T) {
			s, db, now, p := fixture(t)
			db.SetMaxOpenConns(1)
			ctx := context.Background()
			if _, e := db.Exec(ddl); e != nil {
				t.Fatal(e)
			}
			if _, e := s.Get(ctx, p.InstallerProfileID); !errors.Is(e, ErrStorage) {
				t.Fatalf("read accepted changed schema: %v", e)
			}
			if _, e := s.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), func() time.Time { return *now }, guard); !errors.Is(e, ErrStorage) {
				t.Fatalf("write accepted changed schema: %v", e)
			}
		})
	}
}

func TestSchemaMutationCannotRaceProfileCommit(t *testing.T) {
	s, db, now, p := fixture(t)
	db.SetMaxOpenConns(2)
	ctx := context.Background()
	other, e := db.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if _, e = other.ExecContext(ctx, `PRAGMA busy_timeout=1`); e != nil {
		t.Fatal(e)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	result := make(chan error, 1)
	acquire := func(ctx context.Context, customer, profile string) (AuthorityLease, error) {
		return &testAuthority{check: func() error { once.Do(func() { close(entered); <-release }); return nil }}, nil
	}
	profileRaw := raw(t, p)
	go func() {
		_, err := s.Create(ctx, profileRaw, now.Add(time.Hour).Unix(), func() time.Time { return *now }, acquire)
		result <- err
	}()
	<-entered
	ddl := `CREATE TRIGGER injected AFTER INSERT ON customer_profiles_records BEGIN DELETE FROM customer_profiles_records; END`
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
	if _, e = s.Get(ctx, p.InstallerProfileID); !errors.Is(e, ErrStorage) {
		t.Fatal("later schema mutation accepted", e)
	}
}

func TestExtraMetadataRowFailsClosed(t *testing.T) {
	s, db, now, p := fixture(t)
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	if _, e := db.Exec(`PRAGMA ignore_check_constraints=ON`); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(`INSERT INTO customer_profiles_meta(id,manager_id,count,last_at) VALUES(2,?,0,0)`, p.ManagerInstanceID); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(`PRAGMA ignore_check_constraints=OFF`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Get(ctx, p.InstallerProfileID); !errors.Is(e, ErrStorage) {
		t.Fatalf("read accepted extra metadata row: %v", e)
	}
	if _, e := s.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), func() time.Time { return *now }, guard); !errors.Is(e, ErrStorage) {
		t.Fatalf("write accepted extra metadata row: %v", e)
	}
}
