package inventoryledger

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	_ "modernc.org/sqlite"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var fixtureTime = time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
var fixtureRevoked = errors.New("fixture_revoked")

type fixture struct {
	db     *sql.DB
	ledger *Ledger
	path   string
	key    CursorKey
}

func openFixtureDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, e := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)&_pragma=foreign_keys(ON)")
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}
func newFixture(t *testing.T, limits Limits) *fixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.sqlite")
	db := openFixtureDB(t, path)
	l, e := New(limits)
	if e != nil {
		t.Fatal(e)
	}
	key, e := NewCursorKey([32]byte{1, 2, 3})
	if e != nil {
		t.Fatal(e)
	}
	f := &fixture{db, l, path, key}
	e = f.run(false)(context.Background(), func(tx Transaction) error {
		if _, e := tx.ExecContext(context.Background(), `CREATE TABLE fixture_authority(active INTEGER NOT NULL); INSERT INTO fixture_authority VALUES(1)`); e != nil {
			return e
		}
		return l.Initialize(context.Background(), tx)
	})
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *fixture) run(checkAuthority bool) AuthorityTransaction {
	return func(ctx context.Context, action func(Transaction) error) error {
		conn, e := f.db.Conn(ctx)
		if e != nil {
			return e
		}
		defer conn.Close()
		if _, e = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
			return e
		}
		defer conn.ExecContext(context.Background(), "ROLLBACK")
		if checkAuthority {
			var active int
			if e = conn.QueryRowContext(ctx, "SELECT active FROM fixture_authority").Scan(&active); e != nil {
				return e
			}
			if active != 1 {
				return fixtureRevoked
			}
		}
		if e = action(conn); e != nil {
			return e
		}
		_, e = conn.ExecContext(ctx, "COMMIT")
		return e
	}
}
func commit[T any](t *testing.T, f *fixture, fn func(Transaction) (T, error)) T {
	t.Helper()
	v, e := CommitResult(context.Background(), f.run(true), fn)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func fixtureInventory(t *testing.T, generation, rows int) (fullinventory.Manifest, []fullinventory.Chunk) {
	t.Helper()
	items := make([]linuxpackages.PackageRow, rows)
	for i := range items {
		name := fmt.Sprintf("fixture-%06d", i)
		items[i] = linuxpackages.PackageRow{Name: name, Version: "1.2.3-1", Architecture: "amd64", SourcePackage: name, SourceVersion: "1.2.3-1", SourceMapping: "binary-default", InstallState: "installed"}
	}
	m, c, e := fullinventory.Build(context.Background(), fullinventory.SourceInventory{GenerationID: fmt.Sprintf("sample_%032x", generation), CollectedAt: fixtureTime, Rows: items, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	return m, c
}
func stage(t *testing.T, f *fixture, device string, m fullinventory.Manifest, chunks []fullinventory.Chunk, now time.Time) {
	t.Helper()
	commit(t, f, func(tx Transaction) (BeginReceipt, error) {
		return f.ledger.Begin(context.Background(), tx, device, m, now)
	})
	for _, c := range chunks {
		commit(t, f, func(tx Transaction) (ChunkReceipt, error) {
			return f.ledger.Append(context.Background(), tx, device, c, now.Add(time.Second))
		})
	}
}
func complete(t *testing.T, f *fixture, device string, m fullinventory.Manifest, c []fullinventory.Chunk, now time.Time) Completion {
	t.Helper()
	stage(t, f, device, m, c, now)
	return commit(t, f, func(tx Transaction) (Completion, error) {
		return f.ledger.Promote(context.Background(), tx, device, m.GenerationID, now.Add(2*time.Second))
	})
}
func page(t *testing.T, f *fixture, device string, r PageRequest, now time.Time) PageResult {
	t.Helper()
	return commit(t, f, func(tx Transaction) (PageResult, error) {
		return f.ledger.Page(context.Background(), tx, device, r, now, f.key)
	})
}
func assertError[T any](t *testing.T, f *fixture, want error, fn func(Transaction) (T, error)) {
	t.Helper()
	got, e := CommitResult(context.Background(), f.run(true), fn)
	var zero T
	if !errors.Is(e, want) || !reflect.DeepEqual(got, zero) {
		t.Fatalf("error/zero mismatch: %v, zero=%v", e, reflect.DeepEqual(got, zero))
	}
}
func assertAccounting(t *testing.T, f *fixture) {
	t.Helper()
	e := f.run(false)(context.Background(), func(tx Transaction) error {
		rows, e := tx.QueryContext(context.Background(), `SELECT scope,held_rows,held_chunks,stored_bytes,generations FROM fi_budget`)
		if e != nil {
			return e
		}
		type entry struct {
			scope string
			b     budget
		}
		entries := []entry{}
		for rows.Next() {
			var x entry
			if e = rows.Scan(&x.scope, &x.b.rows, &x.b.chunks, &x.b.bytes, &x.b.generations); e != nil {
				return e
			}
			entries = append(entries, x)
		}
		if e = rows.Close(); e != nil {
			return e
		}
		for _, x := range entries {
			var physical, gen int64
			filter := ""
			args := []any{}
			if x.scope != "" {
				filter = " WHERE device=?"
				args = []any{x.scope}
			}
			for _, table := range []string{"fi_chunks", "fi_rows"} {
				var n int64
				if e = tx.QueryRowContext(context.Background(), `SELECT coalesce(sum(length(body)),0) FROM `+table+filter, args...).Scan(&n); e != nil {
					return e
				}
				physical += n
			}
			var meta int64
			if e = tx.QueryRowContext(context.Background(), `SELECT coalesce(sum(length(manifest)+length(checkpoint)),0),count(*) FROM fi_generations`+filter, args...).Scan(&meta, &gen); e != nil {
				return e
			}
			physical += meta
			if physical != x.b.bytes || gen != x.b.generations {
				return fmt.Errorf("accounting mismatch for fixture scope: bytes %d/%d generations %d/%d", physical, x.b.bytes, gen, x.b.generations)
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestCompleteDurablePaginationAndExactRetry(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	m, chunks := fixtureInventory(t, 1, 377)
	begin := commit(t, f, func(tx Transaction) (BeginReceipt, error) {
		return f.ledger.Begin(context.Background(), tx, "device-a", m, fixtureTime)
	})
	first := commit(t, f, func(tx Transaction) (ChunkReceipt, error) {
		return f.ledger.Append(context.Background(), tx, "device-a", chunks[0], fixtureTime.Add(time.Second))
	})
	// A separate pool and Ledger simulate a process restart against the same file.
	l, e := New(DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	reopened := &fixture{openFixtureDB(t, f.path), l, f.path, f.key}
	again := commit(t, reopened, func(tx Transaction) (BeginReceipt, error) {
		return l.Begin(context.Background(), tx, "device-a", m, fixtureTime.Add(time.Minute))
	})
	retry := commit(t, reopened, func(tx Transaction) (ChunkReceipt, error) {
		return l.Append(context.Background(), tx, "device-a", chunks[0], fixtureTime.Add(time.Minute))
	})
	if begin != again || first != retry {
		t.Fatal("retry changed original receipt/time")
	}
	for _, c := range chunks[1:] {
		commit(t, reopened, func(tx Transaction) (ChunkReceipt, error) {
			return l.Append(context.Background(), tx, "device-a", c, fixtureTime.Add(time.Minute))
		})
	}
	completion := commit(t, reopened, func(tx Transaction) (Completion, error) {
		return l.Promote(context.Background(), tx, "device-a", m.GenerationID, fixtureTime.Add(2*time.Minute))
	})
	if !completion.Manifest.CollectedAt.Equal(fixtureTime) || !completion.StartedAt.Equal(begin.StartedAt) {
		t.Fatal("original times changed")
	}
	count := 0
	cursor := ""
	for {
		p := page(t, reopened, "device-a", PageRequest{Limit: 73, Cursor: cursor}, fixtureTime.Add(3*time.Minute))
		count += len(p.Items)
		if p.TotalRows != 377 {
			t.Fatal("wrong total")
		}
		if p.Exhausted {
			if p.NextCursor != "" {
				t.Fatal("exhausted cursor")
			}
			break
		}
		if p.NextCursor == "" {
			t.Fatal("missing continuation")
		}
		cursor = p.NextCursor
	}
	if count != 377 {
		t.Fatalf("lost rows: %d", count)
	}
	assertAccounting(t, reopened)
}

func TestIncompleteConflictAndExpiredStagePreserveCurrent(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	old, c := fixtureInventory(t, 1, 11)
	complete(t, f, "device-a", old, c, fixtureTime)
	pending, chunks := fixtureInventory(t, 2, 300)
	stage(t, f, "device-a", pending, chunks[:1], fixtureTime.Add(time.Minute))
	assertError(t, f, ErrIncomplete, func(tx Transaction) (Completion, error) {
		return f.ledger.Promote(context.Background(), tx, "device-a", pending.GenerationID, fixtureTime.Add(2*time.Minute))
	})
	// Another valid manifest using the same generation identifier conflicts.
	other, _ := fixtureInventory(t, 2, 301)
	assertError(t, f, ErrConflict, func(tx Transaction) (BeginReceipt, error) {
		return f.ledger.Begin(context.Background(), tx, "device-a", other, fixtureTime.Add(2*time.Minute))
	})
	assertError(t, f, ErrConflict, func(tx Transaction) (ChunkReceipt, error) {
		return f.ledger.Append(context.Background(), tx, "device-a", chunks[2], fixtureTime.Add(2*time.Minute))
	})
	assertError(t, f, ErrExpired, func(tx Transaction) (ChunkReceipt, error) {
		return f.ledger.Append(context.Background(), tx, "device-a", chunks[1], fixtureTime.Add(16*time.Minute))
	})
	p := page(t, f, "device-a", PageRequest{Limit: 100}, fixtureTime.Add(17*time.Minute))
	if p.Manifest.GenerationID != old.GenerationID || len(p.Items) != 11 {
		t.Fatal("incomplete replaced complete")
	}
	assertAccounting(t, f)
}

func TestValidZeroRowGeneration(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	m, chunks := fixtureInventory(t, 1, 0)
	if len(chunks) != 0 {
		t.Fatal("expected zero chunks")
	}
	complete(t, f, "device-a", m, chunks, fixtureTime)
	p := page(t, f, "device-a", PageRequest{Limit: 10}, fixtureTime.Add(time.Minute))
	if !p.Exhausted || p.Items == nil || len(p.Items) != 0 || p.TotalRows != 0 {
		t.Fatal("zero generation not faithfully complete")
	}
	assertAccounting(t, f)
}

func TestSearchResumesPastScanBudget(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	m, chunks := fixtureInventory(t, 1, 2300)
	complete(t, f, "device-a", m, chunks, fixtureTime)
	p := page(t, f, "device-a", PageRequest{Limit: 10, Search: "fixture-002299"}, fixtureTime.Add(time.Minute))
	if len(p.Items) != 0 || p.Exhausted || !p.SearchIncomplete || p.ScannedRows != MaxScanRows || p.NextCursor == "" {
		t.Fatal("bounded scan misrepresented empty results")
	}
	q := page(t, f, "device-a", PageRequest{Limit: 10, Search: "fixture-002299", Cursor: p.NextCursor}, fixtureTime.Add(2*time.Minute))
	if len(q.Items) != 1 || q.Items[0].Name != "fixture-002299" || !q.Exhausted || q.SearchIncomplete || !q.CursorExpiresAt.Equal(p.CursorExpiresAt) {
		t.Fatal("unreachable tail or refreshed cursor")
	}
}

func TestCursorBindingAndGenerationRetention(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	a, ca := fixtureInventory(t, 1, 220)
	complete(t, f, "device-a", a, ca, fixtureTime)
	p := page(t, f, "device-a", PageRequest{Limit: 50}, fixtureTime.Add(time.Minute))
	b, cb := fixtureInventory(t, 2, 5)
	complete(t, f, "device-a", b, cb, fixtureTime.Add(2*time.Minute))
	q := page(t, f, "device-a", PageRequest{Limit: 50, Cursor: p.NextCursor}, fixtureTime.Add(3*time.Minute))
	if q.Manifest.GenerationID != a.GenerationID || q.Items[0].Name != "fixture-000050" {
		t.Fatal("cursor crossed generation")
	}
	for _, test := range []struct {
		device  string
		request PageRequest
	}{
		{"device-b", PageRequest{Limit: 50, Cursor: p.NextCursor}},
		{"device-a", PageRequest{Limit: 50, Search: "changed", Cursor: p.NextCursor}},
		{"device-a", PageRequest{Limit: 50, GenerationID: b.GenerationID, Cursor: p.NextCursor}},
		{"device-a", PageRequest{Limit: 51, Cursor: p.NextCursor}},
		{"device-a", PageRequest{Limit: 50, Cursor: p.NextCursor + "x"}},
	} {
		assertError(t, f, ErrCursor, func(tx Transaction) (PageResult, error) {
			return f.ledger.Page(context.Background(), tx, test.device, test.request, fixtureTime.Add(3*time.Minute), f.key)
		})
	}
	assertError(t, f, ErrConflict, func(tx Transaction) (CleanupResult, error) {
		return f.ledger.Cleanup(context.Background(), tx, "device-a", a.GenerationID, fixtureTime.Add(3*time.Minute))
	})
	result := commit(t, f, func(tx Transaction) (CleanupResult, error) {
		return f.ledger.Cleanup(context.Background(), tx, "device-a", a.GenerationID, fixtureTime.Add(18*time.Minute))
	})
	if !result.Done {
		t.Fatal("expected bounded generation reclaimed")
	}
	assertError(t, f, ErrCursorExpired, func(tx Transaction) (PageResult, error) {
		return f.ledger.Page(context.Background(), tx, "device-a", PageRequest{Limit: 50, Cursor: p.NextCursor}, fixtureTime.Add(18*time.Minute), f.key)
	})
	current := page(t, f, "device-a", PageRequest{Limit: 10}, fixtureTime.Add(18*time.Minute))
	if current.Manifest.GenerationID != b.GenerationID {
		t.Fatal("cleanup removed current")
	}
	assertAccounting(t, f)
}

func TestCleanupIsBoundedAndReservationsRemain(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	m, chunks := fixtureInventory(t, 1, 900)
	stage(t, f, "device-a", m, chunks, fixtureTime)
	commit(t, f, func(tx Transaction) (struct{}, error) {
		return struct{}{}, f.ledger.Abandon(context.Background(), tx, "device-a", m.GenerationID, fixtureTime.Add(time.Minute))
	})
	removed := 0
	for i := 0; i < 10; i++ {
		c := commit(t, f, func(tx Transaction) (CleanupResult, error) {
			return f.ledger.Cleanup(context.Background(), tx, "device-a", m.GenerationID, fixtureTime.Add(time.Minute))
		})
		if c.RowsDeleted > MaxCleanupRows || c.ChunksDeleted > MaxCleanupChunks {
			t.Fatal("unbounded cleanup")
		}
		removed += c.RowsDeleted
		assertAccounting(t, f)
		var held int64
		if e := f.db.QueryRow(`SELECT held_rows FROM fi_budget WHERE scope=''`).Scan(&held); e != nil {
			t.Fatal(e)
		}
		if c.Done {
			if held != 0 || removed != 900 {
				t.Fatal("reservation not released at completion")
			}
			break
		}
		if held != 900 {
			t.Fatal("reservation freed before physical cleanup")
		}
		if i == 9 {
			t.Fatal("cleanup failed to terminate")
		}
	}
	var devices int
	if e := f.db.QueryRow(`SELECT count(*) FROM fi_devices`).Scan(&devices); e != nil || devices != 0 {
		t.Fatal("empty device metadata leaked")
	}
}

func TestCompetingHandlesSerializeGlobalReservations(t *testing.T) {
	limits := DefaultLimits()
	limits.GlobalRows = 500
	f := newFixture(t, limits)
	otherLedger, _ := New(limits)
	other := &fixture{openFixtureDB(t, f.path), otherLedger, f.path, f.key}
	m, _ := fixtureInventory(t, 1, 300)
	start := make(chan struct{})
	out := make(chan error, 2)
	var wg sync.WaitGroup
	for i, h := range []*fixture{f, other} {
		wg.Add(1)
		go func(i int, h *fixture) {
			defer wg.Done()
			<-start
			_, e := CommitResult(context.Background(), h.run(true), func(tx Transaction) (BeginReceipt, error) {
				return h.ledger.Begin(context.Background(), tx, fmt.Sprintf("device-%d", i), m, fixtureTime)
			})
			out <- e
		}(i, h)
	}
	close(start)
	wg.Wait()
	close(out)
	ok, quota := 0, 0
	for e := range out {
		if e == nil {
			ok++
		} else if errors.Is(e, ErrQuota) {
			quota++
		} else {
			t.Fatal(e)
		}
	}
	if ok != 1 || quota != 1 {
		t.Fatalf("quota race: %d successes %d quota failures", ok, quota)
	}
	assertAccounting(t, f)
	var devices int
	if e := f.db.QueryRow(`SELECT count(*) FROM fi_devices`).Scan(&devices); e != nil || devices != 1 {
		t.Fatal("failed reservation persisted state")
	}
}

func TestCommitFailureSuppressesOutputAndPromotion(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	old, c := fixtureInventory(t, 1, 10)
	complete(t, f, "device-a", old, c, fixtureTime)
	m, chunks := fixtureInventory(t, 2, 20)
	stage(t, f, "device-a", m, chunks, fixtureTime.Add(time.Minute))
	// SQLite COMMIT really fails: the caller's authority transaction has an unmet
	// deferred foreign-key constraint. The ledger must not expose its new result.
	if _, e := f.db.Exec(`CREATE TABLE fixture_parent(id INTEGER PRIMARY KEY); CREATE TABLE fixture_child(id INTEGER REFERENCES fixture_parent(id) DEFERRABLE INITIALLY DEFERRED)`); e != nil {
		t.Fatal(e)
	}
	got, e := CommitResult(context.Background(), f.run(true), func(tx Transaction) (Completion, error) {
		result, e := f.ledger.Promote(context.Background(), tx, "device-a", m.GenerationID, fixtureTime.Add(2*time.Minute))
		if e != nil {
			return Completion{}, e
		}
		if _, e = tx.ExecContext(context.Background(), `INSERT INTO fixture_child VALUES(99)`); e != nil {
			return Completion{}, e
		}
		return result, nil
	})
	if e == nil || !reflect.DeepEqual(got, Completion{}) {
		t.Fatal("failed commit leaked completion")
	}
	p := page(t, f, "device-a", PageRequest{Limit: 100}, fixtureTime.Add(3*time.Minute))
	if p.Manifest.GenerationID != old.GenerationID {
		t.Fatal("failed commit changed current")
	}
	assertAccounting(t, f)
}

func TestAuthorityRevocationAndPageFailureReturnZero(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	m, c := fixtureInventory(t, 1, 4)
	complete(t, f, "device-a", m, c, fixtureTime)
	if _, e := f.db.Exec(`UPDATE fixture_authority SET active=0`); e != nil {
		t.Fatal(e)
	}
	assertError(t, f, fixtureRevoked, func(tx Transaction) (PageResult, error) {
		return f.ledger.Page(context.Background(), tx, "device-a", PageRequest{Limit: 10}, fixtureTime.Add(time.Minute), f.key)
	})
	if _, e := f.db.Exec(`UPDATE fixture_authority SET active=1; UPDATE fi_rows SET body='invalid' WHERE ordinal=1`); e == nil {
		t.Fatal("STRICT BLOB rejected mutation fixture expected")
	}
	if _, e := f.db.Exec(`UPDATE fixture_authority SET active=1; UPDATE fi_rows SET body=? WHERE ordinal=1`, []byte(`{"name":"broken"}`)); e != nil {
		t.Fatal(e)
	}
	assertError(t, f, ErrStorage, func(tx Transaction) (PageResult, error) {
		return f.ledger.Page(context.Background(), tx, "device-a", PageRequest{Limit: 10}, fixtureTime.Add(time.Minute), f.key)
	})
}

func TestCheckpointCounterMismatchRejectsAndKeepsCurrent(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	old, c := fixtureInventory(t, 1, 1)
	complete(t, f, "device-a", old, c, fixtureTime)
	m, chunks := fixtureInventory(t, 2, 200)
	stage(t, f, "device-a", m, chunks[:1], fixtureTime.Add(time.Minute))
	if _, e := f.db.Exec(`UPDATE fi_generations SET row_bytes=row_bytes+1 WHERE generation=?`, m.GenerationID); e != nil {
		t.Fatal(e)
	}
	assertError(t, f, ErrStorage, func(tx Transaction) (ChunkReceipt, error) {
		return f.ledger.Append(context.Background(), tx, "device-a", chunks[1], fixtureTime.Add(2*time.Minute))
	})
	p := page(t, f, "device-a", PageRequest{Limit: 10}, fixtureTime.Add(3*time.Minute))
	if p.Manifest.GenerationID != old.GenerationID {
		t.Fatal("corruption affected old current")
	}
}

func TestLimitsAndKeysAreExplicit(t *testing.T) {
	invalid := DefaultLimits()
	invalid.GlobalBytes++
	if _, e := New(invalid); !errors.Is(e, ErrInvalid) {
		t.Fatal("ceiling bypass")
	}
	f := newFixture(t, DefaultLimits())
	m, c := fixtureInventory(t, 1, 1)
	complete(t, f, "device-a", m, c, fixtureTime)
	for _, r := range []PageRequest{{Limit: 0}, {Limit: 101}, {Limit: 1, Search: strings.Repeat("x", 129)}, {Limit: 1, Search: "\x00"}} {
		assertError(t, f, ErrInvalid, func(tx Transaction) (PageResult, error) {
			return f.ledger.Page(context.Background(), tx, "device-a", r, fixtureTime.Add(time.Minute), f.key)
		})
	}
	raw, _ := json.Marshal(f.key)
	if string(raw) != `"redacted"` || strings.Contains(fmt.Sprintf("%#v", f.key), "[32]") {
		t.Fatal("cursor key diagnostic leak")
	}
	assertError(t, f, ErrConflict, func(tx Transaction) (CleanupResult, error) {
		return f.ledger.Cleanup(context.Background(), tx, "device-a", m.GenerationID, fixtureTime.Add(2*ObservationTTL))
	})
}

func TestByteQuotaRejectsChunkWithoutAffectingCurrent(t *testing.T) {
	limits := DefaultLimits()
	limits.DeviceBytes = 12000
	f := newFixture(t, limits)
	old, c := fixtureInventory(t, 1, 1)
	complete(t, f, "device-a", old, c, fixtureTime)
	m, chunks := fixtureInventory(t, 2, 128)
	stage(t, f, "device-a", m, nil, fixtureTime.Add(time.Minute))
	var before budget
	commit(t, f, func(tx Transaction) (struct{}, error) {
		var e error
		before, e = readBudget(context.Background(), tx, "device-a")
		return struct{}{}, e
	})
	assertError(t, f, ErrQuota, func(tx Transaction) (ChunkReceipt, error) {
		return f.ledger.Append(context.Background(), tx, "device-a", chunks[0], fixtureTime.Add(2*time.Minute))
	})
	commit(t, f, func(tx Transaction) (struct{}, error) {
		after, e := readBudget(context.Background(), tx, "device-a")
		if after != before {
			t.Fatal("quota failure changed accounting")
		}
		return struct{}{}, e
	})
	p := page(t, f, "device-a", PageRequest{Limit: 1}, fixtureTime.Add(3*time.Minute))
	if p.Manifest.GenerationID != old.GenerationID {
		t.Fatal("quota failure replaced complete")
	}
	assertAccounting(t, f)
}

func TestChunkConflictAndCleanupFailureAreAtomic(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	m, chunks := fixtureInventory(t, 1, 400)
	stage(t, f, "device-a", m, chunks, fixtureTime)
	// A valid chunk from a different semantic manifest with the same generation
	// and ordinal is a conflict, never an overwrite or an idempotent retry.
	_, different := fixtureInventory(t, 1, 401)
	assertError(t, f, ErrConflict, func(tx Transaction) (ChunkReceipt, error) {
		return f.ledger.Append(context.Background(), tx, "device-a", different[0], fixtureTime.Add(time.Minute))
	})
	commit(t, f, func(tx Transaction) (struct{}, error) {
		return struct{}{}, f.ledger.Abandon(context.Background(), tx, "device-a", m.GenerationID, fixtureTime.Add(time.Minute))
	})
	if _, e := f.db.Exec(`CREATE TRIGGER fixture_fail_delete BEFORE DELETE ON fi_chunks BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	assertError(t, f, ErrStorage, func(tx Transaction) (CleanupResult, error) {
		return f.ledger.Cleanup(context.Background(), tx, "device-a", m.GenerationID, fixtureTime.Add(2*time.Minute))
	})
	var count int
	if e := f.db.QueryRow(`SELECT count(*) FROM fi_rows`).Scan(&count); e != nil || count != 400 {
		t.Fatal("cleanup error persisted partial row deletion")
	}
	assertAccounting(t, f)
	if _, e := f.db.Exec(`DROP TRIGGER fixture_fail_delete`); e != nil {
		t.Fatal(e)
	}
	result := commit(t, f, func(tx Transaction) (CleanupResult, error) {
		return f.ledger.Cleanup(context.Background(), tx, "device-a", m.GenerationID, fixtureTime.Add(3*time.Minute))
	})
	if result.Done || result.RowsDeleted != MaxCleanupRows {
		t.Fatal("retry cleanup did not advance bounded batch")
	}
	assertAccounting(t, f)
}

func TestRetainedGenerationQuotaCannotBeBypassed(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	for id := 1; id <= 3; id++ {
		m, c := fixtureInventory(t, id, 2)
		complete(t, f, "device-a", m, c, fixtureTime.Add(time.Duration(id)*time.Minute))
	}
	m, _ := fixtureInventory(t, 4, 2)
	assertError(t, f, ErrQuota, func(tx Transaction) (BeginReceipt, error) {
		return f.ledger.Begin(context.Background(), tx, "device-a", m, fixtureTime.Add(4*time.Minute))
	})
	first, _ := fixtureInventory(t, 1, 2)
	commit(t, f, func(tx Transaction) (CleanupResult, error) {
		return f.ledger.Cleanup(context.Background(), tx, "device-a", first.GenerationID, fixtureTime.Add(18*time.Minute))
	})
	commit(t, f, func(tx Transaction) (BeginReceipt, error) {
		return f.ledger.Begin(context.Background(), tx, "device-a", m, fixtureTime.Add(18*time.Minute))
	})
	assertAccounting(t, f)
}

func TestAllSupportedRowsHaveReachableTail(t *testing.T) {
	if testing.Short() {
		t.Skip("100000-row synthetic storage ceiling fixture")
	}
	f := newFixture(t, DefaultLimits())
	m, chunks := fixtureInventory(t, 1, fullinventory.MaxGenerationRows)
	started := time.Now()
	complete(t, f, "device-a", m, chunks, fixtureTime)
	cursor := ""
	scanned := 0
	pages := 0
	found := false
	for {
		p := page(t, f, "device-a", PageRequest{Limit: 1, Search: "fixture-099999", Cursor: cursor}, fixtureTime.Add(time.Minute))
		pages++
		scanned += p.ScannedRows
		if len(p.Items) > 0 {
			if len(p.Items) != 1 || p.Items[0].Name != "fixture-099999" {
				t.Fatal("wrong tail match")
			}
			found = true
		}
		if p.Exhausted {
			break
		}
		if p.NextCursor == "" || p.NextCursor == cursor {
			t.Fatal("nonadvancing scan")
		}
		cursor = p.NextCursor
	}
	if !found || scanned != fullinventory.MaxGenerationRows || pages != 49 {
		t.Fatalf("all-row reachability failed: found=%v rows=%d pages=%d", found, scanned, pages)
	}
	assertAccounting(t, f)
	var bytes int64
	if e := f.db.QueryRow(`SELECT stored_bytes FROM fi_budget WHERE scope=''`).Scan(&bytes); e != nil {
		t.Fatal(e)
	}
	t.Logf("synthetic full ceiling: rows=%d chunks=%d pages=%d logicalBytes=%d elapsed=%s", m.ObservedCount, len(chunks), pages, bytes, time.Since(started).Round(time.Millisecond))
}

func TestPageAndCleanupQueriesUseBoundedIndexes(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	for _, q := range []string{
		`EXPLAIN QUERY PLAN SELECT ordinal,body FROM fi_rows WHERE device='fixture' AND generation='fixture' AND ordinal>=0 ORDER BY ordinal LIMIT 2048`,
		`EXPLAIN QUERY PLAN SELECT ordinal,length(body) FROM fi_chunks WHERE device='fixture' AND generation='fixture' ORDER BY ordinal LIMIT 16`,
	} {
		rows, e := f.db.Query(q)
		if e != nil {
			t.Fatal(e)
		}
		indexed := false
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if e = rows.Scan(&id, &parent, &unused, &detail); e != nil {
				t.Fatal(e)
			}
			if strings.Contains(detail, "SEARCH") && strings.Contains(detail, "INDEX") {
				indexed = true
			}
			if strings.Contains(detail, "SCAN ") || strings.Contains(detail, "TEMP B-TREE") {
				t.Fatalf("unbounded plan: %s", detail)
			}
		}
		rows.Close()
		if !indexed {
			t.Fatal("indexed search missing")
		}
	}
}

func TestMissingTerminalRowFailsWithoutPartialPage(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	m, c := fixtureInventory(t, 1, 4)
	complete(t, f, "device-a", m, c, fixtureTime)
	if _, e := f.db.Exec(`DELETE FROM fi_rows WHERE ordinal=3`); e != nil {
		t.Fatal(e)
	}
	assertError(t, f, ErrStorage, func(tx Transaction) (PageResult, error) {
		return f.ledger.Page(context.Background(), tx, "device-a", PageRequest{Limit: 10}, fixtureTime.Add(time.Minute), f.key)
	})
}

func TestCursorKeyFormattingAllVerbsDoesNotExposeBytes(t *testing.T) {
	raw := [32]byte{}
	copy(raw[:], []byte("fixture-key-do-not-format-secret!"))
	key, e := NewCursorKey(raw)
	if e != nil {
		t.Fatal(e)
	}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%b", "%o", "%O", "%c", "%U", "%e", "%E", "%f", "%F", "%g", "%G", "%t", "%p", "%T", "%w"}
	signatures := []string{string(raw[:]), fmt.Sprintf("%v", raw), fmt.Sprintf("%x", raw), fmt.Sprintf("%q", raw)}
	for _, format := range verbs {
		for _, value := range []any{key, &key, []CursorKey{key}, map[string]CursorKey{"fixture": key}} {
			out := fmt.Sprintf(format, value)
			for _, secret := range signatures {
				if strings.Contains(out, secret) {
					t.Fatalf("key exposed using %s", format)
				}
			}
		}
	}
	if _, e = NewCursorKey([32]byte{}); !errors.Is(e, ErrInvalid) {
		t.Fatal("zero key accepted")
	}
	f := newFixture(t, DefaultLimits())
	assertError(t, f, ErrInvalid, func(tx Transaction) (PageResult, error) {
		return f.ledger.Page(context.Background(), tx, "device-a", PageRequest{Limit: 10}, fixtureTime, CursorKey{})
	})
}

func TestTrustedClockReversalCannotBackdateCompletion(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	m, chunks := fixtureInventory(t, 1, 200)
	commit(t, f, func(tx Transaction) (BeginReceipt, error) {
		return f.ledger.Begin(context.Background(), tx, "device-a", m, fixtureTime)
	})
	commit(t, f, func(tx Transaction) (ChunkReceipt, error) {
		return f.ledger.Append(context.Background(), tx, "device-a", chunks[0], fixtureTime.Add(4*time.Minute))
	})
	assertError(t, f, ErrExpired, func(tx Transaction) (ChunkReceipt, error) {
		return f.ledger.Append(context.Background(), tx, "device-a", chunks[1], fixtureTime.Add(3*time.Minute))
	})
	commit(t, f, func(tx Transaction) (ChunkReceipt, error) {
		return f.ledger.Append(context.Background(), tx, "device-a", chunks[1], fixtureTime.Add(5*time.Minute))
	})
	assertError(t, f, ErrExpired, func(tx Transaction) (Completion, error) {
		return f.ledger.Promote(context.Background(), tx, "device-a", m.GenerationID, fixtureTime.Add(4*time.Minute))
	})
	result := commit(t, f, func(tx Transaction) (Completion, error) {
		return f.ledger.Promote(context.Background(), tx, "device-a", m.GenerationID, fixtureTime.Add(6*time.Minute))
	})
	if !result.CompletedAt.Equal(fixtureTime.Add(6 * time.Minute)) {
		t.Fatal("completion timestamp changed")
	}
}

func TestCompetingHandlesPromoteAndCleanup(t *testing.T) {
	f := newFixture(t, DefaultLimits())
	l, _ := New(DefaultLimits())
	other := &fixture{openFixtureDB(t, f.path), l, f.path, f.key}
	old, oldChunks := fixtureInventory(t, 1, 600)
	complete(t, f, "device-a", old, oldChunks, fixtureTime)
	m, chunks := fixtureInventory(t, 2, 40)
	stage(t, f, "device-a", m, chunks, fixtureTime.Add(time.Minute))
	start := make(chan struct{})
	receipts := make(chan Completion, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, h := range []*fixture{f, other} {
		wg.Add(1)
		go func(h *fixture) {
			defer wg.Done()
			<-start
			out, e := CommitResult(context.Background(), h.run(true), func(tx Transaction) (Completion, error) {
				return h.ledger.Promote(context.Background(), tx, "device-a", m.GenerationID, fixtureTime.Add(2*time.Minute))
			})
			receipts <- out
			errs <- e
		}(h)
	}
	close(start)
	wg.Wait()
	close(receipts)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var first *Completion
	for x := range receipts {
		if first == nil {
			copy := x
			first = &copy
		} else if !reflect.DeepEqual(*first, x) {
			t.Fatal("concurrent idempotent promotion changed completion")
		}
	}
	start = make(chan struct{})
	deleted := make(chan CleanupResult, 2)
	errs = make(chan error, 2)
	for _, h := range []*fixture{f, other} {
		wg.Add(1)
		go func(h *fixture) {
			defer wg.Done()
			<-start
			out, e := CommitResult(context.Background(), h.run(true), func(tx Transaction) (CleanupResult, error) {
				return h.ledger.Cleanup(context.Background(), tx, "device-a", old.GenerationID, fixtureTime.Add(18*time.Minute))
			})
			deleted <- out
			errs <- e
		}(h)
	}
	close(start)
	wg.Wait()
	close(deleted)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	total := 0
	for x := range deleted {
		total += x.RowsDeleted
		if x.Done || x.RowsDeleted > MaxCleanupRows {
			t.Fatal("concurrent cleanup exceeded budget")
		}
	}
	if total != 2*MaxCleanupRows {
		t.Fatal("concurrent cleanup did not serialize progress")
	}
	assertAccounting(t, f)
	p := page(t, f, "device-a", PageRequest{Limit: 100}, fixtureTime.Add(18*time.Minute))
	if p.Manifest.GenerationID != m.GenerationID || len(p.Items) != 40 {
		t.Fatal("cleanup race changed current")
	}
}
