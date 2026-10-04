package enrollmentstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/fullinventory"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/linuxpackages"
)

// This opt-in measurement generates typed synthetic package metadata only. It
// neither opens a host package source nor exercises a collector or transport.
// Its deliberately maximal device keys stress the isolated ledger's B-tree
// overhead beyond the authority store's narrower, validated device identifiers.
// Run with TRACEBOLT_INVENTORY_CAPACITY_TEST=1 and -run
// TestCompleteInventorySyntheticPhysicalCapacity -count=1 -v.
func TestCompleteInventorySyntheticPhysicalCapacity(t *testing.T) {
	if os.Getenv("TRACEBOLT_INVENTORY_CAPACITY_TEST") != "1" {
		t.Skip("set TRACEBOLT_INVENTORY_CAPACITY_TEST=1 for the full-capacity synthetic measurement")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "synthetic-inventory.sqlite")
	u := url.URL{Scheme: "file", Path: path}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA page_size=4096", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA cache_spill=OFF", "PRAGMA max_page_count=131072", "PRAGMA wal_autocheckpoint=1000", "PRAGMA journal_size_limit=4194304"} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	limits := inventoryledger.DefaultLimits()
	limits.GenerationBytes, limits.DeviceBytes, limits.GlobalBytes = 48<<20, 96<<20, 128<<20
	ledger, err := inventoryledger.New(limits)
	if err != nil {
		t.Fatal(err)
	}
	var maxDB, maxWAL, maxSHM, maxPages int64
	sample := func() {
		t.Helper()
		var pages, pageSize int64
		if db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages) != nil || db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize) != nil || pageSize != 4096 {
			t.Fatal("invalid synthetic fixture page geometry")
		}
		maxPages = max(maxPages, pages)
		for _, file := range []struct {
			suffix string
			max    *int64
			cap    int64
		}{{"", &maxDB, 512 << 20}, {"-wal", &maxWAL, 640 << 20}, {"-shm", &maxSHM, 2 << 20}} {
			info, e := os.Stat(path + file.suffix)
			if e != nil {
				t.Fatal(e)
			}
			*file.max = max(*file.max, info.Size())
			if info.Size() > file.cap {
				t.Fatalf("synthetic file %q exceeds physical cap: %d > %d", file.suffix, info.Size(), file.cap)
			}
		}
	}
	run := func(fn func(inventoryledger.Transaction) error) error {
		conn, e := db.Conn(ctx)
		if e != nil {
			return e
		}
		defer conn.Close()
		if _, e = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
			return e
		}
		defer conn.ExecContext(ctx, "ROLLBACK")
		if e = fn(conn); e != nil {
			return e
		}
		var pages, pageSize, pageCap, spill int64
		if conn.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages) != nil || conn.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize) != nil || conn.QueryRowContext(ctx, "PRAGMA max_page_count").Scan(&pageCap) != nil || conn.QueryRowContext(ctx, "PRAGMA cache_spill").Scan(&spill) != nil || pages > 131072 || pageSize != 4096 || pageCap != 131072 || spill != 0 {
			return errors.New("synthetic fixture physical admission geometry failed")
		}
		var walBytes int64
		info, e := os.Stat(path + "-wal")
		if e == nil {
			walBytes = info.Size()
		} else if !os.IsNotExist(e) {
			return e
		}
		// The pinned SQLite implementation pads FULL-synchronous commits to a
		// sector boundary; 72 KiB covers its clamped 64 KiB sector plus a frame.
		if walBytes+32+pages*(4096+24)+(72<<10) > 640<<20 {
			return errors.New("synthetic fixture WAL reservation exhausted")
		}
		_, e = conn.ExecContext(ctx, "COMMIT")
		return e
	}
	if err = run(func(tx inventoryledger.Transaction) error { return ledger.Initialize(ctx, tx) }); err != nil {
		t.Fatal(err)
	}
	sample()
	started := time.Now()
	now := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	rows := make([]linuxpackages.PackageRow, 100000)
	for i := range rows {
		name := fmt.Sprintf("capacity-%06d", i)
		rows[i] = linuxpackages.PackageRow{Name: name, Version: "1.2.3-1", Architecture: "amd64", SourcePackage: name, SourceVersion: "1.2.3-1", SourceMapping: "binary-default", InstallState: "installed"}
	}
	completed, quotaReached := 0, false
	var rejectedDevice, rejectedGeneration string
	for generation := 1; generation <= 6 && !quotaReached; generation++ {
		device := strings.Repeat("d", 119) + fmt.Sprintf("%09d", generation)
		m, chunks, e := fullinventory.Build(ctx, fullinventory.SourceInventory{GenerationID: fmt.Sprintf("sample_%032x", generation), CollectedAt: now, Rows: rows, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}}, nil)
		if e != nil {
			t.Fatal(e)
		}
		if e = run(func(tx inventoryledger.Transaction) error {
			_, e := ledger.Begin(ctx, tx, device, m, now)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		for _, chunk := range chunks {
			var before int64
			if e = db.QueryRowContext(ctx, "SELECT stored_bytes FROM fi_budget WHERE scope=''").Scan(&before); e != nil {
				t.Fatal(e)
			}
			e = run(func(tx inventoryledger.Transaction) error {
				_, e := ledger.Append(ctx, tx, device, chunk, now.Add(time.Second))
				return e
			})
			if errors.Is(e, inventoryledger.ErrQuota) {
				var after int64
				if e = db.QueryRowContext(ctx, "SELECT stored_bytes FROM fi_budget WHERE scope=''").Scan(&after); e != nil || after != before {
					t.Fatalf("quota failure changed exact budget: before=%d after=%d error=%v", before, after, e)
				}
				quotaReached, rejectedDevice, rejectedGeneration = true, device, m.GenerationID
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			sample()
		}
		if !quotaReached {
			if e = run(func(tx inventoryledger.Transaction) error {
				_, e := ledger.Promote(ctx, tx, device, m.GenerationID, now.Add(2*time.Second))
				return e
			}); e != nil {
				t.Fatal(e)
			}
			completed++
			t.Logf("completed synthetic generation %d: rows=%d chunks=%d canonical_rows=%d", generation, m.ObservedCount, m.ChunkCount, m.CanonicalRowBytes)
		}
	}
	if !quotaReached || completed < 2 {
		t.Fatalf("expected full-capacity quota rejection after multiple complete generations: completed=%d rejected=%v", completed, quotaReached)
	}
	if err = run(func(tx inventoryledger.Transaction) error {
		_, e := ledger.Promote(ctx, tx, rejectedDevice, rejectedGeneration, now.Add(2*time.Second))
		return e
	}); !errors.Is(err, inventoryledger.ErrIncomplete) {
		t.Fatalf("quota-rejected stage unexpectedly promotable: %v", err)
	}
	var logical, storedRows, storedChunks, current int64
	for _, q := range []struct {
		query string
		out   *int64
	}{{"SELECT stored_bytes FROM fi_budget WHERE scope=''", &logical}, {"SELECT count(*) FROM fi_rows", &storedRows}, {"SELECT count(*) FROM fi_chunks", &storedChunks}, {"SELECT count(*) FROM fi_generations WHERE state='current'", &current}} {
		if err = db.QueryRowContext(ctx, q.query).Scan(q.out); err != nil {
			t.Fatal(err)
		}
	}
	if logical > limits.GlobalBytes || limits.GlobalBytes-logical >= 2*fullinventory.MaxChunkBytes+fullinventory.MaxCheckpointBytes || current != int64(completed) {
		t.Fatalf("unexpected capacity or complete pointers: logical=%d current=%d completed=%d", logical, current, completed)
	}
	if _, err = db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	sample()
	t.Logf("synthetic capacity: completed_generations=%d rows=%d chunks=%d logical_bytes=%d max_db_bytes=%d max_wal_bytes=%d max_shm_bytes=%d max_pages=%d elapsed=%s", completed, storedRows, storedChunks, logical, maxDB, maxWAL, maxSHM, maxPages, time.Since(started).Round(time.Millisecond))
}
