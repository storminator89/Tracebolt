package enrollmentstore

import (
	"context"
	"database/sql"
	"os"
)

const (
	CompleteInventoryDatabaseBytes int64 = 512 << 20
	CompleteInventoryWALBytes      int64 = 640 << 20
	completeInventoryPageSize      int64 = 4096
	completeInventoryPages         int64 = CompleteInventoryDatabaseBytes / completeInventoryPageSize
	// Pinned SQLite clamps sector size to65536 bytes and may repeat the last
	// commit frame past that boundary under FULL synchronization. Reserve72KiB.
	completeInventoryWALPadding int64 = 72 << 10
)

func databaseCap(profile string) int64 {
	if completeProfile(profile) {
		return CompleteInventoryDatabaseBytes
	}
	return maxDatabaseBytes
}
func sidecarCap(profile, suffix string) int64 {
	if !completeProfile(profile) {
		return maxDatabaseBytes
	}
	switch suffix {
	case "-wal":
		return CompleteInventoryWALBytes
	case "-shm":
		return 2 << 20
	case "-journal":
		return 0
	default:
		return CompleteInventoryDatabaseBytes
	}
}
func (s *Store) inventoryReadOnlyCapacity(ctx context.Context, c *sql.Conn) error {
	var size, pages int64
	if c.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size) != nil || size != completeInventoryPageSize || c.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages) != nil || pages < 1 || pages > completeInventoryPages {
		return ErrStorage
	}
	return nil
}
func (s *Store) configureInventoryConnection(ctx context.Context, c *sql.Conn) error {
	// These connection settings follow protected schema/ownership restoration.
	// Reapply to the actual transaction connection after any pool reconnect.
	for _, q := range []string{"PRAGMA cache_spill=OFF", "PRAGMA max_page_count=131072"} {
		if _, e := c.ExecContext(ctx, q); e != nil {
			return ErrStorage
		}
	}
	return s.inventoryConnectionCapacity(ctx, c)
}
func (s *Store) inventoryConnectionCapacity(ctx context.Context, c *sql.Conn) error {
	if s.inventoryReadOnlyCapacity(ctx, c) != nil {
		return ErrStorage
	}
	var spill, max, sync int64
	var mode string
	if c.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode) != nil || mode != "wal" {
		return ErrStorage
	}
	if c.QueryRowContext(ctx, "PRAGMA cache_spill").Scan(&spill) != nil || spill != 0 || c.QueryRowContext(ctx, "PRAGMA max_page_count").Scan(&max) != nil || max != completeInventoryPages || c.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&sync) != nil || sync != 2 {
		return ErrStorage
	}
	return nil
}
func (s *Store) inventoryCapacityBeforeCommit(ctx context.Context, c *sql.Conn) error {
	if s.inventoryConnectionCapacity(ctx, c) != nil {
		return ErrStorage
	}
	var pages int64
	if c.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages) != nil || pages > completeInventoryPages {
		return ErrStorage
	}
	var wal int64
	info, e := os.Lstat(s.path + "-wal")
	if e == nil {
		wal = info.Size()
	} else if !os.IsNotExist(e) {
		return ErrStorage
	}
	// BEGIN IMMEDIATE excludes competing writers. With cache_spill disabled,
	// COMMIT emits at most one frame per dirty database page, plus bounded sector
	// padding. Reserve for every current page rather than estimating dirty pages.
	// Automatic checkpointing is an optimization, never the hard cap mechanism.
	if wal < 0 || wal+32+pages*(completeInventoryPageSize+24)+completeInventoryWALPadding > CompleteInventoryWALBytes {
		return ErrStorage
	}
	return nil
}
