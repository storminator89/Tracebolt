package inventoryledger

import (
	"bytes"
	"context"
	"encoding/json"
	"time"
)

const (
	MaxGenerationBytes   int64 = 96 << 20
	MaxDeviceBytes       int64 = 288 << 20
	MaxGlobalBytes       int64 = 512 << 20
	MaxDeviceRows        int64 = 300000
	MaxGlobalRows        int64 = 2000000
	MaxDeviceChunks      int64 = 3072
	MaxGlobalChunks      int64 = 32768
	MaxDeviceGenerations int64 = 3
	MaxGlobalGenerations int64 = 4096
	MaxPageRows                = 100
	MaxScanRows                = 2048
	MaxCleanupRows             = 256
	MaxCleanupChunks           = 16
	MaxSearchBytes             = 128
	MaxCursorBytes             = 1024
	StagingTTL                 = 15 * time.Minute
	CursorTTL                  = 15 * time.Minute
	ObservationTTL             = 24 * time.Hour
)

// Limits may lower the fixed ceilings, never raise them. Exhaustion rejects a
// generation or chunk; it never exports a prefix as complete. Rows and chunks
// are reserved from the immutable manifest until its physical cleanup finishes.
// Bytes count exact retained manifest, checkpoint, chunk and page-row BLOB bytes.
// SQLite metadata, indexes, journal and freelist are NOT included in this count.
type Limits struct {
	GenerationBytes   int64 `json:"generationBytes"`
	DeviceBytes       int64 `json:"deviceBytes"`
	GlobalBytes       int64 `json:"globalBytes"`
	DeviceRows        int64 `json:"deviceRows"`
	GlobalRows        int64 `json:"globalRows"`
	DeviceChunks      int64 `json:"deviceChunks"`
	GlobalChunks      int64 `json:"globalChunks"`
	DeviceGenerations int64 `json:"deviceGenerations"`
	GlobalGenerations int64 `json:"globalGenerations"`
}

func DefaultLimits() Limits {
	return Limits{MaxGenerationBytes, MaxDeviceBytes, MaxGlobalBytes, MaxDeviceRows, MaxGlobalRows,
		MaxDeviceChunks, MaxGlobalChunks, MaxDeviceGenerations, MaxGlobalGenerations}
}
func (x Limits) valid() bool {
	d := DefaultLimits()
	values := [][2]int64{{x.GenerationBytes, d.GenerationBytes}, {x.DeviceBytes, d.DeviceBytes}, {x.GlobalBytes, d.GlobalBytes},
		{x.DeviceRows, d.DeviceRows}, {x.GlobalRows, d.GlobalRows}, {x.DeviceChunks, d.DeviceChunks}, {x.GlobalChunks, d.GlobalChunks},
		{x.DeviceGenerations, d.DeviceGenerations}, {x.GlobalGenerations, d.GlobalGenerations}}
	for _, p := range values {
		if p[0] < 1 || p[0] > p[1] {
			return false
		}
	}
	return true
}

type Ledger struct{ limits Limits }

func New(limits Limits) (*Ledger, error) {
	if !limits.valid() {
		return nil, ErrInvalid
	}
	return &Ledger{limits: limits}, nil
}

var schema = []string{
	`CREATE TABLE fi_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=1),limits BLOB NOT NULL) STRICT`,
	`CREATE TABLE fi_budget(scope TEXT PRIMARY KEY NOT NULL,held_rows INTEGER NOT NULL CHECK(held_rows>=0),held_chunks INTEGER NOT NULL CHECK(held_chunks>=0),stored_bytes INTEGER NOT NULL CHECK(stored_bytes>=0),generations INTEGER NOT NULL CHECK(generations>=0)) STRICT`,
	`CREATE TABLE fi_devices(device TEXT PRIMARY KEY NOT NULL,current_generation TEXT NOT NULL,staging_generation TEXT NOT NULL) STRICT`,
	`CREATE TABLE fi_generations(device TEXT NOT NULL,generation TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('staging','current','retired','garbage')),manifest BLOB NOT NULL CHECK(length(manifest)<=4096),checkpoint BLOB NOT NULL CHECK(length(checkpoint)<=2048),started_at TEXT NOT NULL,expires_at TEXT NOT NULL,completed_at TEXT NOT NULL,retired_at TEXT NOT NULL,next_chunk INTEGER NOT NULL CHECK(next_chunk>=0 AND next_chunk<=1024),next_row INTEGER NOT NULL CHECK(next_row>=0 AND next_row<=100000),wire_bytes INTEGER NOT NULL CHECK(wire_bytes>=0 AND wire_bytes<=50331648),row_bytes INTEGER NOT NULL CHECK(row_bytes>=0 AND row_bytes<=33554432),stored_bytes INTEGER NOT NULL CHECK(stored_bytes>=0),live_rows INTEGER NOT NULL CHECK(live_rows>=0),live_chunks INTEGER NOT NULL CHECK(live_chunks>=0),PRIMARY KEY(device,generation)) STRICT`,
	`CREATE INDEX fi_generation_state ON fi_generations(device,state,generation)`,
	`CREATE TABLE fi_chunks(device TEXT NOT NULL,generation TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<1024),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=65536),received_at TEXT NOT NULL,PRIMARY KEY(device,generation,ordinal)) STRICT`,
	`CREATE TABLE fi_rows(device TEXT NOT NULL,generation TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<100000),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=4096),PRIMARY KEY(device,generation,ordinal)) STRICT`,
}

// Initialize is a fresh-schema operation inside the caller's authority migration
// transaction. It neither migrates nor adopts an existing/legacy ledger. Runtime
// schema/version/profile allowlisting must be explicitly updated by the owner in
// a separately reviewed integration; this isolated package does not do that.
func (l *Ledger) Initialize(ctx context.Context, tx Transaction) error {
	if err := l.validCall(ctx, tx); err != nil {
		return err
	}
	for _, q := range schema {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return ErrStorage
		}
	}
	raw, _ := json.Marshal(l.limits)
	if _, err := tx.ExecContext(ctx, `INSERT INTO fi_meta VALUES(1,1,?)`, raw); err != nil {
		return ErrStorage
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO fi_budget VALUES('',0,0,0,0)`); err != nil {
		return ErrStorage
	}
	return nil
}
func (l *Ledger) validCall(ctx context.Context, tx Transaction) error {
	if l == nil || !l.limits.valid() || ctx == nil || tx == nil {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
func (l *Ledger) check(ctx context.Context, tx Transaction) error {
	if err := l.validCall(ctx, tx); err != nil {
		return err
	}
	var version int
	var raw []byte
	if tx.QueryRowContext(ctx, `SELECT version,limits FROM fi_meta WHERE id=1`).Scan(&version, &raw) != nil {
		return ErrStorage
	}
	expected, _ := json.Marshal(l.limits)
	if version != 1 || !bytes.Equal(raw, expected) {
		return ErrStorage
	}
	return nil
}
