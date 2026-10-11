// Package windowsfullprocessesledger stores only independently consented Windows
// caller-visible process generations. Every operation requires its caller's live authority
// BEGIN IMMEDIATE transaction; this package cannot open or commit a database.
package windowsfullprocessesledger

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/windowsfullprocesses"
	"time"
)

var ErrStorage = errors.New("windows_full_processes_storage")
var ErrNotFound = errors.New("windows_full_processes_not_found")

const (
	MaxGlobalBytes       int64 = 128 << 20
	MaxDeviceBytes       int64 = 48 << 20
	MaxGlobalRows        int64 = 200000
	MaxGlobalChunks      int64 = 4096
	MaxDeviceGenerations       = 3
	MaxGlobalGenerations       = 75
	StagingTTL                 = 15 * time.Minute
)

type Transaction interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

var schema = []inventoryledger.SchemaObject{
	{Type: "table", Name: "wfp_meta", SQL: `CREATE TABLE wfp_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=1),cursor_key BLOB NOT NULL CHECK(length(cursor_key)=32),last_time TEXT NOT NULL) STRICT`},
	{Type: "table", Name: "wfp_authority", SQL: `CREATE TABLE wfp_authority(device TEXT PRIMARY KEY NOT NULL,invitation TEXT NOT NULL UNIQUE REFERENCES enrollment_credentials(invitation_id),certificate TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384)) STRICT`},
	{Type: "table", Name: "wfp_generations", SQL: `CREATE TABLE wfp_generations(device TEXT NOT NULL,generation TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('staging','current','garbage')),manifest BLOB NOT NULL CHECK(length(manifest)>0 AND length(manifest)<=4096),manifest_hash TEXT NOT NULL,started_at TEXT NOT NULL,completed_at TEXT NOT NULL,next_chunk INTEGER NOT NULL CHECK(next_chunk>=0 AND next_chunk<=512),next_row INTEGER NOT NULL CHECK(next_row>=0 AND next_row<=32768),last_pid INTEGER NOT NULL CHECK(last_pid>=0 AND last_pid<=4294967295),reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0),stored_bytes INTEGER NOT NULL CHECK(stored_bytes>=0),declared_rows INTEGER NOT NULL CHECK(declared_rows>=0 AND declared_rows<=32768),declared_chunks INTEGER NOT NULL CHECK(declared_chunks>=1 AND declared_chunks<=512),PRIMARY KEY(device,generation)) STRICT`},
	{Type: "table", Name: "wfp_chunks", SQL: `CREATE TABLE wfp_chunks(device TEXT NOT NULL,generation TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<512),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=65536),receipt BLOB NOT NULL CHECK(length(receipt)>0 AND length(receipt)<=2048),PRIMARY KEY(device,generation,ordinal)) STRICT`},
	{Type: "table", Name: "wfp_rows", SQL: `CREATE TABLE wfp_rows(device TEXT NOT NULL,generation TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<32768),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384),pid INTEGER NOT NULL CHECK(pid>=0 AND pid<=4294967295),parent_pid INTEGER NOT NULL CHECK(parent_pid>=0 AND parent_pid<=4294967295),name TEXT CHECK(name IS NULL OR length(CAST(name AS BLOB))<=2048),threads INTEGER NOT NULL CHECK(threads>=0 AND threads<=4294967295),search TEXT NOT NULL CHECK(length(CAST(search AS BLOB))<=8192),PRIMARY KEY(device,generation,ordinal),UNIQUE(device,generation,pid)) STRICT`},
	{Type: "index", Name: "wfp_rows_pid", SQL: `CREATE INDEX wfp_rows_pid ON wfp_rows(device,generation,pid)`},
	{Type: "index", Name: "wfp_rows_name", SQL: `CREATE INDEX wfp_rows_name ON wfp_rows(device,generation,name,pid)`},
	{Type: "index", Name: "wfp_rows_parent", SQL: `CREATE INDEX wfp_rows_parent ON wfp_rows(device,generation,parent_pid,pid)`},
	{Type: "index", Name: "wfp_rows_threads", SQL: `CREATE INDEX wfp_rows_threads ON wfp_rows(device,generation,threads,pid)`},
}

func SchemaObjects() []inventoryledger.SchemaObject {
	return append([]inventoryledger.SchemaObject(nil), schema...)
}
func Initialize(ctx context.Context, tx Transaction) error {
	for _, o := range schema {
		if _, e := tx.ExecContext(ctx, o.SQL); e != nil {
			return ErrStorage
		}
	}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return ErrStorage
	}
	if _, e := tx.ExecContext(ctx, `INSERT INTO wfp_meta VALUES(1,1,?,'')`, key); e != nil {
		return ErrStorage
	}
	return nil
}

// Record keeps independent consent/capture floors even when every generation is
// reclaimed. Scope and failure receipts retain original retry bytes and times.
type Record struct {
	IngressOrigin  string                        `json:"ingressOrigin"`
	Consent        windowsfullprocesses.Consent  `json:"consent"`
	ScopeRaw       []byte                        `json:"scopeRaw"`
	ScopeReceipt   windowsfullprocesses.Receipt  `json:"scopeReceipt"`
	Floor          uint64                        `json:"floor"`
	Current        string                        `json:"current"`
	Pending        string                        `json:"pending"`
	Latest         *windowsfullprocesses.Attempt `json:"latest"`
	FailureRaw     []byte                        `json:"failureRaw"`
	FailureReceipt *windowsfullprocesses.Receipt `json:"failureReceipt"`
	LastAt         time.Time                     `json:"lastAt"`
}

func LoadRecord(ctx context.Context, tx Transaction, device string) (Record, error) {
	var raw []byte
	if e := tx.QueryRowContext(ctx, `SELECT body FROM wfp_authority WHERE device=?`, device).Scan(&raw); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return Record{}, ErrNotFound
		}
		return Record{}, ErrStorage
	}
	var r Record
	if len(raw) > 16384 || json.Unmarshal(raw, &r) != nil {
		return Record{}, ErrStorage
	}
	canonical, _ := json.Marshal(r)
	if string(canonical) != string(raw) || windowsfullprocesses.ValidateConsent(r.Consent) != nil || r.Floor > windowsfullprocesses.MaxSequence || r.LastAt.IsZero() {
		return Record{}, ErrStorage
	}
	return r, nil
}
func SaveRecord(ctx context.Context, tx Transaction, device, invitation, cert string, r Record) error {
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > 16384 {
		return ErrStorage
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO wfp_authority VALUES(?,?,?,?) ON CONFLICT(device) DO UPDATE SET body=excluded.body`, device, invitation, cert, raw); e != nil {
		return ErrStorage
	}
	return nil
}
func Clock(ctx context.Context, tx Transaction, now time.Time) error {
	var last string
	if tx.QueryRowContext(ctx, `SELECT last_time FROM wfp_meta WHERE id=1`).Scan(&last) != nil {
		return ErrStorage
	}
	if last != "" {
		at, e := time.Parse(time.RFC3339Nano, last)
		if e != nil || now.Before(at) {
			return windowsfullprocesses.ErrInvalid
		}
	}
	if _, e := tx.ExecContext(ctx, `UPDATE wfp_meta SET last_time=? WHERE id=1`, now.UTC().Format(time.RFC3339Nano)); e != nil {
		return ErrStorage
	}
	return nil
}
func Budgets(ctx context.Context, tx Transaction, extraBytes int64) error {
	var bytes, rows, chunks, gens int64
	if tx.QueryRowContext(ctx, `SELECT coalesce(sum(reserved_bytes),0),coalesce(sum(declared_rows),0),coalesce(sum(declared_chunks),0),count(*) FROM wfp_generations`).Scan(&bytes, &rows, &chunks, &gens) != nil {
		return ErrStorage
	}
	if bytes+extraBytes > MaxGlobalBytes || rows > MaxGlobalRows || chunks > MaxGlobalChunks || gens > MaxGlobalGenerations {
		return windowsfullprocesses.ErrBudget
	}
	rr, e := tx.QueryContext(ctx, `SELECT sum(reserved_bytes),count(*) FROM wfp_generations GROUP BY device`)
	if e != nil {
		return ErrStorage
	}
	defer rr.Close()
	for rr.Next() {
		if rr.Scan(&bytes, &gens) != nil {
			return ErrStorage
		}
		if bytes > MaxDeviceBytes || gens > MaxDeviceGenerations {
			return windowsfullprocesses.ErrBudget
		}
	}
	if rr.Err() != nil {
		return ErrStorage
	}
	return nil
}

// Reserve rejects the proposed full generation before any staging/row write.
func Reserve(ctx context.Context, tx Transaction, device string, bytes int64, rows, chunks int, extra int64) error {
	var heldBytes, heldRows, heldChunks, generations int64
	if tx.QueryRowContext(ctx, `SELECT coalesce(sum(reserved_bytes),0),coalesce(sum(declared_rows),0),coalesce(sum(declared_chunks),0),count(*) FROM wfp_generations`).Scan(&heldBytes, &heldRows, &heldChunks, &generations) != nil {
		return ErrStorage
	}
	if heldBytes+bytes+extra > MaxGlobalBytes || heldRows+int64(rows) > MaxGlobalRows || heldChunks+int64(chunks) > MaxGlobalChunks || generations+1 > MaxGlobalGenerations {
		return windowsfullprocesses.ErrBudget
	}
	if tx.QueryRowContext(ctx, `SELECT coalesce(sum(reserved_bytes),0),count(*) FROM wfp_generations WHERE device=?`, device).Scan(&heldBytes, &generations) != nil {
		return ErrStorage
	}
	if heldBytes+bytes > MaxDeviceBytes || generations+1 > MaxDeviceGenerations {
		return windowsfullprocesses.ErrBudget
	}
	return nil
}
