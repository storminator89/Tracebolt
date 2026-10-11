// Package windowsfullservicesledger stores only independently consented Windows
// service generations. Every operation requires its caller's live authority
// BEGIN IMMEDIATE transaction; this package cannot open or commit a database.
package windowsfullservicesledger

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/windowsfullservices"
	"time"
)

var ErrStorage = errors.New("windows_full_services_storage")
var ErrNotFound = errors.New("windows_full_services_not_found")

const (
	MaxGlobalBytes       int64 = 128 << 20
	MaxDeviceBytes       int64 = 24 << 20
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
	{Type: "table", Name: "wfs_meta", SQL: `CREATE TABLE wfs_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=1),cursor_key BLOB NOT NULL CHECK(length(cursor_key)=32),last_time TEXT NOT NULL) STRICT`},
	{Type: "table", Name: "wfs_authority", SQL: `CREATE TABLE wfs_authority(device TEXT PRIMARY KEY NOT NULL,invitation TEXT NOT NULL UNIQUE REFERENCES enrollment_credentials(invitation_id),certificate TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384)) STRICT`},
	{Type: "table", Name: "wfs_generations", SQL: `CREATE TABLE wfs_generations(device TEXT NOT NULL,generation TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('staging','current','garbage')),manifest BLOB NOT NULL CHECK(length(manifest)>0 AND length(manifest)<=4096),manifest_hash TEXT NOT NULL,started_at TEXT NOT NULL,completed_at TEXT NOT NULL,next_chunk INTEGER NOT NULL CHECK(next_chunk>=0 AND next_chunk<=256),next_row INTEGER NOT NULL CHECK(next_row>=0 AND next_row<=8192),last_name TEXT NOT NULL,reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0),stored_bytes INTEGER NOT NULL CHECK(stored_bytes>=0),declared_rows INTEGER NOT NULL CHECK(declared_rows>=0 AND declared_rows<=8192),declared_chunks INTEGER NOT NULL CHECK(declared_chunks>=1 AND declared_chunks<=256),PRIMARY KEY(device,generation)) STRICT`},
	{Type: "table", Name: "wfs_chunks", SQL: `CREATE TABLE wfs_chunks(device TEXT NOT NULL,generation TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<256),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=65536),receipt BLOB NOT NULL CHECK(length(receipt)>0 AND length(receipt)<=2048),PRIMARY KEY(device,generation,ordinal)) STRICT`},
	{Type: "table", Name: "wfs_rows", SQL: `CREATE TABLE wfs_rows(device TEXT NOT NULL,generation TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<8192),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384),name TEXT NOT NULL CHECK(length(CAST(name AS BLOB))>0 AND length(CAST(name AS BLOB))<=1024),identity TEXT NOT NULL CHECK(length(CAST(identity AS BLOB))>0 AND length(CAST(identity AS BLOB))<=1024),search TEXT NOT NULL CHECK(length(CAST(search AS BLOB))<=4096),pid INTEGER CHECK(pid IS NULL OR (pid>=0 AND pid<=4294967295)),state TEXT CHECK(state IS NULL OR length(state)<=16),PRIMARY KEY(device,generation,ordinal),UNIQUE(device,generation,identity)) STRICT`},
	{Type: "index", Name: "wfs_rows_name", SQL: `CREATE INDEX wfs_rows_name ON wfs_rows(device,generation,name)`},
	{Type: "index", Name: "wfs_rows_pid", SQL: `CREATE INDEX wfs_rows_pid ON wfs_rows(device,generation,pid,name)`},
	{Type: "index", Name: "wfs_rows_state", SQL: `CREATE INDEX wfs_rows_state ON wfs_rows(device,generation,state,name)`},
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
	if _, e := tx.ExecContext(ctx, `INSERT INTO wfs_meta VALUES(1,1,?,'')`, key); e != nil {
		return ErrStorage
	}
	return nil
}

// Record keeps independent consent/capture floors even when every generation is
// reclaimed. Scope and failure receipts retain original retry bytes and times.
type Record struct {
	IngressOrigin  string                       `json:"ingressOrigin"`
	Consent        windowsfullservices.Consent  `json:"consent"`
	ScopeRaw       []byte                       `json:"scopeRaw"`
	ScopeReceipt   windowsfullservices.Receipt  `json:"scopeReceipt"`
	Floor          uint64                       `json:"floor"`
	Current        string                       `json:"current"`
	Pending        string                       `json:"pending"`
	Latest         *windowsfullservices.Attempt `json:"latest"`
	FailureRaw     []byte                       `json:"failureRaw"`
	FailureReceipt *windowsfullservices.Receipt `json:"failureReceipt"`
	LastAt         time.Time                    `json:"lastAt"`
}

func LoadRecord(ctx context.Context, tx Transaction, device string) (Record, error) {
	var raw []byte
	if e := tx.QueryRowContext(ctx, `SELECT body FROM wfs_authority WHERE device=?`, device).Scan(&raw); e != nil {
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
	if string(canonical) != string(raw) || windowsfullservices.ValidateConsent(r.Consent) != nil || r.Floor > windowsfullservices.MaxSequence || r.LastAt.IsZero() {
		return Record{}, ErrStorage
	}
	return r, nil
}
func SaveRecord(ctx context.Context, tx Transaction, device, invitation, cert string, r Record) error {
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > 16384 {
		return ErrStorage
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO wfs_authority VALUES(?,?,?,?) ON CONFLICT(device) DO UPDATE SET body=excluded.body`, device, invitation, cert, raw); e != nil {
		return ErrStorage
	}
	return nil
}
func Clock(ctx context.Context, tx Transaction, now time.Time) error {
	var last string
	if tx.QueryRowContext(ctx, `SELECT last_time FROM wfs_meta WHERE id=1`).Scan(&last) != nil {
		return ErrStorage
	}
	if last != "" {
		at, e := time.Parse(time.RFC3339Nano, last)
		if e != nil || now.Before(at) {
			return windowsfullservices.ErrInvalid
		}
	}
	if _, e := tx.ExecContext(ctx, `UPDATE wfs_meta SET last_time=? WHERE id=1`, now.UTC().Format(time.RFC3339Nano)); e != nil {
		return ErrStorage
	}
	return nil
}
func Budgets(ctx context.Context, tx Transaction, extraBytes int64) error {
	var bytes, rows, chunks, gens int64
	if tx.QueryRowContext(ctx, `SELECT coalesce(sum(reserved_bytes),0),coalesce(sum(declared_rows),0),coalesce(sum(declared_chunks),0),count(*) FROM wfs_generations`).Scan(&bytes, &rows, &chunks, &gens) != nil {
		return ErrStorage
	}
	if bytes+extraBytes > MaxGlobalBytes || rows > MaxGlobalRows || chunks > MaxGlobalChunks || gens > MaxGlobalGenerations {
		return windowsfullservices.ErrBudget
	}
	rr, e := tx.QueryContext(ctx, `SELECT sum(reserved_bytes),count(*) FROM wfs_generations GROUP BY device`)
	if e != nil {
		return ErrStorage
	}
	defer rr.Close()
	for rr.Next() {
		if rr.Scan(&bytes, &gens) != nil {
			return ErrStorage
		}
		if bytes > MaxDeviceBytes || gens > MaxDeviceGenerations {
			return windowsfullservices.ErrBudget
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
	if tx.QueryRowContext(ctx, `SELECT coalesce(sum(reserved_bytes),0),coalesce(sum(declared_rows),0),coalesce(sum(declared_chunks),0),count(*) FROM wfs_generations`).Scan(&heldBytes, &heldRows, &heldChunks, &generations) != nil {
		return ErrStorage
	}
	if heldBytes+bytes+extra > MaxGlobalBytes || heldRows+int64(rows) > MaxGlobalRows || heldChunks+int64(chunks) > MaxGlobalChunks || generations+1 > MaxGlobalGenerations {
		return windowsfullservices.ErrBudget
	}
	if tx.QueryRowContext(ctx, `SELECT coalesce(sum(reserved_bytes),0),count(*) FROM wfs_generations WHERE device=?`, device).Scan(&heldBytes, &generations) != nil {
		return ErrStorage
	}
	if heldBytes+bytes > MaxDeviceBytes || generations+1 > MaxDeviceGenerations {
		return windowsfullservices.ErrBudget
	}
	return nil
}
