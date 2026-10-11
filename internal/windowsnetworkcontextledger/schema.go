// Package windowsnetworkcontextledger stores only independently consented Windows
// caller-visible route and interface counter generations. Every operation requires its caller's live authority
// BEGIN IMMEDIATE transaction; this package cannot open or commit a database.
package windowsnetworkcontextledger

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/windowsnetworkcontext"
	"time"
)

var ErrStorage = errors.New("windows_network_context_storage")
var ErrNotFound = errors.New("windows_network_context_not_found")

const (
	MaxGlobalBytes       int64 = 128 << 20
	MaxDeviceBytes       int64 = 12 << 20
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
	{Type: "table", Name: "wnc_meta", SQL: `CREATE TABLE wnc_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=1),cursor_key BLOB NOT NULL CHECK(length(cursor_key)=32),last_time TEXT NOT NULL) STRICT`},
	{Type: "table", Name: "wnc_authority", SQL: `CREATE TABLE wnc_authority(device TEXT PRIMARY KEY NOT NULL,invitation TEXT NOT NULL UNIQUE REFERENCES enrollment_credentials(invitation_id),certificate TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384)) STRICT`},
	{Type: "table", Name: "wnc_generations", SQL: `CREATE TABLE wnc_generations(device TEXT NOT NULL,generation TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('staging','current','garbage')),manifest BLOB NOT NULL CHECK(length(manifest)>0 AND length(manifest)<=4096),manifest_hash TEXT NOT NULL,started_at TEXT NOT NULL,completed_at TEXT NOT NULL,next_chunk INTEGER NOT NULL CHECK(next_chunk>=0 AND next_chunk<=64),next_row INTEGER NOT NULL CHECK(next_row>=0 AND next_row<=4352),last_id INTEGER NOT NULL CHECK(last_id>=0 AND last_id<=4294967295),reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0),stored_bytes INTEGER NOT NULL CHECK(stored_bytes>=0),declared_rows INTEGER NOT NULL CHECK(declared_rows>=0 AND declared_rows<=4352),declared_chunks INTEGER NOT NULL CHECK(declared_chunks>=1 AND declared_chunks<=64),PRIMARY KEY(device,generation)) STRICT`},
	{Type: "table", Name: "wnc_chunks", SQL: `CREATE TABLE wnc_chunks(device TEXT NOT NULL,generation TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<64),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=65536),receipt BLOB NOT NULL CHECK(length(receipt)>0 AND length(receipt)<=2048),PRIMARY KEY(device,generation,ordinal)) STRICT`},
	{Type: "table", Name: "wnc_rows", SQL: `CREATE TABLE wnc_rows(device TEXT NOT NULL,generation TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<4352),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384),id INTEGER NOT NULL CHECK(id>=1 AND id<=4352),interface_index INTEGER NOT NULL CHECK(interface_index>=1 AND interface_index<=4294967295),kind TEXT NOT NULL CHECK(kind IN ('route','interface')),search TEXT NOT NULL CHECK(length(CAST(search AS BLOB))<=8192),PRIMARY KEY(device,generation,ordinal),UNIQUE(device,generation,id)) STRICT`},
	{Type: "index", Name: "wnc_rows_id", SQL: `CREATE INDEX wnc_rows_id ON wnc_rows(device,generation,id)`},
	{Type: "index", Name: "wnc_rows_kind", SQL: `CREATE INDEX wnc_rows_kind ON wnc_rows(device,generation,kind,id)`},
	{Type: "index", Name: "wnc_rows_interface", SQL: `CREATE INDEX wnc_rows_interface ON wnc_rows(device,generation,interface_index,id)`},
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
	if _, e := tx.ExecContext(ctx, `INSERT INTO wnc_meta VALUES(1,1,?,'')`, key); e != nil {
		return ErrStorage
	}
	return nil
}

// Record keeps independent consent/capture floors even when every generation is
// reclaimed. Scope and failure receipts retain original retry bytes and times.
type Record struct {
	IngressOrigin  string                         `json:"ingressOrigin"`
	Consent        windowsnetworkcontext.Consent  `json:"consent"`
	ScopeRaw       []byte                         `json:"scopeRaw"`
	ScopeReceipt   windowsnetworkcontext.Receipt  `json:"scopeReceipt"`
	Floor          uint64                         `json:"floor"`
	Current        string                         `json:"current"`
	Pending        string                         `json:"pending"`
	Latest         *windowsnetworkcontext.Attempt `json:"latest"`
	FailureRaw     []byte                         `json:"failureRaw"`
	FailureReceipt *windowsnetworkcontext.Receipt `json:"failureReceipt"`
	LastAt         time.Time                      `json:"lastAt"`
}

func LoadRecord(ctx context.Context, tx Transaction, device string) (Record, error) {
	var raw []byte
	if e := tx.QueryRowContext(ctx, `SELECT body FROM wnc_authority WHERE device=?`, device).Scan(&raw); e != nil {
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
	if string(canonical) != string(raw) || windowsnetworkcontext.ValidateConsent(r.Consent) != nil || r.Floor > windowsnetworkcontext.MaxSequence || r.LastAt.IsZero() {
		return Record{}, ErrStorage
	}
	return r, nil
}
func SaveRecord(ctx context.Context, tx Transaction, device, invitation, cert string, r Record) error {
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > 16384 {
		return ErrStorage
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO wnc_authority VALUES(?,?,?,?) ON CONFLICT(device) DO UPDATE SET body=excluded.body`, device, invitation, cert, raw); e != nil {
		return ErrStorage
	}
	return nil
}
func Clock(ctx context.Context, tx Transaction, now time.Time) error {
	var last string
	if tx.QueryRowContext(ctx, `SELECT last_time FROM wnc_meta WHERE id=1`).Scan(&last) != nil {
		return ErrStorage
	}
	if last != "" {
		at, e := time.Parse(time.RFC3339Nano, last)
		if e != nil || now.Before(at) {
			return windowsnetworkcontext.ErrInvalid
		}
	}
	if _, e := tx.ExecContext(ctx, `UPDATE wnc_meta SET last_time=? WHERE id=1`, now.UTC().Format(time.RFC3339Nano)); e != nil {
		return ErrStorage
	}
	return nil
}
func Budgets(ctx context.Context, tx Transaction, extraBytes int64) error {
	var bytes, rows, chunks, gens int64
	if tx.QueryRowContext(ctx, `SELECT coalesce(sum(reserved_bytes),0),coalesce(sum(declared_rows),0),coalesce(sum(declared_chunks),0),count(*) FROM wnc_generations`).Scan(&bytes, &rows, &chunks, &gens) != nil {
		return ErrStorage
	}
	if bytes+extraBytes > MaxGlobalBytes || rows > MaxGlobalRows || chunks > MaxGlobalChunks || gens > MaxGlobalGenerations {
		return windowsnetworkcontext.ErrBudget
	}
	rr, e := tx.QueryContext(ctx, `SELECT sum(reserved_bytes),count(*) FROM wnc_generations GROUP BY device`)
	if e != nil {
		return ErrStorage
	}
	defer rr.Close()
	for rr.Next() {
		if rr.Scan(&bytes, &gens) != nil {
			return ErrStorage
		}
		if bytes > MaxDeviceBytes || gens > MaxDeviceGenerations {
			return windowsnetworkcontext.ErrBudget
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
	if tx.QueryRowContext(ctx, `SELECT coalesce(sum(reserved_bytes),0),coalesce(sum(declared_rows),0),coalesce(sum(declared_chunks),0),count(*) FROM wnc_generations`).Scan(&heldBytes, &heldRows, &heldChunks, &generations) != nil {
		return ErrStorage
	}
	if heldBytes+bytes+extra > MaxGlobalBytes || heldRows+int64(rows) > MaxGlobalRows || heldChunks+int64(chunks) > MaxGlobalChunks || generations+1 > MaxGlobalGenerations {
		return windowsnetworkcontext.ErrBudget
	}
	if tx.QueryRowContext(ctx, `SELECT coalesce(sum(reserved_bytes),0),count(*) FROM wnc_generations WHERE device=?`, device).Scan(&heldBytes, &generations) != nil {
		return ErrStorage
	}
	if heldBytes+bytes > MaxDeviceBytes || generations+1 > MaxDeviceGenerations {
		return windowsnetworkcontext.ErrBudget
	}
	return nil
}
