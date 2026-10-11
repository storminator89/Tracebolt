// Package windowsfullsoftwareledger stores only independently consented Windows
// machine software generations. Every operation requires its caller's live authority
// BEGIN IMMEDIATE transaction; this package cannot open or commit a database.
package windowsfullsoftwareledger

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/windowsfullsoftware"
	"time"
)

var ErrStorage = errors.New("windows_full_software_storage")
var ErrNotFound = errors.New("windows_full_software_not_found")

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
	{Type: "table", Name: "wfw_history", SQL: `CREATE TABLE wfw_history(device TEXT PRIMARY KEY NOT NULL,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=1048576)) STRICT`},
	{Type: "table", Name: "wfw_meta", SQL: `CREATE TABLE wfw_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=1),cursor_key BLOB NOT NULL CHECK(length(cursor_key)=32),last_time TEXT NOT NULL) STRICT`},
	{Type: "table", Name: "wfw_authority", SQL: `CREATE TABLE wfw_authority(device TEXT PRIMARY KEY NOT NULL,invitation TEXT NOT NULL UNIQUE REFERENCES enrollment_credentials(invitation_id),certificate TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384)) STRICT`},
	{Type: "table", Name: "wfw_generations", SQL: `CREATE TABLE wfw_generations(device TEXT NOT NULL,generation TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('staging','current','garbage')),manifest BLOB NOT NULL CHECK(length(manifest)>0 AND length(manifest)<=4096),manifest_hash TEXT NOT NULL,started_at TEXT NOT NULL,completed_at TEXT NOT NULL,next_chunk INTEGER NOT NULL CHECK(next_chunk>=0 AND next_chunk<=512),next_row INTEGER NOT NULL CHECK(next_row>=0 AND next_row<=32768),last_registration TEXT NOT NULL,reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0),stored_bytes INTEGER NOT NULL CHECK(stored_bytes>=0),declared_rows INTEGER NOT NULL CHECK(declared_rows>=0 AND declared_rows<=32768),declared_chunks INTEGER NOT NULL CHECK(declared_chunks>=1 AND declared_chunks<=512),PRIMARY KEY(device,generation)) STRICT`},
	{Type: "table", Name: "wfw_chunks", SQL: `CREATE TABLE wfw_chunks(device TEXT NOT NULL,generation TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<512),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=65536),receipt BLOB NOT NULL CHECK(length(receipt)>0 AND length(receipt)<=2048),PRIMARY KEY(device,generation,ordinal)) STRICT`},
	{Type: "table", Name: "wfw_rows", SQL: `CREATE TABLE wfw_rows(device TEXT NOT NULL,generation TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<32768),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384),registration_id TEXT NOT NULL CHECK(length(registration_id)=64),registry_view TEXT NOT NULL CHECK(registry_view IN ('32','64')),name TEXT CHECK(name IS NULL OR length(CAST(name AS BLOB))<=2048),version TEXT CHECK(version IS NULL OR length(CAST(version AS BLOB))<=2048),publisher TEXT CHECK(publisher IS NULL OR length(CAST(publisher AS BLOB))<=2048),search TEXT NOT NULL CHECK(length(CAST(search AS BLOB))<=8192),PRIMARY KEY(device,generation,ordinal),UNIQUE(device,generation,registration_id)) STRICT`},
	{Type: "index", Name: "wfw_rows_name", SQL: `CREATE INDEX wfw_rows_name ON wfw_rows(device,generation,name,registration_id)`},
	{Type: "index", Name: "wfw_rows_version", SQL: `CREATE INDEX wfw_rows_version ON wfw_rows(device,generation,version,registration_id)`},
	{Type: "index", Name: "wfw_rows_publisher", SQL: `CREATE INDEX wfw_rows_publisher ON wfw_rows(device,generation,publisher,registration_id)`},
	{Type: "index", Name: "wfw_rows_view", SQL: `CREATE INDEX wfw_rows_view ON wfw_rows(device,generation,registry_view,registration_id)`},
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
	if _, e := tx.ExecContext(ctx, `INSERT INTO wfw_meta VALUES(1,1,?,'')`, key); e != nil {
		return ErrStorage
	}
	return nil
}

// Record keeps independent consent/capture floors even when every generation is
// reclaimed. Scope and failure receipts retain original retry bytes and times.
type Record struct {
	IngressOrigin  string                       `json:"ingressOrigin"`
	Consent        windowsfullsoftware.Consent  `json:"consent"`
	ScopeRaw       []byte                       `json:"scopeRaw"`
	ScopeReceipt   windowsfullsoftware.Receipt  `json:"scopeReceipt"`
	Floor          uint64                       `json:"floor"`
	Current        string                       `json:"current"`
	Pending        string                       `json:"pending"`
	Latest         *windowsfullsoftware.Attempt `json:"latest"`
	FailureRaw     []byte                       `json:"failureRaw"`
	FailureReceipt *windowsfullsoftware.Receipt `json:"failureReceipt"`
	LastAt         time.Time                    `json:"lastAt"`
}

func LoadRecord(ctx context.Context, tx Transaction, device string) (Record, error) {
	var raw []byte
	if e := tx.QueryRowContext(ctx, `SELECT body FROM wfw_authority WHERE device=?`, device).Scan(&raw); e != nil {
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
	if string(canonical) != string(raw) || windowsfullsoftware.ValidateConsent(r.Consent) != nil || r.Floor > windowsfullsoftware.MaxSequence || r.LastAt.IsZero() {
		return Record{}, ErrStorage
	}
	return r, nil
}
func SaveRecord(ctx context.Context, tx Transaction, device, invitation, cert string, r Record) error {
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > 16384 {
		return ErrStorage
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO wfw_authority VALUES(?,?,?,?) ON CONFLICT(device) DO UPDATE SET body=excluded.body`, device, invitation, cert, raw); e != nil {
		return ErrStorage
	}
	return nil
}
func Clock(ctx context.Context, tx Transaction, now time.Time) error {
	var last string
	if tx.QueryRowContext(ctx, `SELECT last_time FROM wfw_meta WHERE id=1`).Scan(&last) != nil {
		return ErrStorage
	}
	if last != "" {
		at, e := time.Parse(time.RFC3339Nano, last)
		if e != nil || now.Before(at) {
			return windowsfullsoftware.ErrInvalid
		}
	}
	if _, e := tx.ExecContext(ctx, `UPDATE wfw_meta SET last_time=? WHERE id=1`, now.UTC().Format(time.RFC3339Nano)); e != nil {
		return ErrStorage
	}
	return nil
}
func Budgets(ctx context.Context, tx Transaction, extraBytes int64) error {
	var bytes, rows, chunks, gens int64
	if tx.QueryRowContext(ctx, `SELECT coalesce(sum(reserved_bytes),0),coalesce(sum(declared_rows),0),coalesce(sum(declared_chunks),0),count(*) FROM wfw_generations`).Scan(&bytes, &rows, &chunks, &gens) != nil {
		return ErrStorage
	}
	var histories int64
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM wfw_history`).Scan(&histories) != nil {
		return ErrStorage
	}
	bytes += histories * windowsfullsoftware.MaxHistoryBytes
	if bytes+extraBytes > MaxGlobalBytes || rows > MaxGlobalRows || chunks > MaxGlobalChunks || gens > MaxGlobalGenerations {
		return windowsfullsoftware.ErrBudget
	}
	rr, e := tx.QueryContext(ctx, `SELECT coalesce(sum(g.reserved_bytes),0)+CASE WHEN h.device IS NULL THEN 0 ELSE 1048576 END,count(g.generation) FROM wfw_generations g LEFT JOIN wfw_history h ON h.device=g.device GROUP BY g.device`)
	if e != nil {
		return ErrStorage
	}
	defer rr.Close()
	for rr.Next() {
		if rr.Scan(&bytes, &gens) != nil {
			return ErrStorage
		}
		if bytes > MaxDeviceBytes || gens > MaxDeviceGenerations {
			return windowsfullsoftware.ErrBudget
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
	if tx.QueryRowContext(ctx, `SELECT coalesce(sum(reserved_bytes),0),coalesce(sum(declared_rows),0),coalesce(sum(declared_chunks),0),count(*) FROM wfw_generations`).Scan(&heldBytes, &heldRows, &heldChunks, &generations) != nil {
		return ErrStorage
	}
	var histories, own int64
	if tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(CASE WHEN device=? THEN 1 ELSE 0 END),0) FROM wfw_history`, device).Scan(&histories, &own) != nil {
		return ErrStorage
	}
	if heldBytes+bytes+extra+histories*windowsfullsoftware.MaxHistoryBytes > MaxGlobalBytes || heldRows+int64(rows) > MaxGlobalRows || heldChunks+int64(chunks) > MaxGlobalChunks || generations+1 > MaxGlobalGenerations {
		return windowsfullsoftware.ErrBudget
	}
	if tx.QueryRowContext(ctx, `SELECT coalesce(sum(reserved_bytes),0),count(*) FROM wfw_generations WHERE device=?`, device).Scan(&heldBytes, &generations) != nil {
		return ErrStorage
	}
	if heldBytes+bytes+own*windowsfullsoftware.MaxHistoryBytes > MaxDeviceBytes || generations+1 > MaxDeviceGenerations {
		return windowsfullsoftware.ErrBudget
	}
	return nil
}
