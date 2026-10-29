// Package customerapprovalstore is an isolated v3 transaction candidate. It
// cannot issue certificates, activate devices, or authorize observation. Its
// owner must provide protected, non-aliased storage and a durable used marker.
// A future enrollment implementation must make its own authoritative issuance
// state and this binding part of the SAME transaction; this standalone store
// is not an authorization source for v2 or any production endpoint.
package customerapprovalstore

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/customerapproval"
	"localrmm/internal/customerpending"
	"localrmm/internal/customerschema"
	"localrmm/internal/enrollmentcrypto"
)

const MaxRecords = 100
const maxTimestamp = int64(253402300499)
const metaSchema = `CREATE TABLE customer_approval_meta (id INTEGER PRIMARY KEY CHECK(id=1), manager_id TEXT NOT NULL, manager_digest TEXT NOT NULL, count INTEGER NOT NULL CHECK(count>=0 AND count<=100), last_at INTEGER NOT NULL CHECK(last_at>=0)) STRICT`
const recordSchema = `CREATE TABLE customer_approval_records (claim_id TEXT PRIMARY KEY NOT NULL, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384)) STRICT`

var ErrInvalid = errors.New("customer approval input invalid")
var ErrStorage = errors.New("customer approval storage unavailable or invalid")
var ErrConflict = errors.New("customer approval identity or operation already retained")
var ErrLimit = errors.New("customer approval capacity exhausted")

func schema() []customerschema.Object {
	return []customerschema.Object{customerschema.ObjectSQL("customer_approval_meta", metaSchema), customerschema.ObjectSQL("customer_approval_records", recordSchema), customerschema.AutoIndex("sqlite_autoindex_customer_approval_records_1", "customer_approval_records")}
}

// Actor is derived from an authenticated session, not an HTTP request body.
// Shared administration is recorded as shared without inventing a person.
type Actor struct {
	Mode string `json:"mode"`
	ID   string `json:"id"`
}

func (a Actor) valid() bool {
	return a.Mode == "shared" && a.ID == "" || a.Mode == "named" && enrollmentcrypto.ValidID(a.ID, "operator_")
}

// Record is retained public binding data, not evidence of current authority.
type Record struct {
	Version   string                     `json:"version"`
	Actor     Actor                      `json:"actor"`
	Candidate customerapproval.Candidate `json:"candidate"`
}

type Store struct {
	db                       *sql.DB
	managerID, managerDigest string
}

// Initialize is strictly for an empty fresh domain. It cannot detect deletion
// or full rollback of the database. A versioned external used marker and
// protected DB/sidecars must be provided by the eventual owner; never repair a
// missing or previously used domain with this function.
func Initialize(ctx context.Context, db *sql.DB, managerID, managerDigest string) error {
	if ctx == nil || db == nil || !enrollmentcrypto.ValidID(managerID, "manager_") || !enrollmentcrypto.ValidHash(managerDigest) {
		return ErrInvalid
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return ErrStorage
	}
	began, committed := false, false
	defer func() { closeTransaction(conn, began, committed) }()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return ErrStorage
	}
	began = true
	if customerschema.Empty(ctx, conn) != nil {
		return ErrStorage
	}
	for _, statement := range []string{metaSchema, recordSchema} {
		if _, err = conn.ExecContext(ctx, statement); err != nil {
			return ErrStorage
		}
	}
	if _, err = conn.ExecContext(ctx, `INSERT INTO customer_approval_meta VALUES (1,?,?,0,0)`, managerID, managerDigest); err != nil {
		return ErrStorage
	}
	if _, err = conn.ExecContext(ctx, `PRAGMA main.user_version=1`); err != nil || customerschema.Validate(ctx, conn, schema()) != nil {
		return ErrStorage
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return ErrStorage
	}
	committed = true
	return nil
}

// New does not initialize, repair, verify a path or establish exclusive owner.
func New(db *sql.DB, managerID, managerDigest string) (*Store, error) {
	if db == nil || !enrollmentcrypto.ValidID(managerID, "manager_") || !enrollmentcrypto.ValidHash(managerDigest) {
		return nil, ErrInvalid
	}
	return &Store{db, managerID, managerDigest}, nil
}
func discard(c *sql.Conn) { _ = c.Raw(func(any) error { return driver.ErrBadConn }); _ = c.Close() }
func finish(c *sql.Conn, committed bool) {
	defer func() {
		if p := recover(); p != nil {
			discard(c)
			panic(p)
		}
	}()
	if !committed {
		if _, err := c.ExecContext(context.Background(), `ROLLBACK`); err != nil {
			discard(c)
			return
		}
	}
	_ = c.Close()
}

// BEGIN may have reached SQLite even if the driver panics or returns an
// error. An unconfirmed BEGIN must never return its connection to the pool.
func closeTransaction(c *sql.Conn, began, committed bool) {
	if !began {
		discard(c)
		return
	}
	finish(c, committed)
}

func validRecord(r Record, managerID, managerDigest string) bool {
	return r.Version == "tracebolt.customer-approval-record.v1" && r.Actor.valid() && customerapproval.Valid(r.Candidate) && r.Candidate.ManagerDigest == managerDigest && r.Candidate.Pending.ManagerID == managerID
}

// load validates exact schema, count and all retained records including unique
// original claims, keys, operations and device IDs. It does not authenticate
// DB contents or detect a complete backup rollback.
func load(ctx context.Context, c *sql.Conn, managerID, managerDigest string) ([]Record, int64, error) {
	if customerschema.Validate(ctx, c, schema()) != nil {
		return nil, 0, ErrStorage
	}
	var entries, count int
	var id, digest string
	var last int64
	if c.QueryRowContext(ctx, `SELECT count(*) FROM customer_approval_meta`).Scan(&entries) != nil || entries != 1 {
		return nil, 0, ErrStorage
	}
	if c.QueryRowContext(ctx, `SELECT manager_id,manager_digest,count,last_at FROM customer_approval_meta WHERE id=1`).Scan(&id, &digest, &count, &last) != nil || id != managerID || digest != managerDigest || count < 0 || count > MaxRecords || last < 0 || last > maxTimestamp {
		return nil, 0, ErrStorage
	}
	rows, err := c.QueryContext(ctx, `SELECT claim_id,body FROM customer_approval_records ORDER BY claim_id LIMIT 101`)
	if err != nil {
		return nil, 0, ErrStorage
	}
	defer rows.Close()
	out := make([]Record, 0, count)
	claims := map[string]bool{}
	keys := map[string]bool{}
	devices := map[string]bool{}
	ops := map[string]bool{}
	for rows.Next() {
		var key string
		var raw []byte
		var r Record
		if rows.Scan(&key, &raw) != nil || len(raw) > 16384 || json.Unmarshal(raw, &r) != nil || !validRecord(r, managerID, managerDigest) || key != r.Candidate.Pending.ClaimID || r.Candidate.ConfirmedAt > last {
			return nil, 0, ErrStorage
		}
		canonical, e := json.Marshal(r)
		if e != nil || !bytes.Equal(raw, canonical) {
			return nil, 0, ErrStorage
		}
		p := r.Candidate.Pending
		if claims[p.ClaimID] || keys[p.KeyFingerprint] || devices[r.Candidate.DeviceID] || ops[r.Candidate.OperationID] {
			return nil, 0, ErrStorage
		}
		claims[p.ClaimID] = true
		keys[p.KeyFingerprint] = true
		devices[r.Candidate.DeviceID] = true
		ops[r.Candidate.OperationID] = true
		out = append(out, r)
	}
	if rows.Err() != nil || len(out) != count {
		return nil, 0, ErrStorage
	}
	return out, last, nil
}

// Approve records one explicitly reviewed binding. The passed session guard
// must authenticate the exact actor and remain live, and the review acquire
// must enforce protected, alias-free pending/profile/operator storage. Both are
// called under the fixed approval→pending→profile→operator lock order. The
// ReviewLease is held through the approval COMMIT/ROLLBACK. The decision's
// device ID must be freshly generated by trusted manager code, never by a
// client; a boolean here is not evidence of actual human consent. There is no
// automatic write retry; an uncertain COMMIT is reconciled by a guarded read.
// Neither acquire nor sessionGuard may reenter approval or pending storage;
// sessionGuard must also avoid reentering the nested operator/profile stores.
func (s *Store) Approve(ctx context.Context, pending *customerpending.Store, expected customerpending.ReviewExpectation, decision customerapproval.Decision, actor Actor, clock func() time.Time, acquire customerpending.AcquireReviewAuthority, sessionGuard func(context.Context, Actor) error) (Record, error) {
	if s == nil || s.db == nil || ctx == nil || pending == nil || clock == nil || acquire == nil || sessionGuard == nil || !actor.valid() || expected.ManagerID != s.managerID || expected.ManagerDigest != s.managerDigest {
		return Record{}, ErrInvalid
	}
	started := clock().UTC()
	if started.Unix() <= 0 || started.Unix() > maxTimestamp || ctx.Err() != nil {
		return Record{}, ErrInvalid
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return Record{}, ErrStorage
	}
	began, committed := false, false
	var review *customerpending.ReviewLease
	defer func() {
		if review != nil {
			review.Release()
		}
	}()
	defer func() { closeTransaction(conn, began, committed) }()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return Record{}, ErrStorage
	}
	began = true
	records, last, err := load(ctx, conn, s.managerID, s.managerDigest)
	if err != nil {
		return Record{}, err
	}
	if started.Unix() < last {
		return Record{}, ErrInvalid
	}
	if len(records) >= MaxRecords {
		return Record{}, ErrLimit
	}
	review, err = pending.AcquireReview(ctx, expected, clock, acquire)
	if err != nil {
		return Record{}, err
	}
	if err = sessionGuard(ctx, actor); err != nil {
		return Record{}, err
	}
	snapshot, err := review.Snapshot()
	if err != nil {
		return Record{}, err
	}
	now := clock().UTC()
	if now.Before(started) || now.Unix() < last || now.Unix() >= snapshot.DeadlineAt {
		return Record{}, ErrInvalid
	}
	candidate, err := customerapproval.Build(expected, snapshot, decision, now)
	if err != nil {
		return Record{}, ErrInvalid
	}
	record := Record{Version: "tracebolt.customer-approval-record.v1", Actor: actor, Candidate: candidate}
	if !validRecord(record, s.managerID, s.managerDigest) {
		return Record{}, ErrInvalid
	}
	for _, r := range records {
		p := r.Candidate.Pending
		if p.ClaimID == snapshot.ClaimID || p.KeyFingerprint == snapshot.KeyFingerprint || r.Candidate.DeviceID == candidate.DeviceID || r.Candidate.OperationID == candidate.OperationID {
			return Record{}, ErrConflict
		}
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > 16384 {
		return Record{}, ErrInvalid
	}
	if _, err = conn.ExecContext(ctx, `INSERT INTO customer_approval_records(claim_id,body) VALUES (?,?)`, snapshot.ClaimID, raw); err != nil {
		return Record{}, ErrStorage
	}
	if err = review.Check(); err != nil {
		return Record{}, err
	}
	if err = sessionGuard(ctx, actor); err != nil {
		return Record{}, err
	}
	if err = ctx.Err(); err != nil {
		return Record{}, err
	}
	end := clock().UTC()
	if end.Before(now) || end.Unix() >= snapshot.DeadlineAt || end.Unix() > maxTimestamp {
		return Record{}, ErrInvalid
	}
	if _, err = conn.ExecContext(ctx, `UPDATE customer_approval_meta SET count=?,last_at=? WHERE id=1`, len(records)+1, end.Unix()); err != nil || customerschema.Validate(ctx, conn, schema()) != nil {
		return Record{}, ErrStorage
	}
	if err = review.Check(); err != nil {
		return Record{}, err
	}
	if err = sessionGuard(ctx, actor); err != nil {
		return Record{}, err
	}
	if err = review.Check(); err != nil {
		return Record{}, err
	}
	final := clock().UTC()
	if final.Before(end) || final.Unix() >= snapshot.DeadlineAt || final.Unix() > maxTimestamp || ctx.Err() != nil {
		return Record{}, ErrInvalid
	}
	if final.Unix() != end.Unix() {
		if _, err = conn.ExecContext(ctx, `UPDATE customer_approval_meta SET last_at=? WHERE id=1`, final.Unix()); err != nil {
			return Record{}, ErrStorage
		}
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return Record{}, ErrStorage
	}
	committed = true
	return record, nil
}

// Records returns bounded retained data for authenticated operator-only
// reconciliation. It never means the record is current, approved for signing,
// activated or usable for any scope. The caller must enforce that access.
func (s *Store) Records(ctx context.Context) ([]Record, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalid
	}
	c, err := s.db.Conn(ctx)
	if err != nil {
		return nil, ErrStorage
	}
	began, committed := false, false
	defer func() { closeTransaction(c, began, committed) }()
	if _, err = c.ExecContext(ctx, `BEGIN`); err != nil {
		return nil, ErrStorage
	}
	began = true
	records, _, err := load(ctx, c, s.managerID, s.managerDigest)
	if err != nil {
		return nil, err
	}
	if _, err = c.ExecContext(ctx, `COMMIT`); err != nil {
		return nil, ErrStorage
	}
	committed = true
	return records, nil
}
