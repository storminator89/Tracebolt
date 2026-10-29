// Package customerpending persists bounded, unapproved customer-bound claims.
// It does not establish identity, issue credentials or authorize observation.
// Its owner must provide an exclusively used, protected SQLite database and must
// consume a trusted, one-use manager challenge before passing a verified proof.
// It acquires customer/profile/issuer authority after its pending write lock and
// holds the lease until COMMIT or ROLLBACK. It does not provide challenge replay
// protection or transport rate limits.
package customerpending

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/customerclaim"
	"localrmm/internal/customerschema"
	"localrmm/internal/enrollmentcrypto"
)

const MaxRecords = 100
const MaxCustomerRecords = 25
const PendingLifetime = 24 * time.Hour
const maxTimestamp = int64(253402300499)

var ErrInvalid = errors.New("customer pending input invalid")
var ErrStorage = errors.New("customer pending storage unavailable or invalid")
var ErrConflict = errors.New("customer pending claim conflicts with retained identity")
var ErrExpired = errors.New("customer pending claim or proof expired")
var ErrLimit = errors.New("customer pending capacity exhausted")

const metaSchema = `CREATE TABLE customer_pending_meta (id INTEGER PRIMARY KEY CHECK(id=1), count INTEGER NOT NULL CHECK(count>=0 AND count<=100), last_at INTEGER NOT NULL CHECK(last_at>=0)) STRICT`
const claimSchema = `CREATE TABLE customer_pending_claims (claim_id TEXT PRIMARY KEY NOT NULL, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=4096)) STRICT`

func schemaObjects() []customerschema.Object {
	return []customerschema.Object{customerschema.ObjectSQL("customer_pending_meta", metaSchema), customerschema.ObjectSQL("customer_pending_claims", claimSchema), customerschema.AutoIndex("sqlite_autoindex_customer_pending_claims_1", "customer_pending_claims")}
}

// Store borrows the database; its owner retains responsibility for secure
// opening, protected paths, exclusive schema ownership, backups and closure.
type Store struct{ db *sql.DB }

// A failed BEGIN or ROLLBACK can leave a raw SQLite transaction in an unknown
// state. Mark that connection bad so database/sql discards it instead of
// returning it to the pool. This does not determine whether a failed COMMIT
// took effect; callers must reconcile uncertain results separately.
func discardConnection(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
}

func releaseTransaction(conn *sql.Conn, committed bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			discardConnection(conn)
			panic(recovered)
		}
	}()
	if !committed {
		if _, err := conn.ExecContext(context.Background(), `ROLLBACK`); err != nil {
			discardConnection(conn)
			return
		}
	}
	_ = conn.Close()
}

// An interrupted BEGIN may already have opened a transaction. Do not reuse
// that connection unless BEGIN returned success and cleanup completed.
func closeTransaction(conn *sql.Conn, began, committed bool) {
	if !began {
		discardConnection(conn)
		return
	}
	releaseTransaction(conn, committed)
}

// AuthorityLease represents current customer/profile/issuer authority. Check
// must fail on session, issuer, profile, customer or time invalidation. Release
// must retain the held lock until called and must not touch the pending store.
type AuthorityLease interface {
	Check() error
	Release()
}

// AcquireAuthority is invoked only after BEGIN IMMEDIATE on pending storage.
// Implementations acquire profile and then operator authority in that order;
// future issuance must acquire enrollment before pending. Aliased databases and
// any incompatible lock order must be rejected by the eventual coordinator.
type AcquireAuthority func(context.Context, customerclaim.Metadata) (AuthorityLease, error)

// Record is a pending-only snapshot. Its public key is the exact CSR key, not
// certificate contents. Raw CSR, signature and challenge are not persisted.
type Record struct {
	Version            string `json:"version"`
	ManagerID          string `json:"managerId"`
	CustomerID         string `json:"customerId"`
	InstallerProfileID string `json:"installerProfileId"`
	Origin             string `json:"origin"`
	AgentOrigin        string `json:"agentOrigin"`
	IssuerFingerprint  string `json:"issuerFingerprint"`
	ClaimID            string `json:"claimId"`
	RequestID          string `json:"requestId"`
	KeyFingerprint     string `json:"keyFingerprint"`
	CSRHash            string `json:"csrHash"`
	ClaimHash          string `json:"claimHash"`
	ComparisonCode     string `json:"comparisonCode"`
	PublicKeyDER       []byte `json:"publicKeyDer"`
	CreatedAt          int64  `json:"createdAt"`
	DeadlineAt         int64  `json:"deadlineAt"`
}

// Initialize is create-only and requires an otherwise empty fresh database.
// Its eventual owner must use an independently retained version-bound used
// marker to prevent initializing a lost or replaced database. Never use this
// API to recover a previously used or missing domain: neither
// complete database rollback nor a coordinated removal of all tables can be
// detected by this schema. Existing old enrollment state is not adopted.
func Initialize(ctx context.Context, db *sql.DB) error {
	if ctx == nil || db == nil {
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
	if _, err = conn.ExecContext(ctx, metaSchema); err != nil {
		return ErrStorage
	}
	if _, err = conn.ExecContext(ctx, claimSchema); err != nil {
		return ErrStorage
	}
	if _, err = conn.ExecContext(ctx, `INSERT INTO customer_pending_meta VALUES(1,0,0)`); err != nil {
		return ErrStorage
	}
	if _, err = conn.ExecContext(ctx, `PRAGMA main.user_version=1`); err != nil || customerschema.Validate(ctx, conn, schemaObjects()) != nil {
		return ErrStorage
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return ErrStorage
	}
	committed = true
	return nil
}

// New never initializes or repairs storage. All reads and writes validate its
// bounded canonical records and retained count before returning.
func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	return &Store{db: db}, nil
}

func validRecord(r Record) bool {
	if r.Version != "tracebolt.customer-pending.v1" || !enrollmentcrypto.ValidID(r.ManagerID, "manager_") || !enrollmentcrypto.ValidID(r.CustomerID, "customer_") || !enrollmentcrypto.ValidID(r.InstallerProfileID, "profile_") || !enrollmentcrypto.ValidID(r.ClaimID, "claim_") || !enrollmentcrypto.ValidID(r.RequestID, "request_") || !enrollmentcrypto.ValidHash(r.IssuerFingerprint) || !enrollmentcrypto.ValidHash(r.KeyFingerprint) || !enrollmentcrypto.ValidHash(r.CSRHash) || !enrollmentcrypto.ValidHash(r.ClaimHash) || len(r.ComparisonCode) != 32 || r.CreatedAt <= 0 || r.DeadlineAt != r.CreatedAt+int64(PendingLifetime/time.Second) || r.DeadlineAt > maxTimestamp || len(r.PublicKeyDER) != 44 || len(r.Origin) == 0 || len(r.Origin) > 512 || len(r.AgentOrigin) == 0 || len(r.AgentOrigin) > 512 {
		return false
	}
	m := customerclaim.Metadata{ManagerID: r.ManagerID, CustomerID: r.CustomerID, InstallerProfileID: r.InstallerProfileID, Origin: r.Origin, AgentOrigin: r.AgentOrigin, IssuerFingerprint: r.IssuerFingerprint, ClaimID: r.ClaimID, RequestID: r.RequestID, KeyFingerprint: r.KeyFingerprint, CSRHash: r.CSRHash, ClaimHash: r.ClaimHash, ComparisonCode: r.ComparisonCode}
	return customerclaim.ValidateStoredMetadata(m, r.PublicKeyDER)
}

func load(ctx context.Context, conn *sql.Conn) ([]Record, int64, error) {
	if customerschema.Validate(ctx, conn, schemaObjects()) != nil {
		return nil, 0, ErrStorage
	}
	var metaCount int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM customer_pending_meta`).Scan(&metaCount); err != nil || metaCount != 1 {
		return nil, 0, ErrStorage
	}
	var count int
	var last int64
	if err := conn.QueryRowContext(ctx, `SELECT count,last_at FROM customer_pending_meta WHERE id=1`).Scan(&count, &last); err != nil || count < 0 || count > MaxRecords || last < 0 || last > maxTimestamp {
		return nil, 0, ErrStorage
	}
	rows, err := conn.QueryContext(ctx, `SELECT claim_id,body FROM customer_pending_claims ORDER BY claim_id LIMIT 101`)
	if err != nil {
		return nil, 0, ErrStorage
	}
	defer rows.Close()
	out := make([]Record, 0, count)
	requests := make(map[string]bool)
	customers := make(map[string]int)
	for rows.Next() {
		var id string
		var raw []byte
		var r Record
		if rows.Scan(&id, &raw) != nil || len(raw) > 4096 || json.Unmarshal(raw, &r) != nil || id != r.ClaimID || !validRecord(r) || r.CreatedAt > last || requests[r.RequestID] {
			return nil, 0, ErrStorage
		}
		canonical, e := json.Marshal(r)
		if e != nil || !bytes.Equal(canonical, raw) {
			return nil, 0, ErrStorage
		}
		requests[r.RequestID] = true
		customers[r.ManagerID+"/"+r.CustomerID]++
		if customers[r.ManagerID+"/"+r.CustomerID] > MaxCustomerRecords {
			return nil, 0, ErrStorage
		}
		out = append(out, r)
	}
	if rows.Err() != nil || len(out) != count {
		return nil, 0, ErrStorage
	}
	return out, last, nil
}

// Accept persists only an opaque verified proof from customerclaim.Verify. The
// coordinator must have removed the exact challenge from its manager-owned
// single-use pool before calling this method; no proof supplied by a client or
// a cached Verified value alone is admission authority. A live customer/profile/
// issuer lease is acquired after the pending lock and held through COMMIT. Check
// checks that lease and caller context, and is invoked before writing and again
// before committing. The clock is re-read and cannot move backwards. On an
// unknown COMMIT result use an exact read; never blindly replay a mutation.
func (s *Store) Accept(ctx context.Context, proof customerclaim.Verified, clock func() time.Time, acquire AcquireAuthority) (Record, error) {
	if s == nil || s.db == nil || ctx == nil || clock == nil || acquire == nil || !proof.Valid() {
		return Record{}, ErrInvalid
	}
	m := proof.Metadata()
	key := proof.PublicKeyDER()
	started := clock().UTC().Unix()
	if started <= 0 || started > maxTimestamp-int64(PendingLifetime/time.Second) || m.ExpiresAt <= started || m.ExpiresAt > started+int64(customerclaim.MaxChallengeLifetime/time.Second) {
		return Record{}, ErrExpired
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return Record{}, ErrStorage
	}
	var lease AuthorityLease
	began, committed := false, false
	defer func() {
		if lease != nil {
			lease.Release()
		}
	}()
	defer func() { closeTransaction(conn, began, committed) }()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return Record{}, ErrStorage
	}
	began = true
	records, last, err := load(ctx, conn)
	if err != nil {
		return Record{}, err
	}
	if started < last {
		return Record{}, ErrInvalid
	}
	lease, err = acquire(ctx, m)
	if err != nil {
		return Record{}, err
	}
	if lease == nil {
		return Record{}, ErrInvalid
	}
	if err = lease.Check(); err != nil {
		return Record{}, err
	}
	r := Record{Version: "tracebolt.customer-pending.v1", ManagerID: m.ManagerID, CustomerID: m.CustomerID, InstallerProfileID: m.InstallerProfileID, Origin: m.Origin, AgentOrigin: m.AgentOrigin, IssuerFingerprint: m.IssuerFingerprint, ClaimID: m.ClaimID, RequestID: m.RequestID, KeyFingerprint: m.KeyFingerprint, CSRHash: m.CSRHash, ClaimHash: m.ClaimHash, ComparisonCode: m.ComparisonCode, PublicKeyDER: key, CreatedAt: started, DeadlineAt: started + int64(PendingLifetime/time.Second)}
	if !validRecord(r) {
		return Record{}, ErrInvalid
	}
	countCustomer := 0
	found := false
	for _, old := range records {
		if old.CustomerID == r.CustomerID && old.ManagerID == r.ManagerID {
			countCustomer++
		}
		if old.ClaimID == r.ClaimID || old.RequestID == r.RequestID {
			candidate := r
			candidate.CreatedAt = old.CreatedAt
			candidate.DeadlineAt = old.DeadlineAt
			a, _ := json.Marshal(candidate)
			b, _ := json.Marshal(old)
			if !bytes.Equal(a, b) {
				return Record{}, ErrConflict
			}
			r = old
			found = true
		}
	}
	if r.DeadlineAt <= started {
		return Record{}, ErrExpired
	}
	if !found {
		if len(records) >= MaxRecords || countCustomer >= MaxCustomerRecords {
			return Record{}, ErrLimit
		}
		raw, e := json.Marshal(r)
		if e != nil {
			return Record{}, ErrStorage
		}
		if _, e = conn.ExecContext(ctx, `INSERT INTO customer_pending_claims(claim_id,body) VALUES(?,?)`, r.ClaimID, raw); e != nil {
			return Record{}, ErrStorage
		}
	}
	if err = lease.Check(); err != nil {
		return Record{}, err
	}
	if err = ctx.Err(); err != nil {
		return Record{}, err
	}
	end := clock().UTC().Unix()
	if end < started || end > maxTimestamp || end >= m.ExpiresAt || m.ExpiresAt > end+int64(customerclaim.MaxChallengeLifetime/time.Second) || end >= r.DeadlineAt {
		return Record{}, ErrExpired
	}
	count := len(records)
	if !found {
		count++
	}
	if _, err = conn.ExecContext(ctx, `UPDATE customer_pending_meta SET count=?,last_at=? WHERE id=1`, count, end); err != nil {
		return Record{}, ErrStorage
	}
	if customerschema.Validate(ctx, conn, schemaObjects()) != nil {
		return Record{}, ErrStorage
	}
	if err = lease.Check(); err != nil {
		return Record{}, err
	}
	final := clock().UTC().Unix()
	if final < end || final > maxTimestamp || final >= m.ExpiresAt || m.ExpiresAt > final+int64(customerclaim.MaxChallengeLifetime/time.Second) || final >= r.DeadlineAt {
		return Record{}, ErrExpired
	}
	if err = ctx.Err(); err != nil {
		return Record{}, err
	}
	if final != end {
		if _, err = conn.ExecContext(ctx, `UPDATE customer_pending_meta SET last_at=? WHERE id=1`, final); err != nil {
			return Record{}, ErrStorage
		}
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return Record{}, ErrStorage
	}
	committed = true
	return r, nil
}

// Records is a privileged internal snapshot, not a public endpoint. Callers
// must authorize the operator and filter by manager before presenting it. The
// returned retained records include expired claims; callers must assess each
// original DeadlineAt using a trusted live clock before presenting it as pending.
func (s *Store) Records(ctx context.Context) ([]Record, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalid
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, ErrStorage
	}
	began, committed := false, false
	defer func() { closeTransaction(conn, began, committed) }()
	if _, err = conn.ExecContext(ctx, `BEGIN`); err != nil {
		return nil, ErrStorage
	}
	began = true
	records, _, err := load(ctx, conn)
	if err != nil {
		return nil, err
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return nil, ErrStorage
	}
	committed = true
	return records, nil
}
