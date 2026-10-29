// Package customerv3owner is an isolated fresh-only transaction candidate. It
// stores an approval and its first issuance intent as one immutable row in one
// SQLite COMMIT; it cannot sign, issue, activate or authorize observations.
// Its DB is not the existing v2 enrollment authority. A production owner must
// provide protected non-aliased state, independently durable used markers,
// live session/issuer guards, and incorporate this exact row in the SAME
// authoritative enrollment transaction before using it for issuance.
package customerv3owner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/customerapproval"
	"localrmm/internal/customerapprovalstore"
	"localrmm/internal/customerissuance"
	"localrmm/internal/customerpending"
	"localrmm/internal/customerschema"
	"localrmm/internal/enrollmentcrypto"
)

const MaxRecords = 100

// MaxTransactionDuration bounds cooperative DB operations and authority checks;
// it is shorter than the pending review lease. A callback or driver that ignores
// context cannot be forcibly interrupted by this package.
const MaxTransactionDuration = 25 * time.Second
const maxTimestamp = int64(253402300499)
const schemaVersion = 3
const metaSchema = `CREATE TABLE customer_v3_meta (id INTEGER PRIMARY KEY CHECK(id=1), manager_id TEXT NOT NULL, manager_digest TEXT NOT NULL, count INTEGER NOT NULL CHECK(count>=0 AND count<=100), cert_count INTEGER NOT NULL CHECK(cert_count>=0 AND cert_count<=100), activation_count INTEGER NOT NULL CHECK(activation_count>=0 AND activation_count<=100), last_at INTEGER NOT NULL CHECK(last_at>=0)) STRICT`
const recordSchema = `CREATE TABLE customer_v3_intents (claim_id TEXT PRIMARY KEY NOT NULL, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384)) STRICT`
const certificateSchema = `CREATE TABLE customer_v3_certificates (claim_id TEXT PRIMARY KEY NOT NULL, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384)) STRICT`
const activationSchema = `CREATE TABLE customer_v3_activations (claim_id TEXT PRIMARY KEY NOT NULL, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=4096)) STRICT`

var ErrInvalid = errors.New("customer v3 transaction invalid")
var ErrStorage = errors.New("customer v3 storage unavailable or invalid")
var ErrConflict = errors.New("customer v3 identity or operation already retained")
var ErrLimit = errors.New("customer v3 capacity exhausted")
var ErrUncertain = errors.New("customer v3 commit not confirmed; reconcile without retry")

func schema() []customerschema.Object {
	return []customerschema.Object{customerschema.ObjectSQL("customer_v3_meta", metaSchema), customerschema.ObjectSQL("customer_v3_intents", recordSchema), customerschema.AutoIndex("sqlite_autoindex_customer_v3_intents_1", "customer_v3_intents"), customerschema.ObjectSQL("customer_v3_certificates", certificateSchema), customerschema.AutoIndex("sqlite_autoindex_customer_v3_certificates_1", "customer_v3_certificates"), customerschema.ObjectSQL("customer_v3_activations", activationSchema), customerschema.AutoIndex("sqlite_autoindex_customer_v3_activations_1", "customer_v3_activations")}
}

type Store struct {
	db                       *sql.DB
	managerID, managerDigest string
}

func discard(c *sql.Conn) { _ = c.Raw(func(any) error { return driver.ErrBadConn }); _ = c.Close() }
func finish(c *sql.Conn, committed bool) {
	if !committed {
		if _, e := c.ExecContext(context.Background(), `ROLLBACK`); e != nil {
			discard(c)
			return
		}
	}
	_ = c.Close()
}

// A panic or error during BEGIN leaves its actual outcome unknown. Never put
// that connection back in the pool; a confirmed BEGIN can be rolled back.
func closeTransaction(c *sql.Conn, began, committed bool) {
	if !began {
		discard(c)
		return
	}
	finish(c, committed)
}

// Initialize requires a genuinely new, empty database. It cannot detect whole
// database loss or rollback: an independently protected used marker is needed.
// It is never a recovery or adoption path for v2 or another candidate domain.
func Initialize(ctx context.Context, db *sql.DB, managerID, managerDigest string) (result error) {
	commitAttempted := false
	defer func() {
		if recover() != nil {
			if commitAttempted {
				result = ErrUncertain
			} else {
				result = ErrStorage
			}
		}
	}()
	if ctx == nil || db == nil || !enrollmentcrypto.ValidID(managerID, "manager_") || !enrollmentcrypto.ValidHash(managerDigest) {
		return ErrInvalid
	}
	c, e := db.Conn(ctx)
	if e != nil {
		return ErrStorage
	}
	began, committed := false, false
	defer func() { closeTransaction(c, began, committed) }()
	if _, e = c.ExecContext(ctx, `BEGIN IMMEDIATE`); e != nil {
		return ErrStorage
	}
	began = true
	if customerschema.Empty(ctx, c) != nil {
		return ErrStorage
	}
	for _, statement := range []string{metaSchema, recordSchema, certificateSchema, activationSchema} {
		if _, e = c.ExecContext(ctx, statement); e != nil {
			return ErrStorage
		}
	}
	if _, e = c.ExecContext(ctx, `INSERT INTO customer_v3_meta VALUES(1,?,?,0,0,0,0)`, managerID, managerDigest); e != nil {
		return ErrStorage
	}
	if _, e = c.ExecContext(ctx, `PRAGMA main.user_version=3`); e != nil || customerschema.ValidateVersion(ctx, c, schema(), schemaVersion) != nil {
		return ErrStorage
	}
	commitAttempted = true
	if _, e = c.ExecContext(ctx, `COMMIT`); e != nil {
		return ErrUncertain
	}
	committed = true
	if ctx.Err() != nil {
		return ErrUncertain
	}
	return nil
}

// New never creates, repairs or checks filesystem authority.
func New(db *sql.DB, managerID, managerDigest string) (*Store, error) {
	if db == nil || !enrollmentcrypto.ValidID(managerID, "manager_") || !enrollmentcrypto.ValidHash(managerDigest) {
		return nil, ErrInvalid
	}
	return &Store{db, managerID, managerDigest}, nil
}

func load(ctx context.Context, c *sql.Conn, managerID, managerDigest string) ([]customerissuance.Intent, int64, error) {
	if customerschema.ValidateVersion(ctx, c, schema(), schemaVersion) != nil {
		return nil, 0, ErrStorage
	}
	var entries, count, certCount, activationCount int
	var manager, digest string
	var last int64
	if c.QueryRowContext(ctx, `SELECT count(*) FROM customer_v3_meta`).Scan(&entries) != nil || entries != 1 {
		return nil, 0, ErrStorage
	}
	if c.QueryRowContext(ctx, `SELECT manager_id,manager_digest,count,cert_count,activation_count,last_at FROM customer_v3_meta WHERE id=1`).Scan(&manager, &digest, &count, &certCount, &activationCount, &last) != nil || manager != managerID || digest != managerDigest || count < 0 || count > MaxRecords || certCount < 0 || certCount > count || activationCount < 0 || activationCount > certCount || last < 0 || last > maxTimestamp {
		return nil, 0, ErrStorage
	}
	rows, e := c.QueryContext(ctx, `SELECT claim_id,body FROM customer_v3_intents ORDER BY claim_id LIMIT 101`)
	if e != nil {
		return nil, 0, ErrStorage
	}
	defer rows.Close()
	out := make([]customerissuance.Intent, 0, count)
	claims, keys, devices, operations, intents, serials := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for rows.Next() {
		var id string
		var raw []byte
		if rows.Scan(&id, &raw) != nil {
			return nil, 0, ErrStorage
		}
		i, e := customerissuance.Parse(raw)
		if e != nil || id != i.Approval.Candidate.Pending.ClaimID || i.Approval.Candidate.Pending.ManagerID != managerID || i.Approval.Candidate.ManagerDigest != managerDigest || i.NotBefore > last {
			return nil, 0, ErrStorage
		}
		a, p := i.Approval.Candidate, i.Approval.Candidate.Pending
		if claims[p.ClaimID] || keys[p.KeyFingerprint] || devices[a.DeviceID] || operations[a.OperationID] || intents[i.IntentID] || serials[i.SerialHex] {
			return nil, 0, ErrStorage
		}
		claims[p.ClaimID] = true
		keys[p.KeyFingerprint] = true
		devices[a.DeviceID] = true
		operations[a.OperationID] = true
		intents[i.IntentID] = true
		serials[i.SerialHex] = true
		out = append(out, i)
	}
	if rows.Err() != nil || len(out) != count {
		return nil, 0, ErrStorage
	}
	if e = rows.Close(); e != nil {
		return nil, 0, ErrStorage
	}
	certs, e := loadCertificates(ctx, c, out, certCount, last)
	if e != nil {
		return nil, 0, e
	}
	if _, e = loadActivations(ctx, c, out, certs, activationCount, last); e != nil {
		return nil, 0, e
	}
	return out, last, nil
}

// CertificateRecord is a retained public leaf and its exact original intent
// digest. It is not a delivered credential, activation or current authority.
type CertificateRecord struct {
	Version         string `json:"version"`
	ClaimID         string `json:"claimId"`
	IntentID        string `json:"intentId"`
	IntentDigest    string `json:"intentDigest"`
	CertificateHash string `json:"certificateHash"`
	DER             []byte `json:"der"`
	RecordedAt      int64  `json:"recordedAt"`
}

// loadCertificates checks canonical storage, exact stored intent/DER hashes,
// bounded counts and unique certificate hashes. It cannot authenticate a DB
// or establish a currently trusted issuer; callers must reverify with live
// issuer/root and revocation authority before any future credential use.
func loadCertificates(ctx context.Context, c *sql.Conn, intents []customerissuance.Intent, count int, last int64) ([]CertificateRecord, error) {
	byClaim := make(map[string]customerissuance.Intent, len(intents))
	for _, i := range intents {
		byClaim[i.Approval.Candidate.Pending.ClaimID] = i
	}
	rows, e := c.QueryContext(ctx, `SELECT claim_id,body FROM customer_v3_certificates ORDER BY claim_id LIMIT 101`)
	if e != nil {
		return nil, ErrStorage
	}
	defer rows.Close()
	out := make([]CertificateRecord, 0, count)
	hashes := map[string]bool{}
	for rows.Next() {
		var id string
		var raw []byte
		var r CertificateRecord
		if rows.Scan(&id, &raw) != nil || len(raw) > 16384 || json.Unmarshal(raw, &r) != nil {
			return nil, ErrStorage
		}
		i, ok := byClaim[id]
		if !ok || id != r.ClaimID || r.Version != "tracebolt.customer-v3-certificate-record.v1" || r.IntentID != i.IntentID || r.RecordedAt < i.NotBefore || r.RecordedAt >= i.NotAfter || r.RecordedAt >= i.Approval.Candidate.Pending.DeadlineAt || r.RecordedAt > last || len(r.DER) == 0 || len(r.DER) > enrollmentcrypto.MaxCertificateBytes {
			return nil, ErrStorage
		}
		idigest, err := customerissuance.Digest(i)
		sum := sha256.Sum256(r.DER)
		if err != nil || r.IntentDigest != idigest || r.CertificateHash != hex.EncodeToString(sum[:]) || hashes[r.CertificateHash] {
			return nil, ErrStorage
		}
		canonical, err := json.Marshal(r)
		if err != nil || !bytes.Equal(canonical, raw) {
			return nil, ErrStorage
		}
		hashes[r.CertificateHash] = true
		out = append(out, r)
	}
	if rows.Err() != nil || len(out) != count {
		return nil, ErrStorage
	}
	return out, nil
}

// Request contains manager-selected public identifiers and reviewed approval.
// A device must never supply DeviceID, IntentID, SerialHex or Actor. An actual
// session must separately bind and verify Actor and both acknowledgements.
type Request struct {
	Expected            customerpending.ReviewExpectation
	Decision            customerapproval.Decision
	Actor               customerapprovalstore.Actor
	IntentID, SerialHex string
	Lifetime            time.Duration
}

// LiveAuthorityLease represents the exact authenticated operator session and
// original issuer authority. It must remain held until Release and fail Check
// when either is revoked, replaced, expired or otherwise unavailable.
type LiveAuthorityLease interface {
	Check() error
	Release()
}

// AcquireLiveAuthority is called under the held review lease with the verified
// original issuer fingerprint and manager-selected actor. It must not reenter
// any already locked store. A fixture/no-op lease does not authorize runtime.
type AcquireLiveAuthority func(context.Context, customerapprovalstore.Actor, string) (LiveAuthorityLease, error)

// StorageGuard must verify actual protected, distinct open DB/file identities,
// used markers and surrounding storage authority without acquiring any of the
// transaction locks below. A callback that merely returns nil proves nothing.
type StorageGuard func(context.Context) error

// Commit acquires v3 enrollment→pending→profile→operator in this order. The
// returned ReviewLease and live actor/issuer authority lease remain held through
// COMMIT or rollback, and are checked at the guarded mutation edge.
// Before any DB access and again before COMMIT, storageGuard must fail closed
// on missing, unprotected, replaced or aliased stores and used-marker loss. It
// must not itself reenter a locked store. The issuer/root bytes and live guard
// are trusted manager configuration, not request data. Unknown COMMIT results
// return ErrUncertain: reconcile by an authenticated read, never auto-retry.
// No result from this candidate grants signing, credential or runtime authority.
func (s *Store) Commit(ctx context.Context, pending *customerpending.Store, req Request, issuerDER, rootDER []byte, clock func() time.Time, acquire customerpending.AcquireReviewAuthority, acquireLive AcquireLiveAuthority, storageGuard StorageGuard) (result customerissuance.Intent, resultErr error) {
	commitAttempted := false
	defer func() {
		if recover() != nil {
			result = customerissuance.Intent{}
			if commitAttempted {
				resultErr = ErrUncertain
			} else {
				resultErr = ErrInvalid
			}
		}
	}()
	if s == nil || s.db == nil || ctx == nil || pending == nil || clock == nil || acquire == nil || acquireLive == nil || storageGuard == nil || len(issuerDER) == 0 || len(issuerDER) > enrollmentcrypto.MaxCertificateBytes || len(rootDER) == 0 || len(rootDER) > enrollmentcrypto.MaxCertificateBytes || req.Expected.ManagerID != s.managerID || req.Expected.ManagerDigest != s.managerDigest {
		return customerissuance.Intent{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, MaxTransactionDuration)
	defer cancel()
	issuerDER, rootDER = bytes.Clone(issuerDER), bytes.Clone(rootDER)
	started := clock().UTC()
	if started.Unix() <= 0 || started.Unix() > maxTimestamp || ctx.Err() != nil {
		return customerissuance.Intent{}, ErrInvalid
	}
	if err := storageGuard(ctx); err != nil {
		return customerissuance.Intent{}, err
	}
	c, e := s.db.Conn(ctx)
	if e != nil {
		return customerissuance.Intent{}, ErrStorage
	}
	began, committed := false, false
	var review *customerpending.ReviewLease
	var live LiveAuthorityLease
	// Independent defers retain all leases through COMMIT/ROLLBACK and still
	// release the outer review if an inner Release unexpectedly panics.
	defer func() {
		if review != nil {
			review.Release()
		}
	}()
	defer func() {
		if live != nil {
			live.Release()
		}
	}()
	defer func() { closeTransaction(c, began, committed) }()
	if _, e = c.ExecContext(ctx, `BEGIN IMMEDIATE`); e != nil {
		return customerissuance.Intent{}, ErrStorage
	}
	began = true
	rows, last, e := load(ctx, c, s.managerID, s.managerDigest)
	if e != nil {
		return customerissuance.Intent{}, e
	}
	if started.Unix() < last {
		return customerissuance.Intent{}, ErrInvalid
	}
	if len(rows) >= MaxRecords {
		return customerissuance.Intent{}, ErrLimit
	}
	review, e = pending.AcquireReview(ctx, req.Expected, clock, acquire)
	if e != nil {
		return customerissuance.Intent{}, e
	}
	snapshot, e := review.Snapshot()
	if e != nil {
		return customerissuance.Intent{}, e
	}
	live, e = acquireLive(ctx, req.Actor, snapshot.IssuerFingerprint)
	if e != nil {
		return customerissuance.Intent{}, e
	}
	if live == nil {
		return customerissuance.Intent{}, ErrInvalid
	}
	if e = live.Check(); e != nil {
		return customerissuance.Intent{}, e
	}
	now := clock().UTC()
	if now.Before(started) || now.Unix() < last || now.Unix() >= snapshot.DeadlineAt {
		return customerissuance.Intent{}, ErrInvalid
	}
	candidate, e := customerapproval.Build(req.Expected, snapshot, req.Decision, now)
	if e != nil {
		return customerissuance.Intent{}, ErrInvalid
	}
	approval := customerapprovalstore.Record{Version: "tracebolt.customer-approval-record.v1", Actor: req.Actor, Candidate: candidate}
	intent, e := customerissuance.Build(approval, req.IntentID, req.SerialHex, now, req.Lifetime)
	if e != nil {
		return customerissuance.Intent{}, ErrInvalid
	}
	if customerissuance.ValidateIssuer(intent, issuerDER, rootDER, now) != nil {
		return customerissuance.Intent{}, ErrInvalid
	}
	for _, old := range rows {
		a, p := old.Approval.Candidate, old.Approval.Candidate.Pending
		if p.ClaimID == snapshot.ClaimID || p.KeyFingerprint == snapshot.KeyFingerprint || a.DeviceID == candidate.DeviceID || a.OperationID == candidate.OperationID || old.IntentID == intent.IntentID || old.SerialHex == intent.SerialHex {
			return customerissuance.Intent{}, ErrConflict
		}
	}
	raw, e := customerissuance.Canonical(intent)
	if e != nil {
		return customerissuance.Intent{}, ErrInvalid
	}
	if _, e = c.ExecContext(ctx, `INSERT INTO customer_v3_intents(claim_id,body) VALUES(?,?)`, snapshot.ClaimID, raw); e != nil {
		return customerissuance.Intent{}, ErrStorage
	}
	if e = review.Check(); e != nil {
		return customerissuance.Intent{}, e
	}
	if e = live.Check(); e != nil {
		return customerissuance.Intent{}, e
	}
	end := clock().UTC()
	if end.Before(now) || end.Unix() >= snapshot.DeadlineAt || end.Unix() > maxTimestamp || customerissuance.ValidateIssuer(intent, issuerDER, rootDER, end) != nil {
		return customerissuance.Intent{}, ErrInvalid
	}
	if _, e = c.ExecContext(ctx, `UPDATE customer_v3_meta SET count=?,last_at=? WHERE id=1`, len(rows)+1, end.Unix()); e != nil || customerschema.ValidateVersion(ctx, c, schema(), schemaVersion) != nil {
		return customerissuance.Intent{}, ErrStorage
	}
	if e = review.Check(); e != nil {
		return customerissuance.Intent{}, e
	}
	if e = live.Check(); e != nil {
		return customerissuance.Intent{}, e
	}
	if e = review.Check(); e != nil {
		return customerissuance.Intent{}, e
	}
	if e = storageGuard(ctx); e != nil {
		return customerissuance.Intent{}, e
	}
	if e = live.Check(); e != nil {
		return customerissuance.Intent{}, e
	}
	final := clock().UTC()
	// started predates acquisition of the review lease, making this bound
	// conservative even if the last live check took time or blocked.
	if final.Before(end) || !final.Before(started.Add(customerpending.MaxReviewLease)) || final.Unix() >= snapshot.DeadlineAt || final.Unix() > maxTimestamp || ctx.Err() != nil || customerissuance.ValidateIssuer(intent, issuerDER, rootDER, final) != nil {
		return customerissuance.Intent{}, ErrInvalid
	}
	if final.Unix() != end.Unix() {
		if _, e = c.ExecContext(ctx, `UPDATE customer_v3_meta SET last_at=? WHERE id=1`, final.Unix()); e != nil {
			return customerissuance.Intent{}, ErrStorage
		}
	}
	commitAttempted = true
	if _, e = c.ExecContext(ctx, `COMMIT`); e != nil {
		return customerissuance.Intent{}, ErrUncertain
	}
	committed = true
	// A driver may ignore cancellation and return success after the deadline.
	// The bytes may be durable, but this caller cannot assert a live commit.
	if ctx.Err() != nil {
		return customerissuance.Intent{}, ErrUncertain
	}
	if e = storageGuard(ctx); e != nil {
		return customerissuance.Intent{}, ErrUncertain
	}
	if e = live.Check(); e != nil {
		return customerissuance.Intent{}, ErrUncertain
	}
	if e = review.Check(); e != nil {
		return customerissuance.Intent{}, ErrUncertain
	}
	after := clock().UTC()
	if after.Before(final) || !after.Before(started.Add(customerpending.MaxReviewLease)) || after.Unix() >= snapshot.DeadlineAt || after.Unix() > maxTimestamp || ctx.Err() != nil || customerissuance.ValidateIssuer(intent, issuerDER, rootDER, after) != nil {
		return customerissuance.Intent{}, ErrUncertain
	}
	return intent, nil
}

// Records is only for authenticated, bounded, read-only reconciliation. It
// does not establish live authority, permit a signature or retry an operation.
func (s *Store) Records(ctx context.Context) (result []customerissuance.Intent, resultErr error) {
	defer func() {
		if recover() != nil {
			result = nil
			resultErr = ErrStorage
		}
	}()
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalid
	}
	c, e := s.db.Conn(ctx)
	if e != nil {
		return nil, ErrStorage
	}
	began, committed := false, false
	defer func() { closeTransaction(c, began, committed) }()
	if _, e = c.ExecContext(ctx, `BEGIN`); e != nil {
		return nil, ErrStorage
	}
	began = true
	out, _, e := load(ctx, c, s.managerID, s.managerDigest)
	if e != nil {
		return nil, e
	}
	if _, e = c.ExecContext(ctx, `COMMIT`); e != nil {
		return nil, ErrStorage
	}
	committed = true
	// Each parsed key is already an independent copy from SQLite bytes.
	return out, nil
}
