// Package customerprofiles is an isolated source candidate for immutable,
// public Windows installer profiles. It is not a download service, enrollment
// authority or customer-access policy. Storage must be separately protected and
// accompanied by an independently durable used marker; do not initialize a lost,
// used or rolled-back database.
//
// Loaded records are checked at their original creation and expiration bounds,
// but a canonical, rehashed record may still contain substituted valid public
// material: neither Get nor its digest proves authenticity. Treat all Get
// results as untrusted readback only. Create and every active-lease Check
// additionally perform current trust validation. Separate used-state and database
// alias guards remain mandatory before integrating any admission workflow.
package customerprofiles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"localrmm/internal/customerschema"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
)

const MaxRecords = 100
const MaxCustomerRecords = 25
const MaxLifetime = 90 * 24 * time.Hour
const maxTimestamp = int64(253402300499)

var ErrInvalid = errors.New("customer profile input invalid")
var ErrStorage = errors.New("customer profile storage unavailable or invalid")
var ErrConflict = errors.New("customer profile identity or revision conflict")
var ErrInactive = errors.New("customer profile is unavailable, expired or retired")
var ErrLimit = errors.New("customer profile capacity exhausted")

const metaSchema = `CREATE TABLE customer_profiles_meta (id INTEGER PRIMARY KEY CHECK(id=1), manager_id TEXT NOT NULL, count INTEGER NOT NULL CHECK(count>=0 AND count<=100), last_at INTEGER NOT NULL CHECK(last_at>=0)) STRICT`
const recordsSchema = `CREATE TABLE customer_profiles_records (profile_id TEXT PRIMARY KEY NOT NULL, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=100000)) STRICT`

func schemaObjects() []customerschema.Object {
	return []customerschema.Object{customerschema.ObjectSQL("customer_profiles_meta", metaSchema), customerschema.ObjectSQL("customer_profiles_records", recordsSchema), customerschema.AutoIndex("sqlite_autoindex_customer_profiles_records_1", "customer_profiles_records")}
}

type Store struct {
	db        *sql.DB
	managerID string
}

// AuthorityLease represents the separately held current operator/customer and
// issuer authority. Acquire it only after taking this profile database lock.
type AuthorityLease interface {
	Check() error
	Release()
}
type AcquireAuthority func(context.Context, string, string) (AuthorityLease, error)

// Record contains the exact validated public JSON supplied at creation.
// Retired records remain retained and their IDs cannot be reused. A SHA-256
// digest binds review to bytes; it is not an authenticity or publisher proof.
type Record struct {
	Version    string `json:"version"`
	ManagerID  string `json:"managerId"`
	CustomerID string `json:"customerId"`
	ProfileID  string `json:"profileId"`
	PublicJSON []byte `json:"publicJson"`
	Digest     string `json:"digest"`
	CreatedAt  int64  `json:"createdAt"`
	ExpiresAt  int64  `json:"expiresAt"`
	RetiredAt  int64  `json:"retiredAt"`
}

// Initialize is for a fresh, empty, exclusively owned database only. An owner
// must maintain a separate durable used marker; this function cannot detect a
// deleted database or a complete rollback. It must never be used for repair.
func Initialize(ctx context.Context, db *sql.DB, managerID string) error {
	if ctx == nil || db == nil || !enrollmentcrypto.ValidID(managerID, "manager_") {
		return ErrInvalid
	}
	conn, e := db.Conn(ctx)
	if e != nil {
		return ErrStorage
	}
	began, committed := false, false
	defer func() {
		if !began {
			discard(conn)
		} else if committed {
			_ = conn.Close()
		} else {
			end(conn)
		}
	}()
	if _, e = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); e != nil {
		return ErrStorage
	}
	began = true
	if customerschema.Empty(ctx, conn) != nil {
		return ErrStorage
	}
	if _, e = conn.ExecContext(ctx, metaSchema); e != nil {
		return ErrStorage
	}
	if _, e = conn.ExecContext(ctx, recordsSchema); e != nil {
		return ErrStorage
	}
	if _, e = conn.ExecContext(ctx, `INSERT INTO customer_profiles_meta VALUES(1,?,0,0)`, managerID); e != nil {
		return ErrStorage
	}
	if _, e = conn.ExecContext(ctx, `PRAGMA main.user_version=1`); e != nil || customerschema.Validate(ctx, conn, schemaObjects()) != nil {
		return ErrStorage
	}
	if _, e = conn.ExecContext(ctx, `COMMIT`); e != nil {
		return ErrStorage
	}
	committed = true
	return nil
}

// New borrows a protected database; it never initializes or repairs it.
func New(db *sql.DB, managerID string) (*Store, error) {
	if db == nil || !enrollmentcrypto.ValidID(managerID, "manager_") {
		return nil, ErrInvalid
	}
	return &Store{db: db, managerID: managerID}, nil
}

func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func validRecord(r Record, manager string) bool {
	if r.Version != "tracebolt.customer-profile-record.v1" || r.ManagerID != manager || !enrollmentcrypto.ValidID(r.CustomerID, "customer_") || !enrollmentcrypto.ValidID(r.ProfileID, "profile_") || len(r.PublicJSON) == 0 || len(r.PublicJSON) > 64<<10 || digest(r.PublicJSON) != r.Digest || r.CreatedAt <= 0 || r.CreatedAt > maxTimestamp || r.ExpiresAt <= r.CreatedAt || r.ExpiresAt > r.CreatedAt+int64(MaxLifetime/time.Second) || r.ExpiresAt > maxTimestamp || r.RetiredAt < 0 || r.RetiredAt > maxTimestamp || r.RetiredAt > 0 && r.RetiredAt < r.CreatedAt {
		return false
	}
	var p enrollmentclient.CustomerProfile
	if json.Unmarshal(r.PublicJSON, &p) != nil {
		return false
	}
	canonical, err := json.Marshal(p)
	if err != nil || !bytes.Equal(canonical, r.PublicJSON) || p.SchemaVersion != enrollmentclient.CustomerProfileVersion || p.Profile != "tls" || p.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || p.ManagerInstanceID != r.ManagerID || p.CustomerID != r.CustomerID || p.InstallerProfileID != r.ProfileID {
		return false
	}
	if _, err = enrollmentclient.ValidateCustomerProfileAt(r.PublicJSON, time.Unix(r.CreatedAt, 0)); err != nil {
		return false
	}
	if _, err = enrollmentclient.ValidateCustomerProfileAt(r.PublicJSON, time.Unix(r.ExpiresAt-1, 0)); err != nil {
		return false
	}
	return true
}

func load(ctx context.Context, conn *sql.Conn, manager string) ([]Record, int64, error) {
	if customerschema.Validate(ctx, conn, schemaObjects()) != nil {
		return nil, 0, ErrStorage
	}
	var metaCount int
	if e := conn.QueryRowContext(ctx, `SELECT count(*) FROM customer_profiles_meta`).Scan(&metaCount); e != nil || metaCount != 1 {
		return nil, 0, ErrStorage
	}
	var stored string
	var count int
	var last int64
	if e := conn.QueryRowContext(ctx, `SELECT manager_id,count,last_at FROM customer_profiles_meta WHERE id=1`).Scan(&stored, &count, &last); e != nil || stored != manager || count < 0 || count > MaxRecords || last < 0 || last > maxTimestamp {
		return nil, 0, ErrStorage
	}
	rows, e := conn.QueryContext(ctx, `SELECT profile_id,body FROM customer_profiles_records ORDER BY profile_id LIMIT 101`)
	if e != nil {
		return nil, 0, ErrStorage
	}
	defer rows.Close()
	out := make([]Record, 0, count)
	customerCounts := map[string]int{}
	for rows.Next() {
		var id string
		var raw []byte
		var r Record
		if rows.Scan(&id, &raw) != nil || len(raw) > 100000 || json.Unmarshal(raw, &r) != nil || id != r.ProfileID || !validRecord(r, manager) || r.CreatedAt > last || r.RetiredAt > last {
			return nil, 0, ErrStorage
		}
		canonical, e := json.Marshal(r)
		if e != nil || !bytes.Equal(raw, canonical) {
			return nil, 0, ErrStorage
		}
		customerCounts[r.CustomerID]++
		if customerCounts[r.CustomerID] > MaxCustomerRecords {
			return nil, 0, ErrStorage
		}
		out = append(out, r)
	}
	if rows.Err() != nil || len(out) != count {
		return nil, 0, ErrStorage
	}
	return out, last, nil
}

func start(ctx context.Context, s *Store) (*sql.Conn, []Record, int64, error) {
	if ctx == nil || s == nil || s.db == nil {
		return nil, nil, 0, ErrInvalid
	}
	conn, e := s.db.Conn(ctx)
	if e != nil {
		return nil, nil, 0, ErrStorage
	}
	began, handedOff := false, false
	defer func() {
		if !handedOff {
			if began {
				end(conn)
			} else {
				discard(conn)
			}
		}
	}()
	if _, e = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); e != nil {
		return nil, nil, 0, ErrStorage
	}
	began = true
	records, last, e := load(ctx, conn, s.managerID)
	if e != nil {
		return nil, nil, 0, e
	}
	handedOff = true
	return conn, records, last, nil
}

// A failed rollback leaves transaction state uncertain. Retire that driver
// connection rather than returning it to a pool for a later unrelated request.
func discard(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
}
func end(conn *sql.Conn) {
	if conn == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			discard(conn)
			panic(recovered)
		}
	}()
	if _, err := conn.ExecContext(context.Background(), `ROLLBACK`); err != nil {
		discard(conn)
		return
	}
	_ = conn.Close()
}
func clockAt(clock func() time.Time, last int64) (int64, error) {
	if clock == nil {
		return 0, ErrInvalid
	}
	n := clock().UTC().Unix()
	if n <= 0 || n > maxTimestamp || n < last {
		return 0, ErrInvalid
	}
	return n, nil
}

// Get returns untrusted retained readback for an authorized operator to
// reconcile an uncertain write, including expired or retired records. It does
// checks historical structure and trust against the stored bytes but does not
// prove they are the original bytes, establish current trust or establish
// cryptographic authenticity. It is not a live authority lease and must never
// be used alone for challenge, enrollment, download or claim admission.
func (s *Store) Get(ctx context.Context, profileID string) (Record, error) {
	if !enrollmentcrypto.ValidID(profileID, "profile_") {
		return Record{}, ErrInvalid
	}
	conn, records, _, e := start(ctx, s)
	if e != nil {
		return Record{}, e
	}
	defer end(conn)
	for _, r := range records {
		if r.ProfileID == profileID {
			return r, nil
		}
	}
	return Record{}, ErrInactive
}

// Create persists exact public configuration after strict local validation. The
// acquire obtains the customer-revision/session and issuer lease only after
// the profile lock; its Check must hold through COMMIT.
// A lost response requires read-only reconciliation, never automatic recreation.
func (s *Store) Create(ctx context.Context, raw []byte, expiresAt int64, clock func() time.Time, acquire AcquireAuthority) (Record, error) {
	if clock == nil || acquire == nil || len(raw) == 0 || len(raw) > 64<<10 {
		return Record{}, ErrInvalid
	}
	conn, records, last, e := start(ctx, s)
	if e != nil {
		return Record{}, e
	}
	var lease AuthorityLease
	committed := false
	defer func() {
		if lease != nil {
			lease.Release()
		}
	}()
	defer func() {
		if committed {
			_ = conn.Close()
		} else {
			end(conn)
		}
	}()
	now, e := clockAt(clock, last)
	if e != nil {
		return Record{}, e
	}
	profile, _, e := enrollmentclient.ParseCustomerProfile(raw, time.Unix(now, 0))
	if e != nil || profile.ManagerInstanceID != s.managerID {
		return Record{}, ErrInvalid
	}
	canonical, e := json.Marshal(profile)
	if e != nil || !bytes.Equal(raw, canonical) {
		return Record{}, ErrInvalid
	}
	// Profile expiry is independently immutable; issuer/root trust must also be
	// valid at its final second, otherwise the profile would outlive its trust.
	if expiresAt <= now || expiresAt > now+int64(MaxLifetime/time.Second) || expiresAt > maxTimestamp {
		return Record{}, ErrInvalid
	}
	if _, e = enrollmentclient.ValidateCustomerProfileAt(raw, time.Unix(now, 0)); e != nil {
		return Record{}, ErrInvalid
	}
	if _, e = enrollmentclient.ValidateCustomerProfileAt(raw, time.Unix(expiresAt-1, 0)); e != nil {
		return Record{}, ErrInvalid
	}
	lease, e = acquire(ctx, profile.CustomerID, profile.InstallerProfileID)
	if e != nil {
		return Record{}, e
	}
	if lease == nil {
		return Record{}, ErrInvalid
	}
	if e = lease.Check(); e != nil {
		return Record{}, e
	}
	countCustomer := 0
	for _, r := range records {
		if r.CustomerID == profile.CustomerID {
			countCustomer++
		}
		if r.ProfileID == profile.InstallerProfileID {
			return Record{}, ErrConflict
		}
	}
	if len(records) >= MaxRecords || countCustomer >= MaxCustomerRecords {
		return Record{}, ErrLimit
	}
	r := Record{Version: "tracebolt.customer-profile-record.v1", ManagerID: s.managerID, CustomerID: profile.CustomerID, ProfileID: profile.InstallerProfileID, PublicJSON: bytes.Clone(raw), Digest: digest(raw), CreatedAt: now, ExpiresAt: expiresAt}
	body, e := json.Marshal(r)
	if e != nil {
		return Record{}, ErrInvalid
	}
	if _, e = conn.ExecContext(ctx, `INSERT INTO customer_profiles_records(profile_id,body) VALUES(?,?)`, r.ProfileID, body); e != nil {
		return Record{}, ErrStorage
	}
	if _, e = conn.ExecContext(ctx, `UPDATE customer_profiles_meta SET count=?,last_at=? WHERE id=1`, len(records)+1, now); e != nil {
		return Record{}, ErrStorage
	}
	endTime, e := clockAt(clock, now)
	if e != nil || endTime >= expiresAt {
		return Record{}, ErrInvalid
	}
	if _, _, e = enrollmentclient.ParseCustomerProfile(raw, time.Unix(endTime, 0)); e != nil {
		return Record{}, ErrInactive
	}
	if customerschema.Validate(ctx, conn, schemaObjects()) != nil {
		return Record{}, ErrStorage
	}
	if e = lease.Check(); e != nil {
		return Record{}, e
	}
	finalTime, e := clockAt(clock, endTime)
	if e != nil || finalTime >= expiresAt || ctx.Err() != nil {
		return Record{}, ErrInactive
	}
	if _, _, e = enrollmentclient.ParseCustomerProfile(raw, time.Unix(finalTime, 0)); e != nil {
		return Record{}, ErrInactive
	}
	if _, e = conn.ExecContext(ctx, `UPDATE customer_profiles_meta SET last_at=? WHERE id=1`, finalTime); e != nil {
		return Record{}, ErrStorage
	}
	if _, e = conn.ExecContext(ctx, `COMMIT`); e != nil {
		return Record{}, ErrStorage
	}
	committed = true
	return r, nil
}

// Retire requires the exact reviewed public profile digest and an explicit
// acknowledgement. The authority lease is acquired after the profile lock and
// held through COMMIT. Expired profiles can still be explicitly retired.
func (s *Store) Retire(ctx context.Context, customerID, profileID, expectedDigest string, acknowledged bool, clock func() time.Time, acquire AcquireAuthority) (Record, error) {
	if !acknowledged || acquire == nil || !enrollmentcrypto.ValidID(customerID, "customer_") || !enrollmentcrypto.ValidID(profileID, "profile_") || !enrollmentcrypto.ValidHash(expectedDigest) {
		return Record{}, ErrInvalid
	}
	conn, records, last, e := start(ctx, s)
	if e != nil {
		return Record{}, e
	}
	var lease AuthorityLease
	committed := false
	defer func() {
		if lease != nil {
			lease.Release()
		}
	}()
	defer func() {
		if committed {
			_ = conn.Close()
		} else {
			end(conn)
		}
	}()
	now, e := clockAt(clock, last)
	if e != nil {
		return Record{}, e
	}
	lease, e = acquire(ctx, customerID, profileID)
	if e != nil {
		return Record{}, e
	}
	if lease == nil {
		return Record{}, ErrInvalid
	}
	if e = lease.Check(); e != nil {
		return Record{}, e
	}
	var r Record
	found := false
	for _, candidate := range records {
		if candidate.ProfileID == profileID {
			r = candidate
			found = true
			break
		}
	}
	if !found || r.CustomerID != customerID || r.Digest != expectedDigest || r.RetiredAt != 0 {
		return Record{}, ErrConflict
	}
	r.RetiredAt = now
	body, e := json.Marshal(r)
	if e != nil {
		return Record{}, ErrInvalid
	}
	if _, e = conn.ExecContext(ctx, `UPDATE customer_profiles_records SET body=? WHERE profile_id=?`, body, profileID); e != nil {
		return Record{}, ErrStorage
	}
	endTime, e := clockAt(clock, now)
	if e != nil {
		return Record{}, e
	}
	if customerschema.Validate(ctx, conn, schemaObjects()) != nil {
		return Record{}, ErrStorage
	}
	if e = lease.Check(); e != nil {
		return Record{}, e
	}
	finalTime, e := clockAt(clock, endTime)
	if e != nil || ctx.Err() != nil {
		return Record{}, ErrInvalid
	}
	if _, e = conn.ExecContext(ctx, `UPDATE customer_profiles_meta SET last_at=? WHERE id=1`, finalTime); e != nil {
		return Record{}, ErrStorage
	}
	if _, e = conn.ExecContext(ctx, `COMMIT`); e != nil {
		return Record{}, ErrStorage
	}
	committed = true
	return r, nil
}

// ActiveLease holds profile and operator authority, in that order. Check must
// be called immediately before the coordinator's durable claim commit. The
// coordinator must establish that profile, pending, enrollment and operator
// databases do not alias before obtaining any locks. This package alone cannot
// establish that property or prevent deadlocks across separately opened paths.
type ActiveLease struct {
	mu       sync.Mutex
	conn     *sql.Conn
	ctx      context.Context
	operator AuthorityLease
	clock    func() time.Time
	last     int64
	record   Record
}

func (l *ActiveLease) Check() error {
	if l == nil {
		return ErrInactive
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.checkLocked()
	return err
}

func (l *ActiveLease) checkLocked() (enrollmentclient.TrustDisplay, error) {
	if l.conn == nil || l.operator == nil || l.ctx == nil || l.ctx.Err() != nil {
		return enrollmentclient.TrustDisplay{}, ErrInactive
	}
	now, e := clockAt(l.clock, l.last)
	if e != nil || now < l.record.CreatedAt || now >= l.record.ExpiresAt {
		return enrollmentclient.TrustDisplay{}, ErrInactive
	}
	_, display, e := enrollmentclient.ParseCustomerProfile(l.record.PublicJSON, time.Unix(now, 0))
	if e != nil {
		return enrollmentclient.TrustDisplay{}, ErrInactive
	}
	if e = l.operator.Check(); e != nil {
		return enrollmentclient.TrustDisplay{}, e
	}
	finalTime, e := clockAt(l.clock, now)
	if e != nil || l.ctx.Err() != nil || finalTime >= l.record.ExpiresAt {
		return enrollmentclient.TrustDisplay{}, ErrInactive
	}
	_, display, e = enrollmentclient.ParseCustomerProfile(l.record.PublicJSON, time.Unix(finalTime, 0))
	if e != nil {
		return enrollmentclient.TrustDisplay{}, ErrInactive
	}
	l.last = finalTime
	return display, nil
}

// Snapshot returns the bound public bytes and validated issuer display, after
// a fresh Check. It is not a substitute for the final check before commit.
func (l *ActiveLease) Snapshot() (Record, enrollmentclient.TrustDisplay, error) {
	if l == nil {
		return Record{}, enrollmentclient.TrustDisplay{}, ErrInactive
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	d, e := l.checkLocked()
	if e != nil {
		return Record{}, enrollmentclient.TrustDisplay{}, e
	}
	r := l.record
	r.PublicJSON = bytes.Clone(r.PublicJSON)
	return r, d, nil
}

// Release is idempotent and releases the operator only after the profile
// transaction has been closed; it performs no profile mutation.
func (l *ActiveLease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	operator, conn := l.operator, l.conn
	l.operator, l.conn = nil, nil
	if operator != nil {
		defer operator.Release()
	}
	if conn != nil {
		end(conn)
	}
}

// AcquireActive holds profile exclusion until Release. acquire obtains the
// operator lease only after the profile transaction lock. Callers must close
// every returned lease even when nested work fails or has an uncertain result.
func (s *Store) AcquireActive(ctx context.Context, customerID, profileID string, clock func() time.Time, acquire AcquireAuthority) (*ActiveLease, error) {
	if acquire == nil || clock == nil || !enrollmentcrypto.ValidID(customerID, "customer_") || !enrollmentcrypto.ValidID(profileID, "profile_") {
		return nil, ErrInvalid
	}
	conn, records, last, e := start(ctx, s)
	if e != nil {
		return nil, e
	}
	l := &ActiveLease{conn: conn, ctx: ctx, clock: clock, last: last}
	handedOff := false
	defer func() {
		if !handedOff {
			l.Release()
		}
	}()
	now, e := clockAt(clock, last)
	if e != nil {
		return nil, e
	}
	found := false
	for _, r := range records {
		if r.ProfileID == profileID {
			l.record = r
			found = true
			break
		}
	}
	if !found || l.record.CustomerID != customerID || l.record.RetiredAt != 0 || now < l.record.CreatedAt || now >= l.record.ExpiresAt {
		e = ErrInactive
		return nil, e
	}
	l.last = now
	if _, _, e = enrollmentclient.ParseCustomerProfile(l.record.PublicJSON, time.Unix(now, 0)); e != nil {
		e = ErrInactive
		return nil, e
	}
	l.operator, e = acquire(ctx, customerID, profileID)
	if e != nil {
		return nil, e
	}
	if l.operator == nil {
		e = ErrInvalid
		return nil, e
	}
	if e = l.Check(); e != nil {
		return nil, e
	}
	handedOff = true
	return l, nil
}
