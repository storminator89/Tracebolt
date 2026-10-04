// Package enrollmentstore provides private Linux SQLite enrollment transactions.
// Every command restores a transaction-local trusted ledger while holding a
// SQLite BEGIN IMMEDIATE lock, validates and transitions it, persists credential
// and lifecycle state atomically, then returns only after COMMIT. There is no
// process-local authority cache. Operator calls are privileged internal calls;
// network authentication, signer custody and backup rollback recovery are not
// provided here. A valid older complete backup cannot be detected locally and
// must never be treated as transparent restoration of an existing live manager.
package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/lanstore"
	_ "modernc.org/sqlite"
)

var ErrStorage = errors.New("enrollment storage is unavailable or invalid")

const schemaVersion = 1
const maxCredentialBytes = 128 << 10
const maxDatabaseBytes = 192 << 20
const stateSchema = `CREATE TABLE enrollment_state(id INTEGER PRIMARY KEY CHECK(id=1), ledger BLOB NOT NULL CHECK(length(ledger)>0 AND length(ledger)<=16644096)) STRICT`
const credentialSchema = `CREATE TABLE enrollment_credentials(invitation_id TEXT PRIMARY KEY NOT NULL, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=131072)) STRICT`

type Store struct{ *storeState }
type storeState struct {
	db               *sql.DB
	path             string
	info             os.FileInfo
	config           enrollmentstate.Config
	issuerDER        []byte
	operationalReads chan struct{}
	inventoryCalls   chan struct{}
}

func (Store) String() string               { return "enrollmentstore.Store{contents:redacted}" }
func (Store) GoString() string             { return "enrollmentstore.Store{contents:redacted}" }
func (s Store) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (Store) MarshalJSON() ([]byte, error) { return []byte(`{"contentsRedacted":true}`), nil }

type Delivery struct {
	RequestID string `json:"requestID"`
	FirstAt   int64  `json:"firstAt"`
	LastAt    int64  `json:"lastAt"`
	Count     uint64 `json:"count"`
}
type Replay struct {
	Sequence    uint64    `json:"sequence"`
	PayloadHash string    `json:"payloadHash"`
	GeneratedAt time.Time `json:"generatedAt"`
	CollectedAt time.Time `json:"collectedAt"`
	ReceivedAt  time.Time `json:"receivedAt"`
}
type credential struct {
	DER      []byte   `json:"der"`
	Delivery Delivery `json:"delivery"`
	Replay   Replay   `json:"replay"`
	Frame    []byte   `json:"frame"`
}
type transaction struct {
	conn                *sql.Conn
	engine              *enrollmentstate.Engine
	credentials         map[string]credential
	originalLedger      []byte
	originalCredentials map[string][]byte
	operational         map[string]operationalRecord
	originalOperational map[string][]byte
	validatedFrames     map[frameValidationKey]lanstore.Frame
	inventory           map[string]inventoryRecord
	originalInventory   map[string][]byte
	inventoryKey        inventoryledger.CursorKey
	system              map[string]systemRecord
}

// Open rejects existing insecure paths; it never chmods or adopts them. The
// issuer is public preprovided DER, not a signing key. Config changes are refused
// on reopen, including the manager instance, origins, issuer and quotas.
func Open(path string, config enrollmentstate.Config, issuerDER []byte) (*Store, error) {
	if runtime.GOOS != "linux" || validateIssuer(config, issuerDER) != nil || (enrollmentcrypto.ManagedCollectionProfile(config.Binding.CollectionProfile) && config.RecordLimit > 25) {
		return nil, ErrStorage
	}
	engine, err := enrollmentstate.New(config)
	if err != nil {
		return nil, err
	}
	absolute, err := safePath(path)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0700); err != nil {
		return nil, ErrStorage
	}
	if err = privateStateDirectory(filepath.Dir(absolute)); err != nil {
		return nil, err
	}
	if err = checkFilesForProfile(absolute, config.Binding.CollectionProfile); err != nil {
		return nil, err
	}
	created := false
	file, err := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		created = true
		if file.Close() != nil {
			return nil, ErrStorage
		}
	} else if !os.IsExist(err) {
		return nil, ErrStorage
	}
	info, err := os.Lstat(absolute)
	if err != nil || info.Size() > databaseCap(config.Binding.CollectionProfile) {
		return nil, ErrStorage
	}
	if !created {
		if info.Size() == 0 {
			return nil, ErrStorage
		}
		candidate := &Store{&storeState{path: absolute, info: info, config: config, issuerDER: bytes.Clone(issuerDER), operationalReads: make(chan struct{}, 1), inventoryCalls: make(chan struct{}, 1)}}
		if candidate.preflightExisting() != nil {
			return nil, ErrStorage
		}
	}
	u := url.URL{Scheme: "file", Path: absolute}
	q := u.Query()
	q.Set("mode", "rw")
	q.Set("_pragma", "busy_timeout(5000)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, ErrStorage
	}
	db.SetMaxOpenConns(1)
	s := &Store{&storeState{db: db, path: absolute, info: info, config: config, issuerDER: bytes.Clone(issuerDER), operationalReads: make(chan struct{}, 1), inventoryCalls: make(chan struct{}, 1)}}
	fail := func() (*Store, error) { db.Close(); return nil, ErrStorage }
	pragmas := []string{"PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON", "PRAGMA trusted_schema=OFF", "PRAGMA max_page_count=49152"}
	if completeProfile(config.Binding.CollectionProfile) {
		pragmas[len(pragmas)-1] = "PRAGMA max_page_count=131072"
		pragmas = append(pragmas, "PRAGMA cache_spill=OFF")
	}
	for _, query := range pragmas {
		if _, err = db.Exec(query); err != nil {
			return fail()
		}
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		return fail()
	}
	if _, err = conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		conn.Close()
		return fail()
	}
	rollback := func() { conn.ExecContext(context.Background(), "ROLLBACK"); conn.Close() }
	var version int
	if conn.QueryRowContext(context.Background(), "PRAGMA user_version").Scan(&version) != nil {
		rollback()
		return fail()
	}
	if created && version == 0 {
		var count int
		if conn.QueryRowContext(context.Background(), "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&count) != nil || count != 0 {
			rollback()
			return fail()
		}
		queries := []string{stateSchema, credentialSchema, `PRAGMA user_version=1`}
		if enrollmentcrypto.ManagedCollectionProfile(config.Binding.CollectionProfile) {
			queries = []string{stateSchema, credentialSchema, operationalSchema, `PRAGMA user_version=2`}
		}
		for _, query := range queries {
			if _, err = conn.ExecContext(context.Background(), query); err != nil {
				rollback()
				return fail()
			}
		}
		if completeProfile(config.Binding.CollectionProfile) {
			if initializeInventory(context.Background(), conn) != nil || initializeSystemObservations(context.Background(), conn) != nil {
				rollback()
				return fail()
			}
			if _, err = conn.ExecContext(context.Background(), "PRAGMA user_version=3"); err != nil {
				rollback()
				return fail()
			}
		}
		raw, _ := engine.EncodeTrustedLedger()
		if _, err = conn.ExecContext(context.Background(), "INSERT INTO enrollment_state(id,ledger) VALUES(1,?)", raw); err != nil {
			rollback()
			return fail()
		}
	} else if version != storeSchemaVersion(config.Binding.CollectionProfile) {
		rollback()
		return fail()
	}
	if validateSchema(context.Background(), conn, s.config.Binding.CollectionProfile) != nil {
		rollback()
		return fail()
	}
	var integrity string
	if conn.QueryRowContext(context.Background(), "PRAGMA quick_check").Scan(&integrity) != nil || integrity != "ok" {
		rollback()
		return fail()
	}
	if _, err = s.load(context.Background(), conn); err != nil {
		rollback()
		return fail()
	}
	if s.checkPath() != nil {
		rollback()
		return fail()
	}
	if completeProfile(s.config.Binding.CollectionProfile) && s.inventoryCapacityBeforeCommit(context.Background(), conn) != nil {
		rollback()
		return fail()
	}
	if _, err = conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		rollback()
		return fail()
	}
	conn.Close()
	if s.checkPath() != nil {
		return fail()
	}
	if created {
		dir, e := os.Open(filepath.Dir(absolute))
		if e != nil {
			return fail()
		}
		e = dir.Sync()
		dir.Close()
		if e != nil {
			return fail()
		}
	}
	return s, nil
}
func validateIssuer(config enrollmentstate.Config, der []byte) error {
	if len(der) == 0 || len(der) > enrollmentcrypto.MaxCertificateBytes {
		return ErrStorage
	}
	sum := sha256.Sum256(der)
	if hex.EncodeToString(sum[:]) != config.Binding.IssuerFingerprint {
		return ErrStorage
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return ErrStorage
	}
	k, ok := c.PublicKey.(ed25519.PublicKey)
	if !ok || !keyvalidation.Ed25519(k) || !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || !c.MaxPathLenZero || c.KeyUsage&x509.KeyUsageCertSign == 0 || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(c.UnknownExtKeyUsage) != 0 || len(c.UnhandledCriticalExtensions) != 0 {
		return ErrStorage
	}
	return nil
}
func safePath(path string) (string, error) {
	if path == "" {
		return "", ErrStorage
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", ErrStorage
	}
	for current := absolute; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", ErrStorage
			}
		} else if !os.IsNotExist(err) {
			return "", ErrStorage
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return absolute, nil
}
func checkFiles(path string) error { return checkFilesForProfile(path, "") }
func checkFilesForProfile(path, profile string) error {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if err := privateStateFile(path + suffix); err != nil {
			return err
		}
		if info, err := os.Lstat(path + suffix); err == nil && info.Size() > sidecarCap(profile, suffix) {
			return ErrStorage
		}
	}
	return nil
}
func (s *Store) checkPath() error {
	if s == nil || s.storeState == nil || privateStateDirectory(filepath.Dir(s.path)) != nil || checkFilesForProfile(s.path, s.config.Binding.CollectionProfile) != nil {
		return ErrStorage
	}
	info, err := os.Lstat(s.path)
	if err != nil || !os.SameFile(s.info, info) {
		return ErrStorage
	}
	return nil
}
func (s *Store) Close() error {
	if s == nil || s.storeState == nil {
		return ErrStorage
	}
	return s.db.Close()
}
func storageError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrStorage
}

func (s *Store) load(ctx context.Context, conn *sql.Conn) (*transaction, error) {
	if validateSchema(ctx, conn, s.config.Binding.CollectionProfile) != nil {
		return nil, ErrStorage
	}
	var count, n int
	if conn.QueryRowContext(ctx, "SELECT count(*),coalesce(max(length(ledger)),0) FROM enrollment_state").Scan(&count, &n) != nil || count != 1 || n <= 0 || n > enrollmentstate.MaxTrustedLedgerBytes {
		return nil, ErrStorage
	}
	var raw []byte
	if conn.QueryRowContext(ctx, "SELECT ledger FROM enrollment_state WHERE id=1").Scan(&raw) != nil {
		return nil, ErrStorage
	}
	engine, err := enrollmentstate.RestoreTrustedLedger(s.config, raw)
	if err != nil {
		return nil, ErrStorage
	}
	t := &transaction{conn: conn, engine: engine, credentials: make(map[string]credential), originalLedger: raw, originalCredentials: make(map[string][]byte), operational: map[string]operationalRecord{}, originalOperational: map[string][]byte{}, inventory: map[string]inventoryRecord{}, originalInventory: map[string][]byte{}}
	if conn.QueryRowContext(ctx, "SELECT count(*),coalesce(max(length(body)),0) FROM enrollment_credentials").Scan(&count, &n) != nil || count > s.config.RecordLimit || n > maxCredentialBytes {
		return nil, ErrStorage
	}
	rows, err := conn.QueryContext(ctx, "SELECT invitation_id,body FROM enrollment_credentials ORDER BY invitation_id")
	if err != nil {
		return nil, ErrStorage
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var body []byte
		if rows.Scan(&id, &body) != nil || len(body) == 0 || len(body) > maxCredentialBytes {
			return nil, ErrStorage
		}
		var c credential
		if json.Unmarshal(body, &c) != nil {
			return nil, ErrStorage
		}
		canonical, err := json.Marshal(c)
		if err != nil || !bytes.Equal(canonical, body) {
			return nil, ErrStorage
		}
		snapshot, err := engine.Get(id)
		if err != nil || snapshot.Issuance.CertificateHash == "" {
			return nil, ErrStorage
		}
		intent, err := engine.TrustedRecordedIntent(id)
		if err != nil {
			return nil, ErrStorage
		}
		cert, err := enrollmentcrypto.VerifyIssued(c.DER, s.issuerDER, intent, time.Unix(snapshot.Issuance.At, 0))
		if err != nil || cert.CertificateHash() != snapshot.Issuance.CertificateHash || !t.validMetadata(snapshot, c) {
			return nil, ErrStorage
		}
		t.credentials[id] = c
		t.originalCredentials[id] = body
	}
	if rows.Err() != nil {
		return nil, ErrStorage
	}
	for _, snapshot := range engine.Snapshots() {
		_, ok := t.credentials[snapshot.InvitationID]
		if ok != (snapshot.Issuance.CertificateHash != "") {
			return nil, ErrStorage
		}
	}
	if err = s.loadOperational(ctx, t); err != nil {
		return nil, ErrStorage
	}
	if err = s.loadInventory(ctx, t); err != nil {
		return nil, ErrStorage
	}
	if err = s.loadSystemMetadata(ctx, t); err != nil {
		return nil, ErrStorage
	}
	return t, nil
}
func (t *transaction) validMetadata(s enrollmentstate.Snapshot, c credential) bool {
	d := c.Delivery
	if d != (Delivery{}) && (!enrollmentcrypto.ValidID(d.RequestID, "request_") || d.Count == 0 || d.Count > enrollmentstate.MaxRevision || d.FirstAt < s.Issuance.At || d.LastAt < d.FirstAt || d.LastAt >= s.Intent.NotAfter) {
		return false
	}
	if s.Termination.At != 0 && d.LastAt > s.Termination.At {
		return false
	}
	r := c.Replay
	if r == (Replay{}) {
		return len(c.Frame) == 0
	}
	if s.Activation == (enrollmentstate.Activation{}) || r.Sequence == 0 || r.Sequence > enrollmentstate.MaxRevision || !enrollmentcrypto.ValidHash(r.PayloadHash) || r.ReceivedAt.Unix() < s.Activation.At || r.ReceivedAt.Unix() >= s.Intent.NotAfter || !validStoreTime(r.GeneratedAt) || !validStoreTime(r.CollectedAt) || !validStoreTime(r.ReceivedAt) {
		return false
	}
	if s.Termination.At != 0 && r.ReceivedAt.Unix() > s.Termination.At {
		return false
	}
	frame, err := t.validateFrame(c.Frame, r.ReceivedAt)
	sum := sha256.Sum256(c.Frame)
	if err != nil || !lanstore.FrameMatchesCollectionProfile(frame, s.Binding.CollectionProfile) || frame.Observation.Observation.Platform != s.Platform || hex.EncodeToString(sum[:]) != r.PayloadHash || frame.Sequence != r.Sequence || !frame.Observation.GeneratedAt.Equal(r.GeneratedAt) || !frame.Observation.Observation.LastSeen.Equal(r.CollectedAt) {
		return false
	}

	return true
}
func (s *Store) transact(ctx context.Context, action func(*transaction) error) error {
	if ctx == nil {
		return enrollmentstate.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.checkPath() != nil {
		return ErrStorage
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return storageError(ctx)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return beginError(ctx, err)
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	t, err := s.load(ctx, conn)
	if err != nil {
		return storageError(ctx)
	}
	if completeProfile(s.config.Binding.CollectionProfile) && s.configureInventoryConnection(ctx, conn) != nil {
		return storageError(ctx)
	}
	if err = action(t); err != nil {
		return err
	}
	for id, c := range t.credentials {
		snapshot, err := t.engine.Get(id)
		if err != nil || !t.validMetadata(snapshot, c) {
			return enrollmentstate.ErrInvalid
		}
	}
	raw, err := t.engine.EncodeTrustedLedger()
	if err != nil {
		return ErrStorage
	}
	if !bytes.Equal(raw, t.originalLedger) {
		if _, err = conn.ExecContext(ctx, "UPDATE enrollment_state SET ledger=? WHERE id=1", raw); err != nil {
			return storageError(ctx)
		}
	}
	for id, c := range t.credentials {
		body, err := json.Marshal(c)
		if err != nil || len(body) > maxCredentialBytes {
			return ErrStorage
		}
		if bytes.Equal(body, t.originalCredentials[id]) {
			continue
		}
		if _, err = conn.ExecContext(ctx, "INSERT INTO enrollment_credentials(invitation_id,body) VALUES(?,?) ON CONFLICT(invitation_id) DO UPDATE SET body=excluded.body", id, body); err != nil {
			return storageError(ctx)
		}
	}
	if err = s.saveOperational(ctx, t); err != nil {
		return storageError(ctx)
	}
	if err = s.saveInventory(ctx, t); err != nil {
		return storageError(ctx)
	}
	if validateSystemRecords(t) != nil {
		return ErrStorage
	}
	if s.checkPath() != nil {
		return ErrStorage
	}
	if completeProfile(s.config.Binding.CollectionProfile) && s.inventoryCapacityBeforeCommit(ctx, conn) != nil {
		return storageError(ctx)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return storageError(ctx)
	}
	return nil
}

func validateSchema(ctx context.Context, conn *sql.Conn, profile string) error {
	var version int
	if conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version) != nil || version != storeSchemaVersion(profile) {
		return ErrStorage
	}
	expected := map[string]inventoryledger.SchemaObject{
		"enrollment_state":       {Type: "table", Name: "enrollment_state", SQL: stateSchema},
		"enrollment_credentials": {Type: "table", Name: "enrollment_credentials", SQL: credentialSchema},
	}
	if enrollmentcrypto.ManagedCollectionProfile(profile) {
		expected["enrollment_operational"] = inventoryledger.SchemaObject{Type: "table", Name: "enrollment_operational", SQL: operationalSchema}
	}
	if completeProfile(profile) {
		expected["enrollment_inventory_meta"] = inventoryledger.SchemaObject{Type: "table", Name: "enrollment_inventory_meta", SQL: inventoryMetaSchema}
		expected["enrollment_inventory_authority"] = inventoryledger.SchemaObject{Type: "table", Name: "enrollment_inventory_authority", SQL: inventoryAuthoritySchema}
		expected["enrollment_inventory_generations"] = inventoryledger.SchemaObject{Type: "table", Name: "enrollment_inventory_generations", SQL: inventoryGenerationsSchema}
		for _, obj := range systemSchemaObjects() {
			expected[obj.Name] = obj
		}
		for _, obj := range inventoryledger.SchemaObjects() {
			expected[obj.Name] = obj
		}
	}
	rows, e := conn.QueryContext(ctx, "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
	if e != nil {
		return ErrStorage
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var kind, name, definition string
		if rows.Scan(&kind, &name, &definition) != nil {
			return ErrStorage
		}
		obj, ok := expected[name]
		if !ok || kind != obj.Type || definition != obj.SQL {
			return ErrStorage
		}
		count++
	}
	if rows.Err() != nil || count != len(expected) {
		return ErrStorage
	}
	return nil
}

// preflightExisting must precede every mutable SQLite pragma. Closed WAL-mode
// databases without a WAL are read immutably to avoid creating empty sidecars.
// Live WAL stores require their existing protected index; missing sidecars are
// treated as an incomplete store, not permission to repair unknown data.
func (s *Store) preflightExisting() error {
	u := url.URL{Scheme: "file", Path: s.path}
	q := u.Query()
	q.Set("mode", "ro")
	wal, err := os.Lstat(s.path + "-wal")
	if os.IsNotExist(err) {
		q.Set("immutable", "1")
	} else if err != nil || !wal.Mode().IsRegular() {
		return ErrStorage
	} else {
		if _, err = os.Lstat(s.path + "-shm"); err != nil {
			return ErrStorage
		}
	}
	q.Set("_pragma", "busy_timeout(5000)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return ErrStorage
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(context.Background())
	if err != nil {
		return ErrStorage
	}
	defer conn.Close()
	if _, err = conn.ExecContext(context.Background(), "PRAGMA trusted_schema=OFF"); err != nil {
		return ErrStorage
	}
	if _, err = conn.ExecContext(context.Background(), "BEGIN"); err != nil {
		return ErrStorage
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	if validateSchema(context.Background(), conn, s.config.Binding.CollectionProfile) != nil {
		return ErrStorage
	}
	var integrity string
	if conn.QueryRowContext(context.Background(), "PRAGMA quick_check").Scan(&integrity) != nil || integrity != "ok" {
		return ErrStorage
	}
	if _, err = s.load(context.Background(), conn); err != nil {
		return ErrStorage
	}
	if completeProfile(s.config.Binding.CollectionProfile) && s.inventoryReadOnlyCapacity(context.Background(), conn) != nil {
		return ErrStorage
	}
	return s.checkPath()
}

func storeSchemaVersion(profile string) int {
	if completeProfile(profile) {
		return 3
	}
	if enrollmentcrypto.ManagedCollectionProfile(profile) {
		return 2
	}
	return schemaVersion
}
