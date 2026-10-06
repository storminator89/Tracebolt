package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"localrmm/internal/actionjob"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/keyvalidation"
)

// SQLite shares WAL-index mappings inside a process. readonly_shm cannot make
// an existing writable mapping read-only, so in-process writers must never be
// paired with the planner. Independent planner processes can inspect live WALs.
var serviceActionInspectionWriters = struct {
	sync.Mutex
	paths map[string]int
}{paths: map[string]int{}}

var ErrServiceActionInspectionBusy = errors.New("service-action read-only inspection requires a separate process or closed local store")

func registerServiceActionWriter(path string) func() {
	serviceActionInspectionWriters.Lock()
	serviceActionInspectionWriters.paths[path]++
	serviceActionInspectionWriters.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			serviceActionInspectionWriters.Lock()
			defer serviceActionInspectionWriters.Unlock()
			serviceActionInspectionWriters.paths[path]--
			if serviceActionInspectionWriters.paths[path] == 0 {
				delete(serviceActionInspectionWriters.paths, path)
			}
		})
	}
}

const serviceActionSetupMarkerVersion = "tracebolt.service-action-setup-marker.v1"

// serviceActionSetupMarker is part of the existing canonical credential record,
// not a separately recoverable sidecar. It survives missing action tables/rows.
// The fenced row reciprocally binds its digest, distinguishing legacy records.
type serviceActionSetupMarker struct {
	Version           string    `json:"version"`
	ManagerID         string    `json:"managerId"`
	DeviceID          string    `json:"deviceId"`
	IncarnationDigest string    `json:"incarnationDigest"`
	KeyID             string    `json:"keyId"`
	InitializedAt     time.Time `json:"initializedAt"`
}

func (m serviceActionSetupMarker) digest() string {
	body, _ := json.Marshal(m)
	return actionpermit.Digest(body)
}
func validServiceActionSetupMarker(s enrollmentstate.Snapshot, m *serviceActionSetupMarker) bool {
	if m == nil {
		return true
	}
	return completeProfile(s.Binding.CollectionProfile) && s.Platform == "linux" && s.Activation.At != 0 &&
		m.Version == serviceActionSetupMarkerVersion && m.ManagerID == s.Binding.InstanceID &&
		m.DeviceID == s.Approval.DeviceID && m.IncarnationDigest == "sha256:"+s.Issuance.CertificateHash &&
		actionpermit.ValidDigest(m.KeyID) && actionjob.ValidTime(m.InitializedAt) &&
		m.InitializedAt.Unix() >= s.Activation.At && m.InitializedAt.Unix() >= s.Intent.NotBefore &&
		m.InitializedAt.Unix() < s.Intent.NotAfter && (s.Termination.At == 0 || m.InitializedAt.Unix() <= s.Termination.At)
}

// ServiceActionSetupStatus describes the entire manager action domain, not only
// the selected endpoint. Existing legacy/fenced domains cannot be adopted by
// create-only setup. Invalid or incomplete domains return ErrStorage instead.
type ServiceActionSetupStatus string

const (
	ServiceActionSetupAbsent ServiceActionSetupStatus = "absent"
	ServiceActionSetupLegacy ServiceActionSetupStatus = "legacy"
	ServiceActionSetupFenced ServiceActionSetupStatus = "fenced"
)

type ServiceActionSetupInspection struct {
	Config    enrollmentstate.Config
	Identity  enrollmentstate.Snapshot
	Status    ServiceActionSetupStatus
	PublicKey ed25519.PublicKey
}

// SetupServiceActionsCreateOnly is the separately authorized provisioning seam.
// It atomically commits the new schema, key, first identity row and immutable
// credential marker. It never adopts an existing domain or repairs missing live
// state, even when the key/identity match. Runtime startup must not call it.
func (s *Store) SetupServiceActionsCreateOnly(ctx context.Context, key ed25519.PublicKey, device, incarnationDigest string, now time.Time) error {
	if !keyvalidation.Ed25519(key) || !actionpermit.ValidDigest(incarnationDigest) || !actionjob.ValidTime(now) {
		return actionjob.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error {
		return s.setupServiceActionsCreateOnly(ctx, t, key, device, incarnationDigest, now)
	})
}

func (s *Store) setupServiceActionsCreateOnly(ctx context.Context, t *transaction, key ed25519.PublicKey, device, incarnationDigest string, now time.Time) error {
	present, err := serviceActionSchemaPresent(ctx, t.conn)
	if err != nil {
		return err
	}
	if present {
		return enrollmentstate.ErrConflict
	}
	for _, c := range t.credentials {
		if c.ServiceActionSetup != nil {
			return ErrStorage
		}
	}
	snap, err := systemDevice(t, device)
	if err != nil {
		return err
	}
	if incarnationDigest != "sha256:"+snap.Issuance.CertificateHash {
		return enrollmentstate.ErrProof
	}
	if _, err = s.systemAuthority(t, snap.InvitationID, snap.Issuance.CertificateHash, now); err != nil {
		return err
	}
	r, err := actionjob.New(s.config.Binding.InstanceID, device, incarnationDigest, key, now)
	if err != nil {
		return err
	}
	marker := &serviceActionSetupMarker{Version: serviceActionSetupMarkerVersion, ManagerID: r.ManagerID, DeviceID: r.DeviceID, IncarnationDigest: r.IncarnationDigest, KeyID: actionpermit.Digest(key), InitializedAt: now}
	if !validServiceActionSetupMarker(snap, marker) {
		return ErrStorage
	}
	for _, object := range serviceActionFencedSchemaObjects() {
		if _, err = t.conn.ExecContext(ctx, object.SQL); err != nil {
			return ErrStorage
		}
	}
	if _, err = t.conn.ExecContext(ctx, `INSERT INTO enrollment_service_action_meta VALUES(1,?)`, []byte(key)); err != nil {
		return ErrStorage
	}
	body, _ := json.Marshal(r)
	if _, err = t.conn.ExecContext(ctx, `INSERT INTO enrollment_service_action_records(invitation_id,body,setup_fence) VALUES(?,?,?)`, snap.InvitationID, body, marker.digest()); err != nil {
		return ErrStorage
	}
	credential := t.credentials[snap.InvitationID]
	credential.ServiceActionSetup = marker
	t.credentials[snap.InvitationID] = credential
	return nil
}

// InspectServiceActionSetup validates the existing database and selected live
// complete-profile Linux identity without Open, BEGIN IMMEDIATE, schema changes,
// checkpoints, leases or application writes. No missing database/sidecar is
// created. A live WAL requires its already existing protected shared index;
// closed databases without a WAL use immutable read-only SQLite access. A
// Store already open in this process is refused because SQLite would reuse its
// writable WAL-index mapping despite readonly_shm. Run the planner separately.
func InspectServiceActionSetup(ctx context.Context, path string, issuerDER []byte, device string, now time.Time) (ServiceActionSetupInspection, error) {
	zero := ServiceActionSetupInspection{}
	if ctx == nil || runtime.GOOS != "linux" {
		return zero, ErrStorage
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	absolute, err := safePath(path)
	if err != nil || privateStateDirectory(filepath.Dir(absolute)) != nil || checkFilesForProfile(absolute, enrollmentcrypto.CollectionProfileComplete) != nil {
		return zero, ErrStorage
	}
	serviceActionInspectionWriters.Lock()
	defer serviceActionInspectionWriters.Unlock()
	if serviceActionInspectionWriters.paths[absolute] != 0 {
		return zero, ErrServiceActionInspectionBusy
	}
	info, err := os.Lstat(absolute)
	if err != nil || info.Size() <= 0 || info.Size() > databaseCap(enrollmentcrypto.CollectionProfileComplete) {
		return zero, ErrStorage
	}
	u := url.URL{Scheme: "file", Path: absolute}
	q := u.Query()
	q.Set("mode", "ro")
	// This SQLite URI option forces a genuinely read-only WAL-index mapping.
	// mode=ro alone still permits changing SHM read marks.
	q.Set("readonly_shm", "1")
	immutable := false
	wal, err := os.Lstat(absolute + "-wal")
	if os.IsNotExist(err) {
		// A rollback journal requires recovery rather than a potentially stale
		// immutable read. No recovery is performed by planning.
		if _, journalErr := os.Lstat(absolute + "-journal"); !os.IsNotExist(journalErr) {
			return zero, ErrStorage
		}
		q.Set("immutable", "1")
		immutable = true
	} else if err != nil || !wal.Mode().IsRegular() {
		return zero, ErrStorage
	} else if _, err = os.Lstat(absolute + "-shm"); err != nil {
		return zero, ErrStorage
	}
	q.Set("_pragma", "busy_timeout(5000)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return zero, ErrStorage
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return zero, storageError(ctx)
	}
	defer conn.Close()
	for _, query := range []string{"PRAGMA query_only=ON", "PRAGMA trusted_schema=OFF", "BEGIN"} {
		if _, err = conn.ExecContext(ctx, query); err != nil {
			return zero, storageError(ctx)
		}
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	var size int
	if conn.QueryRowContext(ctx, `SELECT length(ledger) FROM enrollment_state WHERE id=1`).Scan(&size) != nil || size <= 0 || size > enrollmentstate.MaxTrustedLedgerBytes {
		return zero, ErrStorage
	}
	var raw []byte
	if conn.QueryRowContext(ctx, `SELECT ledger FROM enrollment_state WHERE id=1`).Scan(&raw) != nil {
		return zero, ErrStorage
	}
	config, err := enrollmentstate.TrustedLedgerConfig(raw)
	if err != nil || !completeProfile(config.Binding.CollectionProfile) || config.RecordLimit > 25 || validateIssuer(config, issuerDER) != nil {
		return zero, ErrStorage
	}
	s := &Store{&storeState{db: db, path: absolute, info: info, config: config, issuerDER: bytes.Clone(issuerDER)}}
	if s.checkPath() != nil {
		return zero, ErrStorage
	}
	var integrity string
	if conn.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity) != nil || integrity != "ok" {
		return zero, ErrStorage
	}
	t, err := s.load(ctx, conn)
	if err != nil || s.inventoryReadOnlyCapacity(ctx, conn) != nil {
		return zero, storageError(ctx)
	}
	snap, err := systemDevice(t, device)
	if err != nil {
		return zero, err
	}
	if _, err = s.systemAuthority(t, snap.InvitationID, snap.Issuance.CertificateHash, now); err != nil {
		return zero, err
	}
	out := ServiceActionSetupInspection{Config: config, Identity: snap, Status: ServiceActionSetupAbsent}
	present, err := serviceActionSchemaPresent(ctx, conn)
	if err != nil {
		return zero, err
	}
	if present {
		fenced, err := serviceActionFenced(ctx, conn)
		if err != nil || conn.QueryRowContext(ctx, `SELECT public_key FROM enrollment_service_action_meta WHERE id=1`).Scan(&out.PublicKey) != nil {
			return zero, ErrStorage
		}
		out.Status = ServiceActionSetupLegacy
		if fenced {
			out.Status = ServiceActionSetupFenced
		}
	}
	if s.checkPath() != nil {
		return zero, ErrStorage
	}
	if immutable {
		current, err := os.Lstat(absolute)
		if err != nil || current.Size() != info.Size() || !current.ModTime().Equal(info.ModTime()) {
			return zero, ErrStorage
		}
		for _, suffix := range []string{"-wal", "-journal"} {
			if _, err := os.Lstat(absolute + suffix); !os.IsNotExist(err) {
				return zero, ErrStorage
			}
		}
	}
	return out, nil
}
