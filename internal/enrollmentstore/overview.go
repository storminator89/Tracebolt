package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewledger"
	"localrmm/internal/overviewwire"
)

// Complete overview is an explicitly initialized, checked add-only extension
// of the current authority schema. These rejection ceilings are not a promise
// that every maximum-size pure-contract generation fits.
const overviewMetaSchema = `CREATE TABLE enrollment_overview_meta(id INTEGER PRIMARY KEY CHECK(id=1),cursor_key BLOB NOT NULL CHECK(length(cursor_key)=32)) STRICT`
const overviewAuthoritySchema = `CREATE TABLE enrollment_overview_authority(invitation_id TEXT NOT NULL REFERENCES enrollment_credentials(invitation_id),section TEXT NOT NULL CHECK(section IN ('processes','volumes')),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=8192),PRIMARY KEY(invitation_id,section)) STRICT`

const overviewGenerationsSchema = `CREATE TABLE enrollment_overview_generations(device TEXT NOT NULL,generation TEXT NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>0),manifest_hash TEXT NOT NULL CHECK(length(manifest_hash)=64),PRIMARY KEY(device,generation)) STRICT`

var ErrOverviewBusy = ErrInventoryBusy
var ErrOverviewNotConfigured = errors.New("complete overview storage is not initialized")

func overviewLimits() overviewledger.Limits {
	l := overviewledger.DefaultLimits()
	l.GenerationBytes = 48 << 20
	l.DeviceBytes = 96 << 20
	l.GlobalBytes = 128 << 20
	l.DeviceRows = 98304
	l.GlobalRows = 400000
	l.DeviceChunks = 2048
	l.GlobalChunks = 4096
	l.DeviceGenerations = 18
	l.GlobalGenerations = 75
	return l
}

func overviewLedger() *overviewledger.Ledger {
	l, _ := overviewledger.New(overviewLimits())
	return l
}

// OverviewBinding is a separate replay domain from telemetry. The transport
// must prove possession and bind this exact tuple to its purpose/body. It never
// supplies device identity or overrides the authority read inside the write.
type OverviewBinding struct {
	Section      string `json:"section"`
	Sequence     uint64 `json:"sequence"`
	GenerationID string `json:"generationId"`
	ManifestHash string `json:"manifestHash"`
}

func (b OverviewBinding) valid() bool {
	return validOverviewSection(b.Section) && b.Sequence > 0 && b.Sequence <= enrollmentstate.MaxRevision && enrollmentcrypto.ValidID(b.GenerationID, "sample_") && enrollmentcrypto.ValidHash(b.ManifestHash)
}

type OverviewFailureReport struct {
	Section      string    `json:"section"`
	Sequence     uint64    `json:"sequence"`
	GenerationID string    `json:"generationId"`
	AttemptedAt  time.Time `json:"attemptedAt"`
	Reason       string    `json:"reason"`
}
type OverviewFailureReceipt struct {
	Failure    OverviewFailureReport
	ReceivedAt time.Time
}

func (f OverviewFailureReport) valid() bool {
	if !validOverviewSection(f.Section) || f.Sequence == 0 || f.Sequence > enrollmentstate.MaxRevision || !enrollmentcrypto.ValidID(f.GenerationID, "sample_") || !validStoreTime(f.AttemptedAt) || f.AttemptedAt.Location() != time.UTC {
		return false
	}
	return overviewwire.ValidFailureReason(f.Reason)
}

type overviewRecord struct {
	Binding       OverviewBinding              `json:"binding"`
	Manifest      *overviewgeneration.Manifest `json:"manifest"`
	Failure       *OverviewFailureReport       `json:"failure"`
	State         string                       `json:"state"`
	StartedAt     time.Time                    `json:"startedAt"`
	CompletedAt   time.Time                    `json:"completedAt"`
	LastAt        time.Time                    `json:"lastAt"`
	MaintenanceAt *time.Time                   `json:"maintenanceAt,omitempty"`
}

// OverviewSectionStatus separates the retained complete generation from the latest
// transfer. Complete may be expired metadata. A failed/expired transfer cannot
// erase it or imply a successful zero-row overview.
type OverviewPageResult struct {
	overviewledger.PageResult
	Binding   OverviewBinding
	ServerNow time.Time
	boundary  overviewOutputBoundary
}
type OverviewStatus struct {
	boundary  overviewOutputBoundary
	DeviceID  string
	ServerNow time.Time
	Processes OverviewSectionStatus
	Volumes   OverviewSectionStatus
}

type OverviewSectionStatus struct {
	Section         string
	CompleteBinding OverviewBinding
	DeviceID        string
	ServerNow       time.Time
	Sequence        uint64
	Complete        *overviewledger.GenerationStatus
	Transfer        *overviewledger.GenerationStatus
	Failure         *OverviewFailureReceipt
}

func initializeOverview(ctx context.Context, conn *sql.Conn) error {
	for _, q := range []string{overviewMetaSchema, overviewAuthoritySchema, overviewGenerationsSchema} {
		if _, e := conn.ExecContext(ctx, q); e != nil {
			return ErrStorage
		}
	}
	var key [32]byte
	if _, e := rand.Read(key[:]); e != nil {
		return ErrStorage
	}
	if _, e := conn.ExecContext(ctx, `INSERT INTO enrollment_overview_meta VALUES(1,?)`, key[:]); e != nil {
		return ErrStorage
	}
	return overviewLedger().Initialize(ctx, conn)
}
func (s *Store) loadOverview(ctx context.Context, t *transaction) error {
	if !completeProfile(s.config.Binding.CollectionProfile) {
		return nil
	}
	enabled, e := overviewSchemaPresent(ctx, t.conn)
	if e != nil {
		return e
	}
	t.overviewEnabled = enabled
	if !enabled {
		return nil
	}
	if overviewLedger().Check(ctx, t.conn) != nil {
		return ErrStorage
	}
	var rawKey []byte
	if t.conn.QueryRowContext(ctx, `SELECT cursor_key FROM enrollment_overview_meta WHERE id=1`).Scan(&rawKey) != nil || len(rawKey) != 32 {
		return ErrStorage
	}
	var key [32]byte
	copy(key[:], rawKey)
	t.overviewKey, e = overviewledger.NewCursorKey(key)
	if e != nil {
		return ErrStorage
	}
	var count int
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_overview_authority`).Scan(&count) != nil || count > 2*s.config.RecordLimit {
		return ErrStorage
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT invitation_id,section,body FROM enrollment_overview_authority ORDER BY invitation_id,section`)
	if e != nil {
		return ErrStorage
	}
	for rows.Next() {
		var id, section string
		var raw []byte
		var r overviewRecord
		if rows.Scan(&id, &section, &raw) != nil || len(raw) == 0 || len(raw) > 8192 || json.Unmarshal(raw, &r) != nil {
			rows.Close()
			return ErrStorage
		}
		canonical, _ := json.Marshal(r)
		snap, e := t.engine.Get(id)
		if e != nil || section != r.Binding.Section || !bytes.Equal(canonical, raw) || !validOverviewRecord(snap, r) {
			rows.Close()
			return ErrStorage
		}
		key := overviewRecordKey(id, section)
		t.overview[key] = r
		t.originalOverview[key] = raw
	}
	if rows.Err() != nil {
		rows.Close()
		return ErrStorage
	}
	if rows.Close() != nil {
		return ErrStorage
	}
	return validateOverviewMetadata(ctx, t)
}
func validOverviewRecord(snap enrollmentstate.Snapshot, r overviewRecord) bool {
	if !completeProfile(snap.Binding.CollectionProfile) || snap.Platform != "linux" || snap.Activation.At == 0 || snap.Issuance.CertificateHash == "" || !validStoreTime(r.StartedAt) || !validStoreTime(r.LastAt) || r.StartedAt.Location() != time.UTC || r.LastAt.Location() != time.UTC || r.LastAt.Before(r.StartedAt) || r.StartedAt.Unix() < snap.Activation.At || r.LastAt.Unix() >= snap.Intent.NotAfter {
		return false
	}
	if r.MaintenanceAt != nil && (!validStoreTime(*r.MaintenanceAt) || r.MaintenanceAt.Location() != time.UTC || r.MaintenanceAt.Before(r.StartedAt)) {
		return false
	}
	if snap.Termination.At != 0 && r.LastAt.Unix() > snap.Termination.At {
		return false
	}
	expected, e := overviewwire.GenerationID(snap.Approval.DeviceID, r.Binding.Section, r.Binding.Sequence)
	if e != nil || expected != r.Binding.GenerationID {
		return false
	}
	if r.State == "source_failed" {
		return r.Manifest == nil && r.Failure != nil && r.Failure.valid() && r.Binding == (OverviewBinding{Section: r.Failure.Section, Sequence: r.Failure.Sequence, GenerationID: r.Failure.GenerationID}) && !r.Failure.AttemptedAt.After(r.StartedAt) && r.CompletedAt.IsZero()
	}
	if !r.Binding.valid() || r.Manifest == nil || r.Failure != nil {
		return false
	}
	digest, e := overviewgeneration.ManifestDigest(*r.Manifest)
	if e != nil || digest != r.Binding.ManifestHash || r.Manifest.Section != r.Binding.Section || r.Manifest.GenerationID != r.Binding.GenerationID || r.Manifest.CaptureFinishedAt.After(r.StartedAt) {
		return false
	}
	switch r.State {
	case "pending", "aborted":
		return r.CompletedAt.IsZero()
	case "complete":
		return validStoreTime(r.CompletedAt) && r.CompletedAt.Location() == time.UTC && !r.CompletedAt.Before(r.StartedAt) && !r.CompletedAt.After(r.LastAt)
	}
	return false
}
func (s *Store) saveOverview(ctx context.Context, t *transaction) error {
	if !t.overviewEnabled {
		return nil
	}
	for key, r := range t.overview {
		id, section, ok := strings.Cut(key, ":")
		if !ok || section != r.Binding.Section {
			return ErrStorage
		}
		snap, e := t.engine.Get(id)
		if e != nil || !validOverviewRecord(snap, r) {
			return ErrStorage
		}
		raw, e := json.Marshal(r)
		if e != nil || len(raw) > 8192 {
			return ErrStorage
		}
		if bytes.Equal(raw, t.originalOverview[key]) {
			continue
		}
		if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_overview_authority VALUES(?,?,?) ON CONFLICT(invitation_id,section) DO UPDATE SET body=excluded.body`, id, section, raw); e != nil {
			return ErrStorage
		}
	}
	return nil
}
func (s *Store) overviewAdmission(ctx context.Context) (func(), error) {
	return s.inventoryAdmission(ctx)
}
func (s *Store) overviewAuthority(t *transaction, id, certificateHash, section string, now time.Time) (enrollmentstate.Snapshot, error) {
	zero := enrollmentstate.Snapshot{}
	if !t.overviewEnabled {
		return zero, ErrOverviewNotConfigured
	}
	if !validOverviewSection(section) {
		return zero, enrollmentstate.ErrInvalid
	}
	if !enrollmentcrypto.ValidID(id, "invite_") || !enrollmentcrypto.ValidHash(certificateHash) || !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	snap, e := t.engine.Get(id)
	if e != nil {
		return zero, e
	}
	if !completeProfile(snap.Binding.CollectionProfile) || snap.Platform != "linux" {
		return zero, enrollmentstate.ErrProof
	}
	if snap.State != enrollmentstate.Activated {
		return zero, enrollmentstate.ErrState
	}
	if snap.Issuance.CertificateHash != certificateHash {
		return zero, enrollmentstate.ErrProof
	}
	if now.Unix() < snap.UpdatedAt || now.Unix() < snap.Intent.NotBefore {
		return zero, enrollmentstate.ErrInvalid
	}
	if now.Unix() >= snap.Intent.NotAfter {
		return zero, enrollmentstate.ErrExpired
	}
	if r, ok := t.overview[overviewRecordKey(id, section)]; ok && (now.Before(r.LastAt) || r.MaintenanceAt != nil && now.Before(*r.MaintenanceAt)) {
		return zero, enrollmentstate.ErrInvalid
	}
	c, ok := t.credentials[id]
	if !ok {
		return zero, ErrStorage
	}
	intent, e := t.engine.TrustedRecordedIntent(id)
	if e != nil {
		return zero, ErrStorage
	}
	if _, e = enrollmentcrypto.VerifyIssued(c.DER, s.issuerDER, intent, now); e != nil {
		return zero, enrollmentstate.ErrProof
	}
	return snap, nil
}
func (s *Store) overviewOperatorAuthority(t *transaction, device, section string, now time.Time) (enrollmentstate.Snapshot, error) {
	if !enrollmentcrypto.ValidID(device, "agent_") {
		return enrollmentstate.Snapshot{}, enrollmentstate.ErrInvalid
	}
	for _, snap := range t.engine.Snapshots() {
		if snap.Approval.DeviceID == device {
			return s.overviewAuthority(t, snap.InvitationID, snap.Issuance.CertificateHash, section, now)
		}
	}
	return enrollmentstate.Snapshot{}, enrollmentstate.ErrNotFound
}

// Maintenance relies on the privileged local caller, never remote possession
// or a body-supplied lifecycle flag. Restore already verified the exact issued
// certificate at issuance and bound it to this immutable authority identity.
// Current activation/leaf validity is deliberately NOT a cleanup requirement:
// revocation must not strand eligible non-current shared-budget reservations.
func (s *Store) overviewMaintenanceAuthority(t *transaction, device, section string, now time.Time) (enrollmentstate.Snapshot, error) {
	zero := enrollmentstate.Snapshot{}
	if !t.overviewEnabled {
		return zero, ErrOverviewNotConfigured
	}
	if !validOverviewSection(section) {
		return zero, enrollmentstate.ErrInvalid
	}
	if !enrollmentcrypto.ValidID(device, "agent_") || !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	for _, snap := range t.engine.Snapshots() {
		if snap.Approval.DeviceID != device {
			continue
		}
		if !completeProfile(snap.Binding.CollectionProfile) || snap.Platform != "linux" || snap.Activation.At == 0 || !enrollmentcrypto.ValidHash(snap.Issuance.CertificateHash) {
			return zero, enrollmentstate.ErrProof
		}
		if _, ok := t.credentials[snap.InvitationID]; !ok {
			return zero, ErrStorage
		}
		r, ok := t.overview[overviewRecordKey(snap.InvitationID, section)]
		if !ok {
			return zero, overviewledger.ErrNotFound
		}
		if now.Unix() < snap.UpdatedAt || now.Unix() < snap.Intent.NotBefore || now.Before(r.LastAt) || r.MaintenanceAt != nil && now.Before(*r.MaintenanceAt) {
			return zero, enrollmentstate.ErrInvalid
		}
		return snap, nil
	}
	return zero, enrollmentstate.ErrNotFound
}

func matchOverview(t *transaction, id string, b OverviewBinding) (overviewRecord, error) {
	if !b.valid() {
		return overviewRecord{}, enrollmentstate.ErrInvalid
	}
	r, ok := t.overview[overviewRecordKey(id, b.Section)]
	if !ok {
		return overviewRecord{}, overviewledger.ErrNotFound
	}
	if r.Binding != b {
		return overviewRecord{}, overviewledger.ErrConflict
	}
	if r.State == "source_failed" || r.State == "aborted" {
		return overviewRecord{}, overviewledger.ErrConflict
	}
	return r, nil
}
func touchOverview(t *transaction, id, section string, now time.Time) {
	r, ok := t.overview[overviewRecordKey(id, section)]
	if ok {
		r.LastAt = now
		t.overview[overviewRecordKey(id, section)] = r
	}
}

// OverviewBegin authenticates and advances the independent floor atomically
// with reservations. Exact retries retain their original start/expiry; the floor
// survives cleanup and may never be reset to make room for a new upload.
func (s *Store) OverviewBegin(ctx context.Context, id, certificateHash string, b OverviewBinding, m overviewgeneration.Manifest, now time.Time) (overviewledger.BeginReceipt, error) {
	zero := overviewledger.BeginReceipt{}
	release, e := s.overviewAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	digest, e := overviewgeneration.ManifestDigest(m)
	if !b.valid() || e != nil || digest != b.ManifestHash || m.Section != b.Section || m.GenerationID != b.GenerationID || !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	// Clone pointer-bearing manifest before entering the authority transaction.
	raw, _ := json.Marshal(m)
	m, e = overviewgeneration.DecodeManifest(raw)
	if e != nil {
		return zero, enrollmentstate.ErrInvalid
	}
	now = now.UTC()
	var out overviewledger.BeginReceipt
	e = s.transact(ctx, func(t *transaction) error {
		var clockErr error
		now, clockErr = overviewNow(ctx, now)
		if clockErr != nil {
			return clockErr
		}
		snap, e := s.overviewAuthority(t, id, certificateHash, b.Section, now)
		if e != nil {
			return e
		}
		expected, e := overviewwire.GenerationID(snap.Approval.DeviceID, b.Section, b.Sequence)
		if e != nil || expected != b.GenerationID {
			return enrollmentstate.ErrProof
		}
		if old, ok := t.overview[overviewRecordKey(id, b.Section)]; ok {
			if b.Sequence < old.Binding.Sequence || b.Sequence == old.Binding.Sequence && old.Binding != b {
				return overviewledger.ErrConflict
			}
			if b.Sequence == old.Binding.Sequence {
				if old.State == "aborted" || old.State == "source_failed" {
					return overviewledger.ErrConflict
				}
				// The durable floor outlives cleanup. An exact retry must never
				// recreate a removed generation or refresh its original lifetime.
				if old.State == "pending" && !now.Before(old.StartedAt.Add(overviewledger.StagingTTL)) {
					return overviewledger.ErrExpired
				}
				// Load validated a bijection with retained ledger generations;
				// require that binding even if the supplied clock predates cleanup.
				retained, e := overviewGenerationBinding(ctx, t, overviewDevice(snap.Approval.DeviceID, b.Section), b.GenerationID)
				if e != nil || retained != b {
					return ErrStorage
				}
				out, e = overviewLedger().Begin(ctx, t.conn, overviewDevice(snap.Approval.DeviceID, b.Section), m, now)
				if e == nil {
					touchOverview(t, id, b.Section, now)
				}
				return e
			}
			if e = retirePendingOverview(ctx, t, overviewDevice(snap.Approval.DeviceID, b.Section), old, now); e != nil {
				return e
			}
		}
		var exists int
		if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM co_generations WHERE device=? AND generation=?`, overviewDevice(snap.Approval.DeviceID, b.Section), b.GenerationID).Scan(&exists) != nil {
			return ErrStorage
		}
		if exists != 0 {
			return overviewledger.ErrConflict
		}
		out, e = overviewLedger().Begin(ctx, t.conn, overviewDevice(snap.Approval.DeviceID, b.Section), m, now)
		if e != nil {
			return e
		}
		if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_overview_generations VALUES(?,?,?,?)`, overviewDevice(snap.Approval.DeviceID, b.Section), b.GenerationID, b.Sequence, b.ManifestHash); e != nil {
			return ErrStorage
		}
		t.overview[overviewRecordKey(id, b.Section)] = overviewRecord{Binding: b, Manifest: &m, State: "pending", StartedAt: out.StartedAt, LastAt: now}
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
func retirePendingOverview(ctx context.Context, t *transaction, device string, r overviewRecord, now time.Time) error {
	if r.State != "pending" {
		return nil
	}
	if now.Before(r.StartedAt.Add(overviewledger.StagingTTL)) {
		return overviewledger.ErrConflict
	}
	e := overviewLedger().Abandon(ctx, t.conn, device, r.Binding.GenerationID, now)
	if errors.Is(e, overviewledger.ErrNotFound) {
		return nil
	}
	return e
}
func (s *Store) OverviewAppend(ctx context.Context, id, certificateHash string, b OverviewBinding, c overviewgeneration.Chunk, now time.Time) (overviewledger.ChunkReceipt, error) {
	zero := overviewledger.ChunkReceipt{}
	release, e := s.overviewAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if !b.valid() || c.Section != b.Section || c.GenerationID != b.GenerationID || c.ManifestSHA256 != b.ManifestHash || overviewgeneration.ValidateChunk(c) != nil || !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	raw, _ := json.Marshal(c)
	c, e = overviewgeneration.DecodeChunk(raw)
	if e != nil {
		return zero, enrollmentstate.ErrInvalid
	}
	now = now.UTC()
	var out overviewledger.ChunkReceipt
	e = s.transact(ctx, func(t *transaction) error {
		var clockErr error
		now, clockErr = overviewNow(ctx, now)
		if clockErr != nil {
			return clockErr
		}
		snap, e := s.overviewAuthority(t, id, certificateHash, b.Section, now)
		if e != nil {
			return e
		}
		if _, e = matchOverview(t, id, b); e != nil {
			return e
		}
		out, e = overviewLedger().Append(ctx, t.conn, overviewDevice(snap.Approval.DeviceID, b.Section), c, now)
		if e == nil {
			touchOverview(t, id, b.Section, now)
		}
		return e
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
func (s *Store) OverviewFinalize(ctx context.Context, id, certificateHash string, b OverviewBinding, now time.Time) (overviewledger.Completion, error) {
	zero := overviewledger.Completion{}
	release, e := s.overviewAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	now = now.UTC()
	var out overviewledger.Completion
	e = s.transact(ctx, func(t *transaction) error {
		var clockErr error
		now, clockErr = overviewNow(ctx, now)
		if clockErr != nil {
			return clockErr
		}
		snap, e := s.overviewAuthority(t, id, certificateHash, b.Section, now)
		if e != nil {
			return e
		}
		r, e := matchOverview(t, id, b)
		if e != nil {
			return e
		}
		out, e = overviewLedger().Promote(ctx, t.conn, overviewDevice(snap.Approval.DeviceID, b.Section), b.GenerationID, now)
		if e != nil {
			return e
		}
		r.State = "complete"
		r.CompletedAt = out.CompletedAt
		r.LastAt = now
		t.overview[overviewRecordKey(id, b.Section)] = r
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
func (s *Store) OverviewAbort(ctx context.Context, id, certificateHash string, b OverviewBinding, now time.Time) error {
	release, e := s.overviewAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	now = now.UTC()
	return s.transact(ctx, func(t *transaction) error {
		var clockErr error
		now, clockErr = overviewNow(ctx, now)
		if clockErr != nil {
			return clockErr
		}
		snap, e := s.overviewAuthority(t, id, certificateHash, b.Section, now)
		if e != nil {
			return e
		}
		if !b.valid() {
			return enrollmentstate.ErrInvalid
		}
		r, ok := t.overview[overviewRecordKey(id, b.Section)]
		if !ok {
			return overviewledger.ErrNotFound
		}
		if r.Binding != b {
			return overviewledger.ErrConflict
		}
		if r.State == "aborted" {
			touchOverview(t, id, b.Section, now)
			return nil
		}
		if r.State != "pending" {
			return overviewledger.ErrConflict
		}
		if e = overviewLedger().Abandon(ctx, t.conn, overviewDevice(snap.Approval.DeviceID, b.Section), b.GenerationID, now); e != nil {
			// Cleanup may already have removed this expired pending transfer.
			// Current authority and the exact retained binding above still prove
			// which floor to terminate; absence before original expiry is an error.
			if !errors.Is(e, overviewledger.ErrNotFound) || now.Before(r.StartedAt.Add(overviewledger.StagingTTL)) {
				return e
			}
		}
		r.State = "aborted"
		r.LastAt = now
		t.overview[overviewRecordKey(id, b.Section)] = r
		return nil
	})
}
func (s *Store) OverviewFailure(ctx context.Context, id, certificateHash string, f OverviewFailureReport, now time.Time) (OverviewFailureReceipt, error) {
	zero := OverviewFailureReceipt{}
	release, e := s.overviewAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if !f.valid() || !validStoreTime(now) || f.AttemptedAt.After(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	now = now.UTC()
	var out OverviewFailureReceipt
	e = s.transact(ctx, func(t *transaction) error {
		var clockErr error
		now, clockErr = overviewNow(ctx, now)
		if clockErr != nil {
			return clockErr
		}
		snap, e := s.overviewAuthority(t, id, certificateHash, f.Section, now)
		if e != nil {
			return e
		}
		expected, e := overviewwire.GenerationID(snap.Approval.DeviceID, f.Section, f.Sequence)
		if e != nil || expected != f.GenerationID {
			return enrollmentstate.ErrProof
		}
		if old, ok := t.overview[overviewRecordKey(id, f.Section)]; ok {
			if f.Sequence <= old.Binding.Sequence {
				if old.State != "source_failed" || old.Failure == nil || *old.Failure != f {
					return overviewledger.ErrConflict
				}
				out = OverviewFailureReceipt{*old.Failure, old.StartedAt}
				touchOverview(t, id, f.Section, now)
				return nil
			}
			if e = retirePendingOverview(ctx, t, overviewDevice(snap.Approval.DeviceID, f.Section), old, now); e != nil {
				return e
			}
		}
		var exists int
		if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM co_generations WHERE device=? AND generation=?`, overviewDevice(snap.Approval.DeviceID, f.Section), f.GenerationID).Scan(&exists) != nil {
			return ErrStorage
		}
		if exists != 0 {
			return overviewledger.ErrConflict
		}
		t.overview[overviewRecordKey(id, f.Section)] = overviewRecord{Binding: OverviewBinding{Section: f.Section, Sequence: f.Sequence, GenerationID: f.GenerationID}, Failure: &f, State: "source_failed", StartedAt: now, LastAt: now}
		out = OverviewFailureReceipt{f, now}
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
func overviewStatus(ctx context.Context, t *transaction, snap enrollmentstate.Snapshot, section string, now time.Time) (OverviewSectionStatus, error) {
	out := OverviewSectionStatus{DeviceID: snap.Approval.DeviceID, Section: section, ServerNow: now}
	complete, e := overviewLedger().CurrentStatus(ctx, t.conn, overviewDevice(snap.Approval.DeviceID, section), now)
	if e == nil {
		out.Complete = &complete
		out.CompleteBinding, e = overviewGenerationBinding(ctx, t, overviewDevice(snap.Approval.DeviceID, section), complete.Manifest.GenerationID)
		if e != nil {
			return OverviewSectionStatus{}, e
		}
	} else if !errors.Is(e, overviewledger.ErrNotFound) {
		return OverviewSectionStatus{}, e
	}
	if r, ok := t.overview[overviewRecordKey(snap.InvitationID, section)]; ok {
		out.Sequence = r.Binding.Sequence
		if r.Failure != nil {
			out.Failure = &OverviewFailureReceipt{*r.Failure, r.StartedAt}
		} else {
			status, e := overviewLedger().GenerationStatus(ctx, t.conn, overviewDevice(snap.Approval.DeviceID, section), r.Binding.GenerationID, now)
			if errors.Is(e, overviewledger.ErrNotFound) && (r.State == "aborted" || r.State == "pending" && !now.Before(r.StartedAt.Add(overviewledger.StagingTTL))) {
				state := "failed"
				if r.State == "pending" {
					state = "expired"
				}
				status = overviewledger.GenerationStatus{Manifest: *r.Manifest, State: state, StartedAt: r.StartedAt, ExpiresAt: r.StartedAt.Add(overviewledger.StagingTTL)}
			} else if e != nil {
				return OverviewSectionStatus{}, e
			}
			out.Transfer = &status
		}
	}
	return out, nil
}
func (s *Store) OverviewStatus(ctx context.Context, id, certificateHash string, b OverviewBinding, now time.Time) (OverviewSectionStatus, error) {
	zero := OverviewSectionStatus{}
	release, e := s.overviewAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	now = now.UTC()
	var out OverviewSectionStatus
	e = s.transact(ctx, func(t *transaction) error {
		var clockErr error
		now, clockErr = overviewNow(ctx, now)
		if clockErr != nil {
			return clockErr
		}
		snap, e := s.overviewAuthority(t, id, certificateHash, b.Section, now)
		if e != nil {
			return e
		}
		if !b.valid() {
			return enrollmentstate.ErrInvalid
		}
		r, ok := t.overview[overviewRecordKey(id, b.Section)]
		if !ok {
			return overviewledger.ErrNotFound
		}
		if r.Binding != b {
			return overviewledger.ErrConflict
		}
		out, e = overviewStatus(ctx, t, snap, b.Section, now)
		if e == nil {
			touchOverview(t, id, b.Section, now)
		}
		return e
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
func (s *Store) OverviewView(ctx context.Context, device string, now time.Time) (OverviewStatus, error) {
	zero := OverviewStatus{}
	release, e := s.systemReadAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	now = now.UTC()
	var out OverviewStatus
	e = s.transact(ctx, func(t *transaction) error {
		var clockErr error
		now, clockErr = overviewNow(ctx, now)
		if clockErr != nil {
			return clockErr
		}
		snap, e := s.overviewOperatorAuthority(t, device, "processes", now)
		if e != nil {
			return e
		}
		out = OverviewStatus{DeviceID: device, ServerNow: now}
		out.Processes, e = overviewStatus(ctx, t, snap, "processes", now)
		if e != nil {
			return e
		}
		if _, e = s.overviewOperatorAuthority(t, device, "volumes", now); e != nil {
			return e
		}
		out.Volumes, e = overviewStatus(ctx, t, snap, "volumes", now)
		if e != nil {
			return e
		}
		out.boundary = statusOutputBoundary(out, snap.Intent.NotAfter)
		touchOverview(t, snap.InvitationID, "processes", now)
		touchOverview(t, snap.InvitationID, "volumes", now)
		return nil
	})
	if e != nil {
		return zero, e
	}
	now, e = overviewNow(ctx, now)
	if e != nil {
		return zero, e
	}
	if e = out.ValidateAt(now); e != nil {
		return zero, e
	}
	out.ServerNow = now
	out.Processes.ServerNow = now
	out.Volumes.ServerNow = now
	out.boundary.checkedAt = now
	return out, nil
}
func (s *Store) OverviewPage(ctx context.Context, device string, req overviewledger.PageRequest, now time.Time) (OverviewPageResult, error) {
	zero := OverviewPageResult{}
	release, e := s.overviewAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	now = now.UTC()
	var out OverviewPageResult
	e = s.transact(ctx, func(t *transaction) error {
		var clockErr error
		now, clockErr = overviewNow(ctx, now)
		if clockErr != nil {
			return clockErr
		}
		snap, e := s.overviewOperatorAuthority(t, device, req.Section, now)
		if e != nil {
			return e
		}
		out.boundary = overviewBoundary(now, snap.Intent.NotAfter)
		out.ServerNow = now
		out.PageResult, e = overviewLedger().Page(ctx, t.conn, overviewDevice(device, req.Section), req, now, t.overviewKey)
		if e == nil {
			out.boundary.limit(out.CursorExpiresAt, overviewledger.ErrCursorExpired)
			out.Binding, e = overviewGenerationBinding(ctx, t, overviewDevice(device, req.Section), out.Manifest.GenerationID)
		}
		if e == nil {
			touchOverview(t, snap.InvitationID, req.Section, now)
		}
		return e
	})
	if e != nil {
		return zero, e
	}
	now, e = overviewNow(ctx, now)
	if e != nil {
		return zero, e
	}
	if e = out.ValidateAt(now); e != nil {
		return zero, e
	}
	out.ServerNow = now
	out.boundary.checkedAt = now
	return out, nil
}

// OverviewCleanup is a privileged operator-maintenance operation, not an agent
// endpoint. It resolves the immutable device/profile binding in the same fresh
// authority transaction, including after revocation or certificate expiry.
// Existing ledger eligibility windows still apply. Each call removes at most
// 256 rows and 16 chunks, never current data, identity, floor or cursor key.
func (s *Store) OverviewCleanup(ctx context.Context, device, section, generation string, now time.Time) (overviewledger.CleanupResult, error) {
	zero := overviewledger.CleanupResult{}
	release, e := s.overviewAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	now = now.UTC()
	var out overviewledger.CleanupResult
	e = s.transact(ctx, func(t *transaction) error {
		var clockErr error
		now, clockErr = overviewNow(ctx, now)
		if clockErr != nil {
			return clockErr
		}
		snap, e := s.overviewMaintenanceAuthority(t, device, section, now)
		if e != nil {
			return e
		}
		out, e = overviewLedger().Cleanup(ctx, t.conn, overviewDevice(device, section), generation, now)
		if e == nil && out.Done {
			if _, e = t.conn.ExecContext(ctx, `DELETE FROM enrollment_overview_generations WHERE device=? AND generation=?`, overviewDevice(device, section), generation); e != nil {
				return ErrStorage
			}
		}
		if e == nil {
			r := t.overview[overviewRecordKey(snap.InvitationID, section)]
			r.MaintenanceAt = &now
			t.overview[overviewRecordKey(snap.InvitationID, section)] = r
		}
		return e
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}

func overviewGenerationBinding(ctx context.Context, t *transaction, device, generation string) (OverviewBinding, error) {
	public, section, ok := strings.Cut(device, ":")
	if !ok || !validOverviewSection(section) {
		return OverviewBinding{}, ErrStorage
	}
	b := OverviewBinding{Section: section, GenerationID: generation}
	if t.conn.QueryRowContext(ctx, `SELECT sequence,manifest_hash FROM enrollment_overview_generations WHERE device=? AND generation=?`, device, generation).Scan(&b.Sequence, &b.ManifestHash) != nil {
		return OverviewBinding{}, ErrStorage
	}
	expected, e := overviewwire.GenerationID(public, section, b.Sequence)
	if e != nil || expected != generation || !b.valid() {
		return OverviewBinding{}, ErrStorage
	}
	return b, nil
}

// Validate only bounded generation metadata and exact budget accounting. This
// does not restore chunks/rows and does not claim to authenticate arbitrary
// malicious rewrites of an otherwise protected local database.
func validateOverviewMetadata(ctx context.Context, t *transaction) error {
	return validateOverviewBudgets(ctx, t)
}
