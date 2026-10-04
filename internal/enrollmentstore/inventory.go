package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/inventorywire"
)

// Complete inventory is a fresh authority schema, never an existing-profile
// migration. These runtime budgets are rejection ceilings, not a promise that
// every maximum-size pure-contract generation fits.
const inventoryMetaSchema = `CREATE TABLE enrollment_inventory_meta(id INTEGER PRIMARY KEY CHECK(id=1),cursor_key BLOB NOT NULL CHECK(length(cursor_key)=32)) STRICT`
const inventoryAuthoritySchema = `CREATE TABLE enrollment_inventory_authority(invitation_id TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_credentials(invitation_id),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=8192)) STRICT`

const inventoryGenerationsSchema = `CREATE TABLE enrollment_inventory_generations(device TEXT NOT NULL,generation TEXT NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>0),manifest_hash TEXT NOT NULL CHECK(length(manifest_hash)=64),PRIMARY KEY(device,generation)) STRICT`

var ErrInventoryBusy = errors.New("inventory admission is busy")

func inventoryLimits() inventoryledger.Limits {
	l := inventoryledger.DefaultLimits()
	l.GenerationBytes = 48 << 20
	l.DeviceBytes = 96 << 20
	l.GlobalBytes = 128 << 20
	l.DeviceRows = 200000
	l.GlobalRows = 400000
	l.DeviceChunks = 2048
	l.GlobalChunks = 4096
	l.DeviceGenerations = 3
	l.GlobalGenerations = 75
	return l
}
func completeProfile(profile string) bool {
	return profile == enrollmentcrypto.CollectionProfileComplete
}
func completeLedger() *inventoryledger.Ledger {
	l, _ := inventoryledger.New(inventoryLimits())
	return l
}

// InventoryBinding is a separate replay domain from telemetry. The transport
// must prove possession and bind this exact tuple to its purpose/body. It never
// supplies device identity or overrides the authority read inside the write.
type InventoryBinding struct {
	Sequence     uint64 `json:"sequence"`
	GenerationID string `json:"generationId"`
	ManifestHash string `json:"manifestHash"`
}

func (b InventoryBinding) valid() bool {
	return b.Sequence > 0 && b.Sequence <= enrollmentstate.MaxRevision && enrollmentcrypto.ValidID(b.GenerationID, "sample_") && enrollmentcrypto.ValidHash(b.ManifestHash)
}

type InventoryFailureReport struct {
	Sequence     uint64    `json:"sequence"`
	GenerationID string    `json:"generationId"`
	AttemptedAt  time.Time `json:"attemptedAt"`
	Reason       string    `json:"reason"`
}
type InventoryFailureReceipt struct {
	Failure    InventoryFailureReport
	ReceivedAt time.Time
}

func (f InventoryFailureReport) valid() bool {
	if f.Sequence == 0 || f.Sequence > enrollmentstate.MaxRevision || !enrollmentcrypto.ValidID(f.GenerationID, "sample_") || !validStoreTime(f.AttemptedAt) || f.AttemptedAt.Location() != time.UTC {
		return false
	}
	switch f.Reason {
	case "source_missing", "source_invalid", "source_changed", "resource_limit", "collection_failed":
		return true
	}
	return false
}

type inventoryRecord struct {
	Binding       InventoryBinding        `json:"binding"`
	Manifest      *fullinventory.Manifest `json:"manifest"`
	Failure       *InventoryFailureReport `json:"failure"`
	State         string                  `json:"state"`
	StartedAt     time.Time               `json:"startedAt"`
	CompletedAt   time.Time               `json:"completedAt"`
	LastAt        time.Time               `json:"lastAt"`
	MaintenanceAt *time.Time              `json:"maintenanceAt,omitempty"`
}

// InventoryStatus separates the retained complete generation from the latest
// transfer. Complete may be expired metadata. A failed/expired transfer cannot
// erase it or imply a successful zero-row inventory.
type InventoryPageResult struct {
	inventoryledger.PageResult
	Binding InventoryBinding
}
type InventoryStatus struct {
	CompleteBinding InventoryBinding
	DeviceID        string
	ServerNow       time.Time
	Sequence        uint64
	Complete        *inventoryledger.GenerationStatus
	Transfer        *inventoryledger.GenerationStatus
	Failure         *InventoryFailureReceipt
}

func initializeInventory(ctx context.Context, conn *sql.Conn) error {
	for _, q := range []string{inventoryMetaSchema, inventoryAuthoritySchema, inventoryGenerationsSchema} {
		if _, e := conn.ExecContext(ctx, q); e != nil {
			return ErrStorage
		}
	}
	var key [32]byte
	if _, e := rand.Read(key[:]); e != nil {
		return ErrStorage
	}
	if _, e := conn.ExecContext(ctx, `INSERT INTO enrollment_inventory_meta VALUES(1,?)`, key[:]); e != nil {
		return ErrStorage
	}
	return completeLedger().Initialize(ctx, conn)
}
func (s *Store) loadInventory(ctx context.Context, t *transaction) error {
	if !completeProfile(s.config.Binding.CollectionProfile) {
		return nil
	}
	if completeLedger().Check(ctx, t.conn) != nil {
		return ErrStorage
	}
	var count, n int
	if t.conn.QueryRowContext(ctx, `SELECT count(*),coalesce(max(length(cursor_key)),0) FROM enrollment_inventory_meta`).Scan(&count, &n) != nil || count != 1 || n != 32 {
		return ErrStorage
	}
	var rawKey []byte
	if t.conn.QueryRowContext(ctx, `SELECT cursor_key FROM enrollment_inventory_meta WHERE id=1`).Scan(&rawKey) != nil || len(rawKey) != 32 {
		return ErrStorage
	}
	var key [32]byte
	copy(key[:], rawKey)
	var e error
	t.inventoryKey, e = inventoryledger.NewCursorKey(key)
	if e != nil {
		return ErrStorage
	}
	if t.conn.QueryRowContext(ctx, `SELECT count(*),coalesce(max(length(body)),0) FROM enrollment_inventory_authority`).Scan(&count, &n) != nil || count > s.config.RecordLimit || n > 8192 {
		return ErrStorage
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT invitation_id,body FROM enrollment_inventory_authority ORDER BY invitation_id`)
	if e != nil {
		return ErrStorage
	}
	for rows.Next() {
		var id string
		var raw []byte
		var r inventoryRecord
		if rows.Scan(&id, &raw) != nil || len(raw) == 0 || len(raw) > 8192 || json.Unmarshal(raw, &r) != nil {
			rows.Close()
			return ErrStorage
		}
		canonical, _ := json.Marshal(r)
		if !bytes.Equal(raw, canonical) {
			rows.Close()
			return ErrStorage
		}
		snap, e := t.engine.Get(id)
		if e != nil || !validInventoryRecord(snap, r) {
			rows.Close()
			return ErrStorage
		}
		t.inventory[id] = r
		t.originalInventory[id] = raw
	}
	if e = rows.Err(); e != nil {
		rows.Close()
		return ErrStorage
	}
	if rows.Close() != nil {
		return ErrStorage
	}
	// Metadata-only bounded ownership validation. Never load fi_rows or chunks on
	// routine authority transactions. Quotas include retained/garbage generations.
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM fi_devices`).Scan(&count) != nil || count > s.config.RecordLimit {
		return ErrStorage
	}
	rows, e = t.conn.QueryContext(ctx, `SELECT device FROM fi_devices ORDER BY device`)
	if e != nil {
		return ErrStorage
	}
	known := map[string]bool{}
	for id := range t.inventory {
		snap, _ := t.engine.Get(id)
		known[snap.Approval.DeviceID] = true
	}
	for rows.Next() {
		var device string
		if rows.Scan(&device) != nil || !known[device] {
			rows.Close()
			return ErrStorage
		}
	}
	if rows.Err() != nil {
		rows.Close()
		return ErrStorage
	}
	if rows.Close() != nil {
		return ErrStorage
	}
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM fi_generations`).Scan(&count) != nil || int64(count) > inventoryLimits().GlobalGenerations {
		return ErrStorage
	}
	var orphans int
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM fi_generations g LEFT JOIN fi_devices d ON g.device=d.device WHERE d.device IS NULL`).Scan(&orphans) != nil || orphans != 0 {
		return ErrStorage
	}
	if validateInventoryGenerationBindings(ctx, t) != nil {
		return ErrStorage
	}
	return validateInventoryMetadata(ctx, t)
}
func validInventoryRecord(snap enrollmentstate.Snapshot, r inventoryRecord) bool {
	if !completeProfile(snap.Binding.CollectionProfile) || snap.Platform != "linux" || snap.Activation.At == 0 || snap.Issuance.CertificateHash == "" || !validStoreTime(r.StartedAt) || !validStoreTime(r.LastAt) || r.StartedAt.Location() != time.UTC || r.LastAt.Location() != time.UTC || r.LastAt.Before(r.StartedAt) || r.StartedAt.Unix() < snap.Activation.At || r.LastAt.Unix() >= snap.Intent.NotAfter {
		return false
	}
	if r.MaintenanceAt != nil && (!validStoreTime(*r.MaintenanceAt) || r.MaintenanceAt.Location() != time.UTC || r.MaintenanceAt.Before(r.StartedAt)) {
		return false
	}
	if snap.Termination.At != 0 && r.LastAt.Unix() > snap.Termination.At {
		return false
	}
	expected, e := inventorywire.GenerationID(snap.Approval.DeviceID, r.Binding.Sequence)
	if e != nil || expected != r.Binding.GenerationID {
		return false
	}
	if r.State == "source_failed" {
		return r.Manifest == nil && r.Failure != nil && r.Failure.valid() && r.Binding == (InventoryBinding{Sequence: r.Failure.Sequence, GenerationID: r.Failure.GenerationID}) && !r.Failure.AttemptedAt.After(r.StartedAt) && r.CompletedAt.IsZero()
	}
	if !r.Binding.valid() || r.Manifest == nil || r.Failure != nil {
		return false
	}
	digest, e := fullinventory.ManifestDigest(*r.Manifest)
	if e != nil || digest != r.Binding.ManifestHash || r.Manifest.GenerationID != r.Binding.GenerationID || r.Manifest.CollectedAt.After(r.StartedAt) {
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
func (s *Store) saveInventory(ctx context.Context, t *transaction) error {
	if !completeProfile(s.config.Binding.CollectionProfile) {
		return nil
	}
	for id, r := range t.inventory {
		snap, e := t.engine.Get(id)
		if e != nil || !validInventoryRecord(snap, r) {
			return ErrStorage
		}
		raw, _ := json.Marshal(r)
		if len(raw) > 8192 {
			return ErrStorage
		}
		if bytes.Equal(raw, t.originalInventory[id]) {
			continue
		}
		if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_inventory_authority VALUES(?,?) ON CONFLICT(invitation_id) DO UPDATE SET body=excluded.body`, id, raw); e != nil {
			return ErrStorage
		}
	}
	return nil
}
func (s *Store) inventoryAdmission(ctx context.Context) (func(), error) {
	if s == nil || s.storeState == nil || ctx == nil {
		return nil, enrollmentstate.ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if !completeProfile(s.config.Binding.CollectionProfile) {
		return nil, enrollmentstate.ErrProof
	}
	select {
	case s.inventoryCalls <- struct{}{}:
		return func() { <-s.inventoryCalls }, nil
	default:
		return nil, ErrInventoryBusy
	}
}
func (s *Store) inventoryAuthority(t *transaction, id, certificateHash string, now time.Time) (enrollmentstate.Snapshot, error) {
	zero := enrollmentstate.Snapshot{}
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
	if r, ok := t.inventory[id]; ok && (now.Before(r.LastAt) || r.MaintenanceAt != nil && now.Before(*r.MaintenanceAt)) {
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
func (s *Store) inventoryOperatorAuthority(t *transaction, device string, now time.Time) (enrollmentstate.Snapshot, error) {
	if !enrollmentcrypto.ValidID(device, "agent_") {
		return enrollmentstate.Snapshot{}, enrollmentstate.ErrInvalid
	}
	for _, snap := range t.engine.Snapshots() {
		if snap.Approval.DeviceID == device {
			return s.inventoryAuthority(t, snap.InvitationID, snap.Issuance.CertificateHash, now)
		}
	}
	return enrollmentstate.Snapshot{}, enrollmentstate.ErrNotFound
}

// Maintenance relies on the privileged local caller, never remote possession
// or a body-supplied lifecycle flag. Restore already verified the exact issued
// certificate at issuance and bound it to this immutable authority identity.
// Current activation/leaf validity is deliberately NOT a cleanup requirement:
// revocation must not strand eligible non-current shared-budget reservations.
func (s *Store) inventoryMaintenanceAuthority(t *transaction, device string, now time.Time) (enrollmentstate.Snapshot, error) {
	zero := enrollmentstate.Snapshot{}
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
		r, ok := t.inventory[snap.InvitationID]
		if !ok {
			return zero, inventoryledger.ErrNotFound
		}
		if now.Unix() < snap.UpdatedAt || now.Unix() < snap.Intent.NotBefore || now.Before(r.LastAt) || r.MaintenanceAt != nil && now.Before(*r.MaintenanceAt) {
			return zero, enrollmentstate.ErrInvalid
		}
		return snap, nil
	}
	return zero, enrollmentstate.ErrNotFound
}

func matchInventory(t *transaction, id string, b InventoryBinding) (inventoryRecord, error) {
	if !b.valid() {
		return inventoryRecord{}, enrollmentstate.ErrInvalid
	}
	r, ok := t.inventory[id]
	if !ok {
		return inventoryRecord{}, inventoryledger.ErrNotFound
	}
	if r.Binding != b {
		return inventoryRecord{}, inventoryledger.ErrConflict
	}
	if r.State == "source_failed" || r.State == "aborted" {
		return inventoryRecord{}, inventoryledger.ErrConflict
	}
	return r, nil
}
func touchInventory(t *transaction, id string, now time.Time) {
	r, ok := t.inventory[id]
	if ok {
		r.LastAt = now
		t.inventory[id] = r
	}
}

// InventoryBegin authenticates and advances the independent floor atomically
// with reservations. Exact retries retain their original start/expiry; the floor
// survives cleanup and may never be reset to make room for a new upload.
func (s *Store) InventoryBegin(ctx context.Context, id, certificateHash string, b InventoryBinding, m fullinventory.Manifest, now time.Time) (inventoryledger.BeginReceipt, error) {
	zero := inventoryledger.BeginReceipt{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	digest, e := fullinventory.ManifestDigest(m)
	if !b.valid() || e != nil || digest != b.ManifestHash || m.GenerationID != b.GenerationID || !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	// Clone pointer-bearing manifest before entering the authority transaction.
	raw, _ := json.Marshal(m)
	m, e = fullinventory.DecodeManifest(raw)
	if e != nil {
		return zero, enrollmentstate.ErrInvalid
	}
	now = now.UTC()
	var out inventoryledger.BeginReceipt
	e = s.transact(ctx, func(t *transaction) error {
		snap, e := s.inventoryAuthority(t, id, certificateHash, now)
		if e != nil {
			return e
		}
		expected, e := inventorywire.GenerationID(snap.Approval.DeviceID, b.Sequence)
		if e != nil || expected != b.GenerationID {
			return enrollmentstate.ErrProof
		}
		if old, ok := t.inventory[id]; ok {
			if b.Sequence < old.Binding.Sequence || b.Sequence == old.Binding.Sequence && old.Binding != b {
				return inventoryledger.ErrConflict
			}
			if b.Sequence == old.Binding.Sequence {
				if old.State == "aborted" || old.State == "source_failed" {
					return inventoryledger.ErrConflict
				}
				out, e = completeLedger().Begin(ctx, t.conn, snap.Approval.DeviceID, m, now)
				if e == nil {
					touchInventory(t, id, now)
				}
				return e
			}
			if e = retirePendingInventory(ctx, t, snap.Approval.DeviceID, old, now); e != nil {
				return e
			}
		}
		var exists int
		if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM fi_generations WHERE device=? AND generation=?`, snap.Approval.DeviceID, b.GenerationID).Scan(&exists) != nil {
			return ErrStorage
		}
		if exists != 0 {
			return inventoryledger.ErrConflict
		}
		out, e = completeLedger().Begin(ctx, t.conn, snap.Approval.DeviceID, m, now)
		if e != nil {
			return e
		}
		if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_inventory_generations VALUES(?,?,?,?)`, snap.Approval.DeviceID, b.GenerationID, b.Sequence, b.ManifestHash); e != nil {
			return ErrStorage
		}
		t.inventory[id] = inventoryRecord{Binding: b, Manifest: &m, State: "pending", StartedAt: out.StartedAt, LastAt: now}
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
func retirePendingInventory(ctx context.Context, t *transaction, device string, r inventoryRecord, now time.Time) error {
	if r.State != "pending" {
		return nil
	}
	if now.Before(r.StartedAt.Add(inventoryledger.StagingTTL)) {
		return inventoryledger.ErrConflict
	}
	e := completeLedger().Abandon(ctx, t.conn, device, r.Binding.GenerationID, now)
	if errors.Is(e, inventoryledger.ErrNotFound) {
		return nil
	}
	return e
}
func (s *Store) InventoryAppend(ctx context.Context, id, certificateHash string, b InventoryBinding, c fullinventory.Chunk, now time.Time) (inventoryledger.ChunkReceipt, error) {
	zero := inventoryledger.ChunkReceipt{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if !b.valid() || c.GenerationID != b.GenerationID || c.ManifestSHA256 != b.ManifestHash || fullinventory.ValidateChunk(c) != nil || !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	c.Items = append(c.Items[:0:0], c.Items...)
	now = now.UTC()
	var out inventoryledger.ChunkReceipt
	e = s.transact(ctx, func(t *transaction) error {
		snap, e := s.inventoryAuthority(t, id, certificateHash, now)
		if e != nil {
			return e
		}
		if _, e = matchInventory(t, id, b); e != nil {
			return e
		}
		out, e = completeLedger().Append(ctx, t.conn, snap.Approval.DeviceID, c, now)
		if e == nil {
			touchInventory(t, id, now)
		}
		return e
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
func (s *Store) InventoryFinalize(ctx context.Context, id, certificateHash string, b InventoryBinding, now time.Time) (inventoryledger.Completion, error) {
	zero := inventoryledger.Completion{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	now = now.UTC()
	var out inventoryledger.Completion
	e = s.transact(ctx, func(t *transaction) error {
		snap, e := s.inventoryAuthority(t, id, certificateHash, now)
		if e != nil {
			return e
		}
		r, e := matchInventory(t, id, b)
		if e != nil {
			return e
		}
		out, e = completeLedger().Promote(ctx, t.conn, snap.Approval.DeviceID, b.GenerationID, now)
		if e != nil {
			return e
		}
		r.State = "complete"
		r.CompletedAt = out.CompletedAt
		r.LastAt = now
		t.inventory[id] = r
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
func (s *Store) InventoryAbort(ctx context.Context, id, certificateHash string, b InventoryBinding, now time.Time) error {
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	now = now.UTC()
	return s.transact(ctx, func(t *transaction) error {
		snap, e := s.inventoryAuthority(t, id, certificateHash, now)
		if e != nil {
			return e
		}
		if !b.valid() {
			return enrollmentstate.ErrInvalid
		}
		r, ok := t.inventory[id]
		if !ok {
			return inventoryledger.ErrNotFound
		}
		if r.Binding != b {
			return inventoryledger.ErrConflict
		}
		if r.State == "aborted" {
			touchInventory(t, id, now)
			return nil
		}
		if r.State != "pending" {
			return inventoryledger.ErrConflict
		}
		if e = completeLedger().Abandon(ctx, t.conn, snap.Approval.DeviceID, b.GenerationID, now); e != nil {
			return e
		}
		r.State = "aborted"
		r.LastAt = now
		t.inventory[id] = r
		return nil
	})
}
func (s *Store) InventoryFailure(ctx context.Context, id, certificateHash string, f InventoryFailureReport, now time.Time) (InventoryFailureReceipt, error) {
	zero := InventoryFailureReceipt{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if !f.valid() || !validStoreTime(now) || f.AttemptedAt.After(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	now = now.UTC()
	var out InventoryFailureReceipt
	e = s.transact(ctx, func(t *transaction) error {
		snap, e := s.inventoryAuthority(t, id, certificateHash, now)
		if e != nil {
			return e
		}
		expected, e := inventorywire.GenerationID(snap.Approval.DeviceID, f.Sequence)
		if e != nil || expected != f.GenerationID {
			return enrollmentstate.ErrProof
		}
		if old, ok := t.inventory[id]; ok {
			if f.Sequence <= old.Binding.Sequence {
				if old.State != "source_failed" || old.Failure == nil || *old.Failure != f {
					return inventoryledger.ErrConflict
				}
				out = InventoryFailureReceipt{*old.Failure, old.StartedAt}
				touchInventory(t, id, now)
				return nil
			}
			if e = retirePendingInventory(ctx, t, snap.Approval.DeviceID, old, now); e != nil {
				return e
			}
		}
		var exists int
		if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM fi_generations WHERE device=? AND generation=?`, snap.Approval.DeviceID, f.GenerationID).Scan(&exists) != nil {
			return ErrStorage
		}
		if exists != 0 {
			return inventoryledger.ErrConflict
		}
		t.inventory[id] = inventoryRecord{Binding: InventoryBinding{Sequence: f.Sequence, GenerationID: f.GenerationID}, Failure: &f, State: "source_failed", StartedAt: now, LastAt: now}
		out = InventoryFailureReceipt{f, now}
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
func inventoryStatus(ctx context.Context, t *transaction, snap enrollmentstate.Snapshot, now time.Time) (InventoryStatus, error) {
	out := InventoryStatus{DeviceID: snap.Approval.DeviceID, ServerNow: now}
	complete, e := completeLedger().CurrentStatus(ctx, t.conn, snap.Approval.DeviceID, now)
	if e == nil {
		out.Complete = &complete
		out.CompleteBinding, e = inventoryGenerationBinding(ctx, t, snap.Approval.DeviceID, complete.Manifest.GenerationID)
		if e != nil {
			return InventoryStatus{}, e
		}
	} else if !errors.Is(e, inventoryledger.ErrNotFound) {
		return InventoryStatus{}, e
	}
	if r, ok := t.inventory[snap.InvitationID]; ok {
		out.Sequence = r.Binding.Sequence
		if r.Failure != nil {
			out.Failure = &InventoryFailureReceipt{*r.Failure, r.StartedAt}
		} else {
			status, e := completeLedger().GenerationStatus(ctx, t.conn, snap.Approval.DeviceID, r.Binding.GenerationID, now)
			if errors.Is(e, inventoryledger.ErrNotFound) && (r.State == "aborted" || r.State == "pending" && !now.Before(r.StartedAt.Add(inventoryledger.StagingTTL))) {
				state := "failed"
				if r.State == "pending" {
					state = "expired"
				}
				status = inventoryledger.GenerationStatus{Manifest: *r.Manifest, State: state, StartedAt: r.StartedAt, ExpiresAt: r.StartedAt.Add(inventoryledger.StagingTTL)}
			} else if e != nil {
				return InventoryStatus{}, e
			}
			out.Transfer = &status
		}
	}
	return out, nil
}
func (s *Store) InventoryStatus(ctx context.Context, id, certificateHash string, b InventoryBinding, now time.Time) (InventoryStatus, error) {
	zero := InventoryStatus{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	now = now.UTC()
	var out InventoryStatus
	e = s.transact(ctx, func(t *transaction) error {
		snap, e := s.inventoryAuthority(t, id, certificateHash, now)
		if e != nil {
			return e
		}
		if !b.valid() {
			return enrollmentstate.ErrInvalid
		}
		r, ok := t.inventory[id]
		if !ok {
			return inventoryledger.ErrNotFound
		}
		if r.Binding != b {
			return inventoryledger.ErrConflict
		}
		out, e = inventoryStatus(ctx, t, snap, now)
		if e == nil {
			touchInventory(t, id, now)
		}
		return e
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
func (s *Store) InventoryView(ctx context.Context, device string, now time.Time) (InventoryStatus, error) {
	zero := InventoryStatus{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	now = now.UTC()
	var out InventoryStatus
	e = s.transact(ctx, func(t *transaction) error {
		snap, e := s.inventoryOperatorAuthority(t, device, now)
		if e != nil {
			return e
		}
		out, e = inventoryStatus(ctx, t, snap, now)
		if e == nil {
			touchInventory(t, snap.InvitationID, now)
		}
		return e
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
func (s *Store) InventoryPage(ctx context.Context, device string, req inventoryledger.PageRequest, now time.Time) (InventoryPageResult, error) {
	zero := InventoryPageResult{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	now = now.UTC()
	var out InventoryPageResult
	e = s.transact(ctx, func(t *transaction) error {
		snap, e := s.inventoryOperatorAuthority(t, device, now)
		if e != nil {
			return e
		}
		out.PageResult, e = completeLedger().Page(ctx, t.conn, device, req, now, t.inventoryKey)
		if e == nil {
			out.Binding, e = inventoryGenerationBinding(ctx, t, device, out.Manifest.GenerationID)
		}
		if e == nil {
			touchInventory(t, snap.InvitationID, now)
		}
		return e
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}

// InventoryCleanup is a privileged operator-maintenance operation, not an agent
// endpoint. It resolves the immutable device/profile binding in the same fresh
// authority transaction, including after revocation or certificate expiry.
// Existing ledger eligibility windows still apply. Each call removes at most
// 256 rows and 16 chunks, never current data, identity, floor or cursor key.
func (s *Store) InventoryCleanup(ctx context.Context, device, generation string, now time.Time) (inventoryledger.CleanupResult, error) {
	zero := inventoryledger.CleanupResult{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	now = now.UTC()
	var out inventoryledger.CleanupResult
	e = s.transact(ctx, func(t *transaction) error {
		snap, e := s.inventoryMaintenanceAuthority(t, device, now)
		if e != nil {
			return e
		}
		out, e = completeLedger().Cleanup(ctx, t.conn, device, generation, now)
		if e == nil && out.Done {
			if _, e = t.conn.ExecContext(ctx, `DELETE FROM enrollment_inventory_generations WHERE device=? AND generation=?`, device, generation); e != nil {
				return ErrStorage
			}
		}
		if e == nil {
			r := t.inventory[snap.InvitationID]
			r.MaintenanceAt = &now
			t.inventory[snap.InvitationID] = r
		}
		return e
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}

func inventoryGenerationBinding(ctx context.Context, t *transaction, device, generation string) (InventoryBinding, error) {
	b := InventoryBinding{GenerationID: generation}
	if t.conn.QueryRowContext(ctx, `SELECT sequence,manifest_hash FROM enrollment_inventory_generations WHERE device=? AND generation=?`, device, generation).Scan(&b.Sequence, &b.ManifestHash) != nil {
		return InventoryBinding{}, ErrStorage
	}
	expected, e := inventorywire.GenerationID(device, b.Sequence)
	if e != nil || expected != generation || !b.valid() {
		return InventoryBinding{}, ErrStorage
	}
	return b, nil
}
func validateInventoryGenerationBindings(ctx context.Context, t *transaction) error {
	var count, ledgerCount int
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_inventory_generations`).Scan(&count) != nil || int64(count) > inventoryLimits().GlobalGenerations || t.conn.QueryRowContext(ctx, `SELECT count(*) FROM fi_generations`).Scan(&ledgerCount) != nil || count != ledgerCount {
		return ErrStorage
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT b.device,b.generation,b.sequence,b.manifest_hash,g.manifest FROM enrollment_inventory_generations b LEFT JOIN fi_generations g ON b.device=g.device AND b.generation=g.generation ORDER BY b.device,b.generation`)
	if e != nil {
		return ErrStorage
	}
	defer rows.Close()
	for rows.Next() {
		var device string
		var b InventoryBinding
		var raw []byte
		if rows.Scan(&device, &b.GenerationID, &b.Sequence, &b.ManifestHash, &raw) != nil || !b.valid() {
			return ErrStorage
		}
		expected, e := inventorywire.GenerationID(device, b.Sequence)
		if e != nil || expected != b.GenerationID {
			return ErrStorage
		}
		m, e := fullinventory.DecodeManifest(raw)
		if e != nil || m.GenerationID != b.GenerationID {
			return ErrStorage
		}
		h, e := fullinventory.ManifestDigest(m)
		if e != nil || h != b.ManifestHash {
			return ErrStorage
		}
	}
	if rows.Err() != nil {
		return ErrStorage
	}
	return nil
}

// Validate only bounded generation metadata and exact budget accounting. This
// does not restore chunks/rows and does not claim to authenticate arbitrary
// malicious rewrites of an otherwise protected local database.
func validateInventoryMetadata(ctx context.Context, t *transaction) error {
	type totals struct{ rows, chunks, bytes, generations int64 }
	sums := map[string]totals{"": {}}
	devices := map[string]inventoryRecord{}
	for id, r := range t.inventory {
		snap, _ := t.engine.Get(id)
		devices[snap.Approval.DeviceID] = r
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT device,generation,state,stored_bytes,manifest FROM fi_generations ORDER BY device,generation`)
	if e != nil {
		return ErrStorage
	}
	type entry struct{ device, generation, state string }
	entries := []entry{}
	for rows.Next() {
		var item entry
		var stored int64
		var raw []byte
		if rows.Scan(&item.device, &item.generation, &item.state, &stored, &raw) != nil {
			rows.Close()
			return ErrStorage
		}
		r, ok := devices[item.device]
		if !ok {
			rows.Close()
			return ErrStorage
		}
		m, e := fullinventory.DecodeManifest(raw)
		if e != nil || stored < 1 || stored > inventoryLimits().GenerationBytes {
			rows.Close()
			return ErrStorage
		}
		if item.generation == r.Binding.GenerationID && (r.State == "source_failed" || r.State == "complete" && item.state != "current" || r.State == "aborted" && item.state != "garbage" || r.State == "pending" && item.state != "staging" && item.state != "garbage") {
			rows.Close()
			return ErrStorage
		}
		for _, scope := range []string{"", item.device} {
			v := sums[scope]
			v.rows += int64(m.ObservedCount)
			v.chunks += int64(m.ChunkCount)
			v.bytes += stored
			v.generations++
			sums[scope] = v
		}
		entries = append(entries, item)
	}
	if rows.Err() != nil {
		rows.Close()
		return ErrStorage
	}
	if rows.Close() != nil {
		return ErrStorage
	}
	for _, item := range entries {
		if _, e = completeLedger().GenerationStatus(ctx, t.conn, item.device, item.generation, devices[item.device].LastAt); e != nil {
			return ErrStorage
		}
		b, e := inventoryGenerationBinding(ctx, t, item.device, item.generation)
		if e != nil || b.Sequence > devices[item.device].Binding.Sequence {
			return ErrStorage
		}
	}
	limits := inventoryLimits()
	rows, e = t.conn.QueryContext(ctx, `SELECT scope,held_rows,held_chunks,stored_bytes,generations FROM fi_budget ORDER BY scope`)
	if e != nil {
		return ErrStorage
	}
	count := 0
	for rows.Next() {
		var scope string
		var got totals
		if rows.Scan(&scope, &got.rows, &got.chunks, &got.bytes, &got.generations) != nil {
			rows.Close()
			return ErrStorage
		}
		want, ok := sums[scope]
		if !ok || got != want {
			rows.Close()
			return ErrStorage
		}
		cap := totals{limits.DeviceRows, limits.DeviceChunks, limits.DeviceBytes, limits.DeviceGenerations}
		if scope == "" {
			cap = totals{limits.GlobalRows, limits.GlobalChunks, limits.GlobalBytes, limits.GlobalGenerations}
		}
		if got.rows > cap.rows || got.chunks > cap.chunks || got.bytes > cap.bytes || got.generations > cap.generations {
			rows.Close()
			return ErrStorage
		}
		count++
	}
	if rows.Err() != nil {
		rows.Close()
		return ErrStorage
	}
	if rows.Close() != nil || count != len(sums) {
		return ErrStorage
	}
	rows, e = t.conn.QueryContext(ctx, `SELECT device,current_generation,staging_generation FROM fi_devices ORDER BY device`)
	if e != nil {
		return ErrStorage
	}
	defer rows.Close()
	for rows.Next() {
		var device, current, staged string
		if rows.Scan(&device, &current, &staged) != nil {
			return ErrStorage
		}
		r, ok := devices[device]
		if !ok {
			return ErrStorage
		}
		if staged != "" && (r.State != "pending" || staged != r.Binding.GenerationID) {
			return ErrStorage
		}
		if r.State == "complete" && current != r.Binding.GenerationID {
			return ErrStorage
		}
		if current != "" {
			found := false
			for _, item := range entries {
				if item.device == device && item.generation == current && item.state == "current" {
					found = true
					break
				}
			}
			if !found {
				return ErrStorage
			}
		}
		if staged != "" {
			found := false
			for _, item := range entries {
				if item.device == device && item.generation == staged && item.state == "staging" {
					found = true
					break
				}
			}
			if !found {
				return ErrStorage
			}
		}
	}
	if rows.Err() != nil {
		return ErrStorage
	}
	return nil
}
