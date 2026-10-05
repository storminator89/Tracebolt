package enrollmentstore

// This add-only extension stores complete known cached APT candidate rows. It
// neither enables collection nor grants package/cache access on an endpoint.
import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/cachedupdates"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/inventorywire"
	"localrmm/internal/updategeneration"
)

var ErrCompleteUpdatesNotConfigured = errors.New("complete cached updates storage is not initialized")

type CompleteUpdatesCompletion struct {
	Manifest               updategeneration.Manifest
	StartedAt, CompletedAt time.Time
}
type CompleteUpdatesGenerationStatus struct {
	Manifest                          updategeneration.Manifest
	State                             string
	StartedAt, ExpiresAt, CompletedAt time.Time
	AcceptedChunks                    uint32
	AcceptedRows                      uint64
}
type CompleteUpdatesStatus struct {
	DeviceID           string
	ServerNow          time.Time
	Status             string
	Sequence           uint64
	CompleteBinding    InventoryBinding
	Complete, Transfer *CompleteUpdatesGenerationStatus
	Failure            *InventoryFailureReceipt
	boundary           overviewOutputBoundary
}
type CompleteUpdatesPageResult struct {
	Binding                     InventoryBinding
	Manifest                    updategeneration.Manifest
	StartedAt, CompletedAt      time.Time
	ServerNow                   time.Time
	Items                       []cachedupdates.Candidate
	TotalRows                   uint64
	ScannedRows                 int
	Exhausted, SearchIncomplete bool
	NextCursor                  string
	CursorExpiresAt             time.Time
	boundary                    overviewOutputBoundary
}

func (out CompleteUpdatesStatus) ValidateAt(now time.Time) error { return out.boundary.validate(now) }
func (out CompleteUpdatesPageResult) ValidateAt(now time.Time) error {
	return out.boundary.validate(now)
}

// The existing trusted-clock mechanism supplies action and post-commit checks;
// payloads cannot inject or replace it.
func WithCompleteUpdatesClock(ctx context.Context, now func() time.Time) context.Context {
	return WithOverviewClock(ctx, now)
}

type completeUpdatesRetained struct {
	Binding     InventoryBinding          `json:"binding"`
	Manifest    updategeneration.Manifest `json:"manifest"`
	StartedAt   time.Time                 `json:"startedAt"`
	CompletedAt time.Time                 `json:"completedAt"`
}
type completeUpdatesRecord struct {
	Binding       InventoryBinding           `json:"binding"`
	Manifest      *updategeneration.Manifest `json:"manifest"`
	Failure       *InventoryFailureReport    `json:"failure"`
	State         string                     `json:"state"`
	StartedAt     time.Time                  `json:"startedAt"`
	CompletedAt   time.Time                  `json:"completedAt"`
	LastAt        time.Time                  `json:"lastAt"`
	MaintenanceAt *time.Time                 `json:"maintenanceAt,omitempty"`
	Complete      *completeUpdatesRetained   `json:"complete"`
}

func readCompleteUpdatesRecord(ctx context.Context, t *transaction, id string) (completeUpdatesRecord, error) {
	var raw []byte
	err := t.conn.QueryRowContext(ctx, `SELECT body FROM enrollment_complete_updates_authority WHERE invitation_id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return completeUpdatesRecord{}, inventoryledger.ErrNotFound
	}
	if err != nil {
		return completeUpdatesRecord{}, ErrStorage
	}
	var r completeUpdatesRecord
	if len(raw) == 0 || len(raw) > 12288 || json.Unmarshal(raw, &r) != nil {
		return r, ErrStorage
	}
	canonical, _ := json.Marshal(r)
	snap, e := t.engine.Get(id)
	if e != nil || !bytes.Equal(raw, canonical) || !validCompleteUpdatesRecord(snap, r) {
		return completeUpdatesRecord{}, ErrStorage
	}
	return r, nil
}
func saveCompleteUpdatesRecord(ctx context.Context, t *transaction, id string, r completeUpdatesRecord) error {
	snap, e := t.engine.Get(id)
	raw, err := json.Marshal(r)
	if e != nil || err != nil || len(raw) > 12288 || !validCompleteUpdatesRecord(snap, r) {
		return ErrStorage
	}
	if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_complete_updates_authority VALUES(?,?) ON CONFLICT(invitation_id) DO UPDATE SET body=excluded.body`, id, raw); e != nil {
		return ErrStorage
	}
	return nil
}

// Unsupported distributions are a failure in this extension only. Preserve the
// existing package failure grammar and all neutral scalar metadata validation.
func validCompleteUpdatesFailure(f InventoryFailureReport) bool {
	if f.Reason == "not_supported" {
		f.Reason = "collection_failed"
	}
	return f.valid()
}

func validCompleteUpdatesManifest(b InventoryBinding, m updategeneration.Manifest) bool {
	digest, e := updategeneration.ManifestDigest(m)
	return b.valid() && e == nil && b.ManifestHash == digest && b.GenerationID == m.GenerationID
}
func validCompleteUpdatesRecord(snap enrollmentstate.Snapshot, r completeUpdatesRecord) bool {
	if !completeProfile(snap.Binding.CollectionProfile) || snap.Platform != "linux" || snap.Activation.At == 0 || snap.Issuance.CertificateHash == "" || !validStoreTime(r.StartedAt) || !validStoreTime(r.LastAt) || r.StartedAt.Location() != time.UTC || r.LastAt.Location() != time.UTC || r.LastAt.Before(r.StartedAt) || r.StartedAt.Unix() < snap.Activation.At || r.LastAt.Unix() >= snap.Intent.NotAfter || snap.Termination.At != 0 && r.LastAt.Unix() > snap.Termination.At {
		return false
	}
	if r.MaintenanceAt != nil && (!validStoreTime(*r.MaintenanceAt) || r.MaintenanceAt.Location() != time.UTC || r.MaintenanceAt.Before(r.StartedAt)) {
		return false
	}
	expected, e := inventorywire.CachedUpdatesGenerationID(snap.Approval.DeviceID, r.Binding.Sequence)
	if e != nil || expected != r.Binding.GenerationID {
		return false
	}
	if r.State == "source_failed" {
		if r.Manifest != nil || r.Failure == nil || !validCompleteUpdatesFailure(*r.Failure) || r.Binding != (InventoryBinding{Sequence: r.Failure.Sequence, GenerationID: r.Failure.GenerationID}) || r.Failure.AttemptedAt.After(r.StartedAt) || !r.CompletedAt.IsZero() {
			return false
		}
	} else {
		if r.Manifest == nil || r.Failure != nil || !validCompleteUpdatesManifest(r.Binding, *r.Manifest) || r.Manifest.CollectedAt.After(r.StartedAt) || r.State != "aborted" && r.StartedAt.Sub(r.Manifest.CollectedAt) >= inventoryledger.ObservationTTL {
			return false
		}
		switch r.State {
		case "pending", "aborted":
			if !r.CompletedAt.IsZero() {
				return false
			}
		case "complete":
			if !validStoreTime(r.CompletedAt) || r.CompletedAt.Location() != time.UTC || r.CompletedAt.Before(r.StartedAt) || r.CompletedAt.After(r.LastAt) {
				return false
			}
		default:
			return false
		}
	}
	if c := r.Complete; c != nil {
		expected, e := inventorywire.CachedUpdatesGenerationID(snap.Approval.DeviceID, c.Binding.Sequence)
		if e != nil || expected != c.Binding.GenerationID || c.Binding.Sequence > r.Binding.Sequence || !validCompleteUpdatesManifest(c.Binding, c.Manifest) || !validStoreTime(c.StartedAt) || !validStoreTime(c.CompletedAt) || c.StartedAt.Location() != time.UTC || c.CompletedAt.Location() != time.UTC || c.Manifest.CollectedAt.After(c.StartedAt) || c.StartedAt.Unix() < snap.Activation.At || c.CompletedAt.Before(c.StartedAt) || c.CompletedAt.After(r.LastAt) {
			return false
		}
		if r.State == "complete" && (c.Binding != r.Binding || !c.StartedAt.Equal(r.StartedAt) || !c.CompletedAt.Equal(r.CompletedAt)) {
			return false
		}
	} else if r.State == "complete" {
		return false
	}
	return true
}
func (s *Store) completeUpdatesAuthority(ctx context.Context, t *transaction, id, hash string, now time.Time) (enrollmentstate.Snapshot, completeUpdatesRecord, error) {
	zero := enrollmentstate.Snapshot{}
	if !t.completeUpdatesEnabled {
		return zero, completeUpdatesRecord{}, ErrCompleteUpdatesNotConfigured
	}
	// Authenticate against the fresh authority and exact issued leaf. This does
	// not use the system observation clock or either existing replay sequence.
	if !enrollmentcrypto.ValidID(id, "invite_") || !enrollmentcrypto.ValidHash(hash) || !validStoreTime(now) {
		return zero, completeUpdatesRecord{}, enrollmentstate.ErrInvalid
	}
	snap, e := t.engine.Get(id)
	if e != nil {
		return zero, completeUpdatesRecord{}, e
	}
	if !completeProfile(snap.Binding.CollectionProfile) || snap.Platform != "linux" {
		return zero, completeUpdatesRecord{}, enrollmentstate.ErrProof
	}
	if snap.State != enrollmentstate.Activated {
		return zero, completeUpdatesRecord{}, enrollmentstate.ErrState
	}
	if snap.Issuance.CertificateHash != hash {
		return zero, completeUpdatesRecord{}, enrollmentstate.ErrProof
	}
	if now.Unix() < snap.UpdatedAt || now.Unix() < snap.Intent.NotBefore {
		return zero, completeUpdatesRecord{}, enrollmentstate.ErrInvalid
	}
	if now.Unix() >= snap.Intent.NotAfter {
		return zero, completeUpdatesRecord{}, enrollmentstate.ErrExpired
	}
	c, ok := t.credentials[id]
	if !ok {
		return zero, completeUpdatesRecord{}, ErrStorage
	}
	intent, e := t.engine.TrustedRecordedIntent(id)
	if e != nil {
		return zero, completeUpdatesRecord{}, ErrStorage
	}
	if _, e = enrollmentcrypto.VerifyIssued(c.DER, s.issuerDER, intent, now); e != nil {
		return zero, completeUpdatesRecord{}, enrollmentstate.ErrProof
	}
	r, e := readCompleteUpdatesRecord(ctx, t, id)
	if errors.Is(e, inventoryledger.ErrNotFound) {
		return snap, completeUpdatesRecord{}, nil
	}
	if e != nil {
		return zero, r, e
	}
	if now.Before(r.LastAt) || r.MaintenanceAt != nil && now.Before(*r.MaintenanceAt) {
		return zero, r, enrollmentstate.ErrInvalid
	}
	return snap, r, nil
}
func (s *Store) completeUpdatesOperator(ctx context.Context, t *transaction, device string, now time.Time) (enrollmentstate.Snapshot, completeUpdatesRecord, error) {
	if !enrollmentcrypto.ValidID(device, "agent_") {
		return enrollmentstate.Snapshot{}, completeUpdatesRecord{}, enrollmentstate.ErrInvalid
	}
	for _, snap := range t.engine.Snapshots() {
		if snap.Approval.DeviceID == device {
			return s.completeUpdatesAuthority(ctx, t, snap.InvitationID, snap.Issuance.CertificateHash, now)
		}
	}
	return enrollmentstate.Snapshot{}, completeUpdatesRecord{}, enrollmentstate.ErrNotFound
}
func matchCompleteUpdates(r completeUpdatesRecord, b InventoryBinding) error {
	if !b.valid() {
		return enrollmentstate.ErrInvalid
	}
	if r.Binding.Sequence == 0 {
		return inventoryledger.ErrNotFound
	}
	if r.Binding != b || r.State == "aborted" || r.State == "source_failed" {
		return inventoryledger.ErrConflict
	}
	return nil
}
