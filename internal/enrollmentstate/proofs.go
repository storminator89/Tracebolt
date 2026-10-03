package enrollmentstate

import (
	"context"
	"crypto/subtle"
	"encoding/base64"

	"localrmm/internal/enrollmentcrypto"
)

// Claim consumes only a concrete cryptographically verified proof. A caller
// cannot replace verification with a boolean or implement its own proof type.
// The invitation verifier is compared in constant time and is never exported.
func (e *Engine) Claim(ctx context.Context, c ClaimCommand, proof enrollmentcrypto.VerifiedClaim) (Snapshot, error) {
	if e == nil || e.engineState == nil || validateClaim(c) != nil {
		return Snapshot{}, ErrInvalid
	}
	if err := contextError(ctx); err != nil {
		return Snapshot{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.lookup(ctx, c.Control)
	if err != nil {
		return Snapshot{}, err
	}
	s := r.snapshot
	h := proof.InvitationHash()
	if !proof.Valid() || proof.InstanceID() != s.Binding.InstanceID || proof.Profile() != s.Binding.Profile || proof.Origin() != s.Binding.Origin || proof.CollectionProfile() != s.Binding.CollectionProfile || proof.InvitationID() != s.InvitationID || proof.ClaimID() != c.ClaimID || proof.RequestID() != c.Control.RequestID || proof.ExpiresAt() <= c.Control.Now || subtle.ConstantTimeCompare(r.verifier[:], h[:]) != 1 {
		return Snapshot{}, ErrProof
	}
	b := ClaimBinding{ClaimID: proof.ClaimID(), RequestID: proof.RequestID(), KeyFingerprint: proof.KeyFingerprint(), CSRHash: proof.CSRHash(), ClaimHash: proof.ClaimHash(), ComparisonCode: proof.ComparisonCode(), At: c.Control.Now}
	if s.State == ClaimedPending {
		b.At = s.Claim.At
		if b != s.Claim {
			return Snapshot{}, ErrConflict
		}
		return s, nil
	}
	if s.State != Created {
		return Snapshot{}, ErrState
	}
	if err := e.cas(s, c.Control); err != nil {
		return Snapshot{}, err
	}
	if e.pendingCount() >= e.config.PendingLimit {
		return Snapshot{}, ErrCapacity
	}
	for _, r := range e.records {
		if r.snapshot.Claim.ClaimID == c.ClaimID {
			return Snapshot{}, ErrConflict
		}
	}
	if c.Control.Now > MaxTimestamp-e.config.PendingTTL {
		return Snapshot{}, ErrInvalid
	}
	r.publicKeyDERBase64 = base64.RawStdEncoding.EncodeToString(proof.PublicKeyDER())
	s.State = ClaimedPending
	s.Claim = b
	s.DeadlineAt = c.Control.Now + e.config.PendingTTL
	return e.commit(ctx, r, s, c.Control.Now)
}

func expectedIntent(r record) enrollmentcrypto.Intent {
	s := r.snapshot
	return enrollmentcrypto.Intent{
		ManagerInstanceID: s.Binding.InstanceID, Profile: s.Binding.Profile, Origin: s.Binding.Origin, CollectionProfile: s.Binding.CollectionProfile,
		InvitationID: s.InvitationID, ClaimID: s.Claim.ClaimID, RequestID: s.Intent.RequestID, DeviceID: s.Approval.DeviceID, IntentID: s.Intent.IntentID,
		KeyFingerprint: s.Claim.KeyFingerprint, PublicKeyDERBase64: r.publicKeyDERBase64, CSRHash: s.Claim.CSRHash, ClaimHash: s.Claim.ClaimHash,
		IssuerFingerprint: s.Binding.IssuerFingerprint, SerialHex: s.Intent.SerialHex, TemplateVersion: s.Intent.TemplateVersion, KeyGeneration: 1,
		NotBefore: s.Intent.NotBefore, NotAfter: s.Intent.NotAfter,
	}
}

func validateSigningIntent(r record, s Snapshot) error {
	r.snapshot = s
	if enrollmentcrypto.ValidateIntent(expectedIntent(r)) != nil {
		return ErrInvalid
	}
	return nil
}

// SigningIntent exports the exact immutable description after BeginIssuance.
// This process-local record has NOT been durably persisted. No signer should be
// integrated until transactional persistence and reconciliation are implemented.
// now must come from the trusted manager clock, never a client timestamp.
func (e *Engine) SigningIntent(id string, now int64) (enrollmentcrypto.Intent, error) {
	if e == nil || e.engineState == nil || !validID(id, "invite") || !validTime(now) {
		return enrollmentcrypto.Intent{}, ErrInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.records[id]
	if !ok {
		return enrollmentcrypto.Intent{}, ErrNotFound
	}
	if r.snapshot.State != IssuanceIntent {
		return enrollmentcrypto.Intent{}, ErrState
	}
	if now < r.snapshot.UpdatedAt {
		return enrollmentcrypto.Intent{}, ErrInvalid
	}
	if now >= r.snapshot.DeadlineAt || now >= r.snapshot.Intent.NotAfter {
		return enrollmentcrypto.Intent{}, ErrExpired
	}
	if err := validateSigningIntent(r, r.snapshot); err != nil {
		return enrollmentcrypto.Intent{}, err
	}
	return expectedIntent(r), nil
}

// CommitIssued models an external result's authorization by retaining its hash
// and matching it against the complete fixed intent. It does not retain DER,
// deliver a credential, or recover an interrupted signing/delivery operation.
func (e *Engine) CommitIssued(ctx context.Context, c Control, proof enrollmentcrypto.VerifiedCertificate) (Snapshot, error) {
	if e == nil || e.engineState == nil || validateControl(c) != nil {
		return Snapshot{}, ErrInvalid
	}
	if err := contextError(ctx); err != nil {
		return Snapshot{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.lookup(ctx, c)
	if err != nil {
		return Snapshot{}, err
	}
	s := r.snapshot
	if !proof.Valid() || proof.Intent() != expectedIntent(r) || !validHash(proof.CertificateHash()) || c.Now < s.Intent.NotBefore || c.Now >= s.Intent.NotAfter {
		return Snapshot{}, ErrProof
	}
	if s.State == Issued {
		if c.RequestID != s.Issuance.RequestID || proof.CertificateHash() != s.Issuance.CertificateHash {
			return Snapshot{}, ErrConflict
		}
		return s, nil
	}
	if s.State != IssuanceIntent {
		return Snapshot{}, ErrState
	}
	if err := e.cas(s, c); err != nil {
		return Snapshot{}, err
	}
	for _, r := range e.records {
		if r.snapshot.Issuance.CertificateHash == proof.CertificateHash() {
			return Snapshot{}, ErrConflict
		}
	}
	s.State = Issued
	s.Issuance = Issuance{RequestID: c.RequestID, CertificateHash: proof.CertificateHash(), At: c.Now}
	return e.commit(ctx, r, s, c.Now)
}

// Activate requires a separate, challenge-bound proof of possession for this
// exact issued certificate and intent. It models activation authorization only:
// there is no telemetry request, installed service or live connection here.
func (e *Engine) Activate(ctx context.Context, c Control, proof enrollmentcrypto.VerifiedActivation) (Snapshot, error) {
	if e == nil || e.engineState == nil || validateControl(c) != nil {
		return Snapshot{}, ErrInvalid
	}
	if err := contextError(ctx); err != nil {
		return Snapshot{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.lookup(ctx, c)
	if err != nil {
		return Snapshot{}, err
	}
	s := r.snapshot
	if !proof.Valid() || proof.Intent() != expectedIntent(r) || proof.CertificateHash() != s.Issuance.CertificateHash || proof.RequestID() != c.RequestID || proof.ExpiresAt() <= c.Now || c.Now < s.Intent.NotBefore || c.Now >= s.Intent.NotAfter {
		return Snapshot{}, ErrProof
	}
	if s.State == Activated {
		if s.Activation.RequestID != c.RequestID {
			return Snapshot{}, ErrConflict
		}
		return s, nil
	}
	if s.State != Issued {
		return Snapshot{}, ErrState
	}
	if err := e.cas(s, c); err != nil {
		return Snapshot{}, err
	}
	s.State = Activated
	s.Activation = Activation{RequestID: c.RequestID, At: c.Now}
	return e.commit(ctx, r, s, c.Now)
}
