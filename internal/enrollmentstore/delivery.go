package enrollmentstore

import (
	"bytes"
	"context"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

func validStatus(s enrollmentstate.Snapshot, proof enrollmentcrypto.VerifiedStatus, purpose string, now int64) bool {
	return now > 0 && now <= enrollmentstate.MaxTimestamp && now >= s.UpdatedAt && proof.Valid() && proof.Purpose() == purpose && proof.ExpiresAt() > now && proof.InstanceID() == s.Binding.InstanceID && proof.Profile() == s.Binding.Profile && proof.Origin() == s.Binding.Origin && proof.CollectionProfile() == s.Binding.CollectionProfile && proof.InvitationID() == s.InvitationID && proof.ClaimID() == s.Claim.ClaimID && proof.KeyFingerprint() == s.Claim.KeyFingerprint
}
func authorizationDeadline(s enrollmentstate.Snapshot) int64 {
	if s.State == enrollmentstate.Activated {
		return s.Intent.NotAfter
	}
	deadline := s.DeadlineAt
	if s.Intent.NotAfter != 0 && s.Intent.NotAfter < deadline {
		deadline = s.Intent.NotAfter
	}
	return deadline
}

// ReadStatus authorizes one fresh purpose-separated pending-key status proof
// inside the same transaction as the final lifecycle read. Terminal outcomes
// remain inspectable by their bound key, but never authorize another operation.
func (s *Store) ReadStatus(ctx context.Context, id string, proof enrollmentcrypto.VerifiedStatus, now time.Time) (enrollmentstate.Snapshot, error) {
	if !validStoreTime(now) {
		return enrollmentstate.Snapshot{}, enrollmentstate.ErrInvalid
	}
	at := now.Unix()
	return s.command(ctx, func(t *transaction) (enrollmentstate.Snapshot, error) {
		snapshot, err := t.engine.Get(id)
		if err != nil {
			return enrollmentstate.Snapshot{}, err
		}
		if !validStatus(snapshot, proof, enrollmentcrypto.PurposeStatus, at) {
			return enrollmentstate.Snapshot{}, enrollmentstate.ErrProof
		}
		switch snapshot.State {
		case enrollmentstate.Expired, enrollmentstate.Canceled, enrollmentstate.Rejected, enrollmentstate.Revoked:
			return snapshot, nil
		}
		if at >= authorizationDeadline(snapshot) {
			return enrollmentstate.Snapshot{}, enrollmentstate.ErrExpired
		}
		return snapshot, nil
	})
}

// DeliverCredential persists bounded idempotent delivery metadata before any
// DER is returned. Delivery is not activation or observation freshness. An exact
// retry returns the same DER, retaining its original timestamp and count. New
// requests replace only the last request ID while retaining first time/count.
func (s *Store) DeliverCredential(ctx context.Context, c enrollmentstate.Control, proof enrollmentcrypto.VerifiedStatus) ([]byte, error) {
	if !enrollmentcrypto.ValidID(c.InvitationID, "invite_") || !enrollmentcrypto.ValidID(c.RequestID, "request_") || c.ExpectedRevision == 0 || c.ExpectedRevision > enrollmentstate.MaxRevision || c.Now <= 0 || c.Now > enrollmentstate.MaxTimestamp {
		return nil, enrollmentstate.ErrInvalid
	}
	var out []byte
	err := s.transact(ctx, func(t *transaction) error {
		snapshot, err := t.engine.Get(c.InvitationID)
		if err != nil {
			return err
		}
		if !validStatus(snapshot, proof, enrollmentcrypto.PurposeCredential, c.Now) || proof.RequestID() != c.RequestID {
			return enrollmentstate.ErrProof
		}
		if snapshot.State != enrollmentstate.Issued && snapshot.State != enrollmentstate.Activated {
			return enrollmentstate.ErrState
		}
		if c.Now >= authorizationDeadline(snapshot) {
			return enrollmentstate.ErrExpired
		}
		cred, ok := t.credentials[c.InvitationID]
		if !ok {
			return ErrStorage
		}
		d := cred.Delivery
		if d.LastAt > c.Now {
			return enrollmentstate.ErrInvalid
		}
		if d.RequestID != c.RequestID {
			if c.ExpectedRevision != snapshot.Revision || d.Count >= enrollmentstate.MaxRevision {
				return enrollmentstate.ErrConflict
			}
			if d.Count == 0 {
				d.FirstAt = c.Now
			}
			d.RequestID = c.RequestID
			d.LastAt = c.Now
			d.Count++
			cred.Delivery = d
			t.credentials[c.InvitationID] = cred
		}
		out = bytes.Clone(cred.DER)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CertificateForVerification is a privileged local cryptographic lookup, never
// an endpoint response. It reconstructs only the already committed certificate
// and complete intent; it does not authorize delivery or activation. The final
// activation/telemetry transaction must recheck current lifecycle authority.
func (s *Store) CertificateForVerification(ctx context.Context, id string) (enrollmentcrypto.VerifiedCertificate, error) {
	var out enrollmentcrypto.VerifiedCertificate
	err := s.transact(ctx, func(t *transaction) error {
		snapshot, err := t.engine.Get(id)
		if err != nil {
			return err
		}
		cred, ok := t.credentials[id]
		if !ok {
			return enrollmentstate.ErrState
		}
		intent, err := t.engine.TrustedRecordedIntent(id)
		if err != nil {
			return err
		}
		out, err = enrollmentcrypto.VerifyIssued(cred.DER, s.issuerDER, intent, time.Unix(snapshot.Issuance.At, 0))
		return err
	})
	if err != nil {
		return enrollmentcrypto.VerifiedCertificate{}, err
	}
	return out, nil
}
