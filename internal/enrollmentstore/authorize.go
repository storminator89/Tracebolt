package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

// AuthorizeCertificate is a privileged local public-certificate lookup. It
// proves neither TLS nor private-key possession and must not be exposed as a
// native enrollment endpoint. Authority is read afresh from the durable store,
// never from names, a request body, or a cached approval. The caller must still
// use SaveObservation on this same store to atomically recheck current state,
// exact certificate identity and replay when committing telemetry.
func (s *Store) AuthorizeCertificate(ctx context.Context, der []byte, now time.Time) (enrollmentstate.Snapshot, error) {
	if len(der) == 0 || len(der) > enrollmentcrypto.MaxCertificateBytes || !validStoreTime(now) {
		return enrollmentstate.Snapshot{}, enrollmentstate.ErrInvalid
	}
	der = bytes.Clone(der)
	sum := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(sum[:])
	return s.command(ctx, func(t *transaction) (enrollmentstate.Snapshot, error) {
		for _, snapshot := range t.engine.Snapshots() {
			if snapshot.Issuance.CertificateHash != fingerprint {
				continue
			}
			cred, ok := t.credentials[snapshot.InvitationID]
			if !ok {
				return enrollmentstate.Snapshot{}, ErrStorage
			}
			if !bytes.Equal(cred.DER, der) {
				return enrollmentstate.Snapshot{}, enrollmentstate.ErrProof
			}
			if snapshot.State != enrollmentstate.Activated {
				return enrollmentstate.Snapshot{}, enrollmentstate.ErrState
			}
			if now.Unix() < snapshot.UpdatedAt || now.Unix() < snapshot.Intent.NotBefore {
				return enrollmentstate.Snapshot{}, enrollmentstate.ErrInvalid
			}
			if now.Unix() >= snapshot.Intent.NotAfter {
				return enrollmentstate.Snapshot{}, enrollmentstate.ErrExpired
			}
			intent, err := t.engine.TrustedRecordedIntent(snapshot.InvitationID)
			if err != nil {
				return enrollmentstate.Snapshot{}, ErrStorage
			}
			if _, err = enrollmentcrypto.VerifyIssued(der, s.issuerDER, intent, now); err != nil {
				return enrollmentstate.Snapshot{}, enrollmentstate.ErrProof
			}
			return snapshot, nil
		}
		return enrollmentstate.Snapshot{}, enrollmentstate.ErrNotFound
	})
}
