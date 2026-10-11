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
			if snapshot.Issuance.CertificateHash == "" {
				continue
			}
			cred, ok := t.credentials[snapshot.InvitationID]
			if !ok {
				return enrollmentstate.Snapshot{}, ErrStorage
			}
			_, currentDER, currentHash, err := t.currentCredential(snapshot, cred)
			if err != nil {
				return enrollmentstate.Snapshot{}, err
			}
			if currentHash != fingerprint {
				continue
			}
			if !bytes.Equal(currentDER, der) {
				return enrollmentstate.Snapshot{}, enrollmentstate.ErrProof
			}
			if err = t.authorizeCurrentCredential(snapshot, fingerprint, now); err != nil {
				return enrollmentstate.Snapshot{}, err
			}
			return snapshot, nil
		}
		return enrollmentstate.Snapshot{}, enrollmentstate.ErrNotFound
	})
}
