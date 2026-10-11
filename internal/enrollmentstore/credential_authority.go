package enrollmentstore

import (
	"context"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

type authenticatedCertificateKey struct{}

// WithAuthenticatedCertificate carries the actual authenticated transport leaf
// independently of the immutable enrollment identity used by scope grants. Only
// a transport that has verified certificate possession may install this value.
// Every consuming transaction checks it against its freshly loaded credential.
func WithAuthenticatedCertificate(ctx context.Context, certificateHash string) context.Context {
	return context.WithValue(ctx, authenticatedCertificateKey{}, certificateHash)
}

// currentCredential never changes the original enrollment intent or issuance.
// Those remain the stable grant/replay identity throughout same-key renewal.
func (t *transaction) currentCredential(snapshot enrollmentstate.Snapshot, c credential) (enrollmentcrypto.Intent, []byte, string, error) {
	if c.Renewal != nil {
		v := c.Renewal.Current
		return v.Intent, v.DER, v.CertificateHash, nil
	}
	intent, err := t.engine.TrustedRecordedIntent(snapshot.InvitationID)
	if err != nil {
		return enrollmentcrypto.Intent{}, nil, "", ErrStorage
	}
	return intent, c.DER, snapshot.Issuance.CertificateHash, nil
}

func (t *transaction) currentCertificateHash(snapshot enrollmentstate.Snapshot) string {
	c, ok := t.credentials[snapshot.InvitationID]
	if !ok {
		return ""
	}
	_, _, hash, err := t.currentCredential(snapshot, c)
	if err != nil {
		return ""
	}
	return hash
}

func (t *transaction) currentCredentialNotAfter(snapshot enrollmentstate.Snapshot) int64 {
	c, ok := t.credentials[snapshot.InvitationID]
	if !ok || c.Renewal == nil {
		return snapshot.Intent.NotAfter
	}
	return c.Renewal.Current.Intent.NotAfter
}

// Historical metadata can predate the current leaf, but never exceed the
// validated monotonically extended identity lifetime. This does not change any
// stored grant, request, capture, cache, or action deadline.
func recordAuthorityExpiry(snapshot enrollmentstate.Snapshot, expiry ...int64) int64 {
	if len(expiry) == 0 {
		return snapshot.Intent.NotAfter
	}
	if len(expiry) != 1 || expiry[0] < snapshot.Intent.NotAfter || expiry[0] > enrollmentstate.MaxTimestamp {
		return 0
	}
	return expiry[0]
}

// authorizeCurrentCredential maps only authenticated transport identity to the
// immutable anchor. A bare stale certificate hash is never accepted. Operator
// paths use currentCertificateHash while retaining the original grant bindings.
func (t *transaction) authorizeCurrentCredential(snapshot enrollmentstate.Snapshot, certificateHash string, now time.Time) error {
	if !validStoreTime(now) || !enrollmentcrypto.ValidHash(certificateHash) {
		return enrollmentstate.ErrInvalid
	}
	if snapshot.State != enrollmentstate.Activated {
		return enrollmentstate.ErrState
	}
	c, ok := t.credentials[snapshot.InvitationID]
	if !ok {
		return ErrStorage
	}
	intent, der, currentHash, err := t.currentCredential(snapshot, c)
	if err != nil {
		return err
	}
	if t.ctx != nil {
		if authenticated, present := t.ctx.Value(authenticatedCertificateKey{}).(string); present {
			if !enrollmentcrypto.ValidHash(authenticated) || authenticated != currentHash || certificateHash != snapshot.Issuance.CertificateHash && certificateHash != currentHash {
				return enrollmentstate.ErrProof
			}
			certificateHash = authenticated
		}
	}
	if certificateHash != currentHash {
		return enrollmentstate.ErrProof
	}
	if now.Unix() < snapshot.UpdatedAt || now.Unix() < intent.NotBefore || c.Renewal != nil && (now.Unix() < c.Renewal.UpdatedAt || now.Unix() < c.Renewal.Current.ActivatedAt) {
		return enrollmentstate.ErrInvalid
	}
	if now.Unix() >= intent.NotAfter {
		return enrollmentstate.ErrExpired
	}
	verified, err := enrollmentcrypto.VerifyIssued(der, t.issuerDER, intent, now)
	if err != nil || verified.CertificateHash() != currentHash {
		return enrollmentstate.ErrProof
	}
	return nil
}
