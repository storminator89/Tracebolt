package windowscustomerflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
)

// PendingCandidate joins public profile bytes, a verified original customer
// claim, the independently retained local public key and the manager's original
// pending deadline to the existing consent-bound transition model. The exact
// profile digest, executable and service digests must come from separately
// authenticated/protected local provenance, not the same untrusted response.
// The caller must separately authenticate the manager response and persist the
// original deadline; this function cannot prove response origin, persistence,
// an issuer's live status, key custody or operator approval. Claim verification
// is not challenge consumption. It deliberately does not require that the old
// challenge still be live: a confirmed pending response can arrive later.
//
// This creates only an in-memory candidate. It cannot create keys, read or write
// state, contact a manager, install/start a service, issue credentials or grant
// permissions. A restart-safe protected identity, independently retained used
// marker and durable Journal guard/reconciliation owner remain runtime gates.
// This path never reads or adopts an existing invitation/v2 ledger or grant.
func PendingCandidate(profileRaw []byte, originalProfileDigest string, proof customerclaim.Verified, localPublicKeyDER []byte, originalDeadline int64, executableDigest, serviceDigest string, consent Consent, now time.Time) (State, error) {
	if len(profileRaw) == 0 || !enrollmentcrypto.ValidHash(originalProfileDigest) || !proof.Valid() || len(localPublicKeyDER) == 0 || len(localPublicKeyDER) > 1024 || now.IsZero() || now.Unix() <= 0 || now.Unix() > maxTimestamp-int64(customerpending.PendingLifetime/time.Second) || originalDeadline <= now.Unix() || originalDeadline > now.Unix()+int64(customerpending.PendingLifetime/time.Second) {
		return State{}, ErrInvalid
	}
	profileRaw = bytes.Clone(profileRaw)
	key := bytes.Clone(localPublicKeyDER)
	hash := sha256.Sum256(profileRaw)
	if hex.EncodeToString(hash[:]) != originalProfileDigest {
		return State{}, ErrInvalid
	}
	profile, display, err := enrollmentclient.ParseCustomerProfile(profileRaw, now)
	if err != nil {
		return State{}, ErrInvalid
	}
	m := proof.Metadata()
	if !customerclaim.ValidateStoredMetadata(m, key) || !bytes.Equal(proof.PublicKeyDER(), key) || profile.ManagerInstanceID != m.ManagerID || profile.CustomerID != m.CustomerID || profile.InstallerProfileID != m.InstallerProfileID || profile.EnrollmentOrigin != m.Origin || profile.AgentOrigin != m.AgentOrigin || display.IssuerFingerprint != m.IssuerFingerprint {
		return State{}, ErrInvalid
	}
	b := Binding{ManagerID: m.ManagerID, CustomerID: m.CustomerID, InstallerProfileID: m.InstallerProfileID, ClaimID: m.ClaimID, ClaimHash: m.ClaimHash, KeyFingerprint: m.KeyFingerprint, IssuerFingerprint: m.IssuerFingerprint, ProfileDigest: originalProfileDigest, ExecutableDigest: executableDigest, ServiceDigest: serviceDigest, DeadlineAt: originalDeadline}
	return New(b, consent, now)
}
