// Package enrollmentcrypto validates bounded enrollment proofs and fixed
// certificate intents. It has no network, filesystem, key-generation or issuer
// operations. Callers must supply trusted server-side challenge/intent context.
package enrollmentcrypto

import (
	"bytes"
	"errors"
)

const ClaimVersion = "tracebolt.enrollment-claim.v2"
const ActivationVersion = "tracebolt.enrollment-activation.v2"
const TemplateVersion = "tracebolt.enrollment.client.v2"
const CollectionProfile = "basic-readonly-v1"
const CollectionProfileOperational = "managed-operations-v1"
const CollectionProfilePackages = "managed-operations-v2"

// ValidCollectionProfile admits only explicitly implemented, consent-bound profiles.
func ValidCollectionProfile(profile string) bool {
	return profile == CollectionProfile || ManagedCollectionProfile(profile)
}

// ManagedCollectionProfile identifies explicit managed metadata scopes. It does
// not authorize any frame; the exact frame/profile pair is validated separately.
func ManagedCollectionProfile(profile string) bool {
	return profile == CollectionProfileOperational || profile == CollectionProfilePackages
}

const MaxClaimBytes = 16 * 1024
const MaxCSRBytes = 8 * 1024
const MaxCertificateBytes = 8 * 1024

var ErrContract = errors.New("enrollment contract is invalid")
var ErrProof = errors.New("enrollment proof is invalid")
var ErrCertificate = errors.New("issued certificate violates the fixed enrollment intent")

// ChallengeContext comes from the server's bounded, expiring challenge record,
// never from untrusted body fields. A constructor does not itself grant trust.
type ChallengeContext struct {
	ManagerInstanceID string `json:"managerInstanceId"`
	Profile           string `json:"profile"`
	Origin            string `json:"origin"`
	CollectionProfile string `json:"collectionProfile"`
	InvitationID      string `json:"invitationId"`
	ClaimID           string `json:"claimId"`
	Challenge         string `json:"challenge"`
	ExpiresAt         int64  `json:"expiresAt"`
}
type ClaimMetadata struct {
	ManagerInstanceID string
	Profile           string
	Origin            string
	CollectionProfile string
	InvitationID      string
	ClaimID           string
	RequestID         string
	KeyFingerprint    string
	CSRHash           string
	ClaimHash         string
	ComparisonCode    string
	ExpiresAt         int64
}
type VerifiedClaim struct {
	seal           bool
	metadata       ClaimMetadata
	invitationHash [32]byte
	publicKeyDER   []byte
}

func (v VerifiedClaim) Valid() bool                { return v.seal }
func (v VerifiedClaim) Metadata() ClaimMetadata    { return v.metadata }
func (v VerifiedClaim) InstanceID() string         { return v.metadata.ManagerInstanceID }
func (v VerifiedClaim) Profile() string            { return v.metadata.Profile }
func (v VerifiedClaim) Origin() string             { return v.metadata.Origin }
func (v VerifiedClaim) CollectionProfile() string  { return v.metadata.CollectionProfile }
func (v VerifiedClaim) InvitationID() string       { return v.metadata.InvitationID }
func (v VerifiedClaim) ClaimID() string            { return v.metadata.ClaimID }
func (v VerifiedClaim) RequestID() string          { return v.metadata.RequestID }
func (v VerifiedClaim) KeyFingerprint() string     { return v.metadata.KeyFingerprint }
func (v VerifiedClaim) CSRHash() string            { return v.metadata.CSRHash }
func (v VerifiedClaim) ClaimHash() string          { return v.metadata.ClaimHash }
func (v VerifiedClaim) ComparisonCode() string     { return v.metadata.ComparisonCode }
func (v VerifiedClaim) ExpiresAt() int64           { return v.metadata.ExpiresAt }
func (v VerifiedClaim) InvitationHash() [32]byte   { return v.invitationHash }
func (v VerifiedClaim) PublicKeyDER() []byte       { return bytes.Clone(v.publicKeyDER) }
func (VerifiedClaim) String() string               { return "enrollmentcrypto.VerifiedClaim{proof:redacted}" }
func (VerifiedClaim) GoString() string             { return "enrollmentcrypto.VerifiedClaim{proof:redacted}" }
func (VerifiedClaim) MarshalJSON() ([]byte, error) { return []byte(`{"proofRedacted":true}`), nil }

// Intent is the complete fixed public issuance description to persist before
// an external signing operation. It contains no private key or invitation token.
type Intent struct {
	ManagerInstanceID  string `json:"managerInstanceId"`
	Profile            string `json:"profile"`
	Origin             string `json:"origin"`
	CollectionProfile  string `json:"collectionProfile"`
	InvitationID       string `json:"invitationId"`
	ClaimID            string `json:"claimId"`
	RequestID          string `json:"requestId"`
	DeviceID           string `json:"deviceId"`
	IntentID           string `json:"intentId"`
	KeyFingerprint     string `json:"keyFingerprint"`
	PublicKeyDERBase64 string `json:"publicKeyDerBase64"`
	CSRHash            string `json:"csrHash"`
	ClaimHash          string `json:"claimHash"`
	IssuerFingerprint  string `json:"issuerFingerprint"`
	SerialHex          string `json:"serialHex"`
	TemplateVersion    string `json:"templateVersion"`
	KeyGeneration      uint64 `json:"keyGeneration"`
	NotBefore          int64  `json:"notBefore"`
	NotAfter           int64  `json:"notAfter"`
}
type VerifiedCertificate struct {
	seal            bool
	intent          Intent
	certificateHash string
	der             []byte
}

func (v VerifiedCertificate) Valid() bool             { return v.seal }
func (v VerifiedCertificate) Intent() Intent          { return v.intent }
func (v VerifiedCertificate) CertificateHash() string { return v.certificateHash }
func (v VerifiedCertificate) DER() []byte             { return bytes.Clone(v.der) }
func (VerifiedCertificate) String() string {
	return "enrollmentcrypto.VerifiedCertificate{details:redacted}"
}
func (VerifiedCertificate) GoString() string {
	return "enrollmentcrypto.VerifiedCertificate{details:redacted}"
}
func (VerifiedCertificate) MarshalJSON() ([]byte, error) {
	return []byte(`{"detailsRedacted":true}`), nil
}

type VerifiedActivation struct {
	seal                       bool
	intent                     Intent
	certificateHash, requestID string
	expiresAt                  int64
}

func (v VerifiedActivation) Valid() bool             { return v.seal }
func (v VerifiedActivation) Intent() Intent          { return v.intent }
func (v VerifiedActivation) CertificateHash() string { return v.certificateHash }
func (v VerifiedActivation) RequestID() string       { return v.requestID }
func (v VerifiedActivation) ExpiresAt() int64        { return v.expiresAt }
func (VerifiedActivation) String() string {
	return "enrollmentcrypto.VerifiedActivation{proof:redacted}"
}
func (VerifiedActivation) GoString() string {
	return "enrollmentcrypto.VerifiedActivation{proof:redacted}"
}
func (VerifiedActivation) MarshalJSON() ([]byte, error) { return []byte(`{"proofRedacted":true}`), nil }
