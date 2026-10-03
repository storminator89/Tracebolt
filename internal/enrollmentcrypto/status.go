package enrollmentcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"localrmm/internal/keyvalidation"
	"strconv"
	"time"
)

const StatusVersion = "tracebolt.enrollment-status.v2"
const PurposeStatus = "status"
const PurposeCredential = "credential"

// VerifiedStatus is a fresh proof by the already-bound claim key. It does not
// authorize a lifecycle transition: the durable store must still check its
// current binding, deadline, phase and revocation in the consuming transaction.
type VerifiedStatus struct {
	seal                               bool
	context                            ChallengeContext
	purpose, requestID, keyFingerprint string
}

func (v VerifiedStatus) Valid() bool                { return v.seal }
func (v VerifiedStatus) InstanceID() string         { return v.context.ManagerInstanceID }
func (v VerifiedStatus) ManagerInstanceID() string  { return v.context.ManagerInstanceID }
func (v VerifiedStatus) Profile() string            { return v.context.Profile }
func (v VerifiedStatus) Origin() string             { return v.context.Origin }
func (v VerifiedStatus) CollectionProfile() string  { return v.context.CollectionProfile }
func (v VerifiedStatus) InvitationID() string       { return v.context.InvitationID }
func (v VerifiedStatus) ClaimID() string            { return v.context.ClaimID }
func (v VerifiedStatus) KeyFingerprint() string     { return v.keyFingerprint }
func (v VerifiedStatus) RequestID() string          { return v.requestID }
func (v VerifiedStatus) Purpose() string            { return v.purpose }
func (v VerifiedStatus) ExpiresAt() int64           { return v.context.ExpiresAt }
func (VerifiedStatus) String() string               { return "enrollmentcrypto.VerifiedStatus{proof:redacted}" }
func (VerifiedStatus) GoString() string             { return "enrollmentcrypto.VerifiedStatus{proof:redacted}" }
func (VerifiedStatus) MarshalJSON() ([]byte, error) { return []byte(`{"proofRedacted":true}`), nil }

type statusInput struct {
	SchemaVersion     string `json:"schemaVersion"`
	ManagerInstanceID string `json:"managerInstanceId"`
	Profile           string `json:"profile"`
	Origin            string `json:"origin"`
	CollectionProfile string `json:"collectionProfile"`
	InvitationID      string `json:"invitationId"`
	ClaimID           string `json:"claimId"`
	KeyFingerprint    string `json:"keyFingerprint"`
	RequestID         string `json:"requestId"`
	Purpose           string `json:"purpose"`
	Challenge         string `json:"challenge"`
	Proof             string `json:"proof"`
}

func statusKey(der []byte) (ed25519.PublicKey, error) {
	if len(der) == 0 || len(der) > 1024 {
		return nil, ErrContract
	}
	key, e := x509.ParsePKIXPublicKey(der)
	pub, ok := key.(ed25519.PublicKey)
	if e != nil || !ok || !keyvalidation.Ed25519(pub) {
		return nil, ErrProof
	}
	canonical, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil || !bytes.Equal(canonical, der) {
		return nil, ErrContract
	}
	return pub, nil
}

// StatusSigningMessage constructs a versioned, purpose-separated message.
// publicKeyDER must come from the client's key or the trusted stored claim,
// never an unauthenticated request field used as the server's trust source.
func StatusSigningMessage(c ChallengeContext, purpose, requestID string, publicKeyDER []byte, now time.Time) ([]byte, error) {
	if !validContext(c, now) || !ValidID(requestID, "request_") || (purpose != PurposeStatus && purpose != PurposeCredential) {
		return nil, ErrContract
	}
	if _, e := statusKey(publicKeyDER); e != nil {
		return nil, e
	}
	return transcript("Tracebolt enrollment status possession v2", c.ManagerInstanceID, c.Profile, c.Origin, c.CollectionProfile, c.InvitationID, c.ClaimID, hash(publicKeyDER), purpose, requestID, c.Challenge, strconv.FormatInt(c.ExpiresAt, 10)), nil
}
func VerifyStatus(raw []byte, publicKeyDER []byte, c ChallengeContext, now time.Time) (VerifiedStatus, error) {
	var zero VerifiedStatus
	if !validContext(c, now) {
		return zero, ErrContract
	}
	var in statusInput
	if strictObject(raw, &in, "schemaVersion", "managerInstanceId", "profile", "origin", "collectionProfile", "invitationId", "claimId", "keyFingerprint", "requestId", "purpose", "challenge", "proof") != nil {
		return zero, ErrContract
	}
	if in.SchemaVersion != StatusVersion || in.ManagerInstanceID != c.ManagerInstanceID || in.Profile != c.Profile || in.Origin != c.Origin || in.CollectionProfile != c.CollectionProfile || in.InvitationID != c.InvitationID || in.ClaimID != c.ClaimID || in.Challenge != c.Challenge || in.KeyFingerprint != hash(publicKeyDER) {
		return zero, ErrProof
	}
	message, e := StatusSigningMessage(c, in.Purpose, in.RequestID, publicKeyDER, now)
	if e != nil {
		return zero, e
	}
	pub, e := statusKey(publicKeyDER)
	if e != nil {
		return zero, e
	}
	signature, e := decodeBase64(in.Proof, ed25519.SignatureSize)
	if e != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(pub, message, signature) {
		return zero, ErrProof
	}
	return VerifiedStatus{seal: true, context: c, purpose: in.Purpose, requestID: in.RequestID, keyFingerprint: in.KeyFingerprint}, nil
}
