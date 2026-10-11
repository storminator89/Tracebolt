package enrollmentcrypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"
)

const RenewalPolicySameKey = "same-key-v1"
const RenewableClaimVersion = "tracebolt.enrollment-claim.renewable.v1"
const RenewalVersion = "tracebolt.enrollment-renewal.v1"
const PurposeRenewalStatus = "renewal-status"
const PurposeRenewalIssue = "renewal-issue"
const PurposeRenewalActivate = "renewal-activate"
const RenewalLifetimeSeconds int64 = 7 * 24 * 60 * 60
const RenewalWindowSeconds int64 = 48 * 60 * 60

// RenewalContext is server-owned, short-lived context for one exact credential.
// Credential generation advances while the original identity generation and
// same-key anchor remain unchanged. It is never authority supplied by a caller.
type RenewalContext struct {
	ChallengeContext
	IdentityGeneration   string `json:"identityGeneration"`
	CredentialGeneration uint64 `json:"credentialGeneration"`
	CertificateHash      string `json:"certificateHash"`
	DeviceID             string `json:"deviceId"`
	KeyFingerprint       string `json:"keyFingerprint"`
	Revision             uint64 `json:"revision"`
	Purpose              string `json:"purpose"`
}

// RenewalProof uses canonical decimal strings, like the existing bounded proof
// contracts. Context responses use JSON numbers for generations and revision.
type RenewalProof struct {
	SchemaVersion        string `json:"schemaVersion"`
	ManagerInstanceID    string `json:"managerInstanceId"`
	Profile              string `json:"profile"`
	Origin               string `json:"origin"`
	AgentOrigin          string `json:"agentOrigin"`
	CollectionProfile    string `json:"collectionProfile"`
	InvitationID         string `json:"invitationId"`
	ClaimID              string `json:"claimId"`
	IdentityGeneration   string `json:"identityGeneration"`
	CredentialGeneration string `json:"credentialGeneration"`
	CertificateHash      string `json:"certificateHash"`
	DeviceID             string `json:"deviceId"`
	KeyFingerprint       string `json:"keyFingerprint"`
	Revision             string `json:"revision"`
	Purpose              string `json:"purpose"`
	RequestID            string `json:"requestId"`
	Challenge            string `json:"challenge"`
	Proof                string `json:"proof"`
}

type VerifiedRenewal struct {
	seal      bool
	context   RenewalContext
	requestID string
}

func (v VerifiedRenewal) Valid() bool                { return v.seal }
func (v VerifiedRenewal) Context() RenewalContext    { return v.context }
func (v VerifiedRenewal) RequestID() string          { return v.requestID }
func (VerifiedRenewal) String() string               { return "enrollmentcrypto.VerifiedRenewal{proof:redacted}" }
func (VerifiedRenewal) GoString() string             { return "enrollmentcrypto.VerifiedRenewal{proof:redacted}" }
func (VerifiedRenewal) MarshalJSON() ([]byte, error) { return []byte(`{"proofRedacted":true}`), nil }

func ValidRenewalPurpose(p string) bool {
	return p == PurposeRenewalStatus || p == PurposeRenewalIssue || p == PurposeRenewalActivate
}
func validRenewalContext(c RenewalContext, now time.Time) bool {
	return validContext(c.ChallengeContext, now) && c.Profile == "tls" && c.RenewalPolicy == RenewalPolicySameKey && canonicalOrigin(c.AgentOrigin, "tls") && c.ExpiresAt <= now.Unix()+60 && ValidID(c.IdentityGeneration, "identity_") && c.CredentialGeneration > 0 && c.CredentialGeneration <= uint64(1<<63-1) && c.Revision > 0 && c.Revision <= uint64(1<<63-1) && ValidID(c.DeviceID, "agent_") && ValidHash(c.KeyFingerprint) && ValidHash(c.CertificateHash) && ValidRenewalPurpose(c.Purpose)
}
func RenewalSigningMessage(c RenewalContext, requestID string, now time.Time) ([]byte, error) {
	if !validRenewalContext(c, now) || !ValidID(requestID, "request_") {
		return nil, ErrContract
	}
	return transcript("Tracebolt same-key renewal possession v1", c.ManagerInstanceID, c.Profile, c.Origin, c.AgentOrigin, c.CollectionProfile, c.InvitationID, c.ClaimID, c.IdentityGeneration, strconv.FormatUint(c.CredentialGeneration, 10), c.CertificateHash, c.DeviceID, c.KeyFingerprint, strconv.FormatUint(c.Revision, 10), c.Purpose, requestID, c.Challenge, strconv.FormatInt(c.ExpiresAt, 10)), nil
}
func RenewalProofJSON(c RenewalContext, requestID string, signature []byte) ([]byte, error) {
	if len(signature) != ed25519.SignatureSize {
		return nil, ErrProof
	}
	return json.Marshal(RenewalProof{SchemaVersion: RenewalVersion, ManagerInstanceID: c.ManagerInstanceID, Profile: c.Profile, Origin: c.Origin, AgentOrigin: c.AgentOrigin, CollectionProfile: c.CollectionProfile, InvitationID: c.InvitationID, ClaimID: c.ClaimID, IdentityGeneration: c.IdentityGeneration, CredentialGeneration: strconv.FormatUint(c.CredentialGeneration, 10), CertificateHash: c.CertificateHash, DeviceID: c.DeviceID, KeyFingerprint: c.KeyFingerprint, Revision: strconv.FormatUint(c.Revision, 10), Purpose: c.Purpose, RequestID: requestID, Challenge: c.Challenge, Proof: base64.RawStdEncoding.EncodeToString(signature)})
}
func VerifyRenewal(raw, publicKeyDER []byte, c RenewalContext, now time.Time) (VerifiedRenewal, error) {
	var in RenewalProof
	if !validRenewalContext(c, now) || hash(publicKeyDER) != c.KeyFingerprint || strictObject(raw, &in, "schemaVersion", "managerInstanceId", "profile", "origin", "agentOrigin", "collectionProfile", "invitationId", "claimId", "identityGeneration", "credentialGeneration", "certificateHash", "deviceId", "keyFingerprint", "revision", "purpose", "requestId", "challenge", "proof") != nil {
		return VerifiedRenewal{}, ErrContract
	}
	signature, e := decodeBase64(in.Proof, ed25519.SignatureSize)
	if e != nil {
		return VerifiedRenewal{}, ErrProof
	}
	expected, e := RenewalProofJSON(c, in.RequestID, signature)
	if e != nil {
		return VerifiedRenewal{}, e
	}
	var canonical RenewalProof
	if json.Unmarshal(expected, &canonical) != nil || canonical != in {
		return VerifiedRenewal{}, ErrProof
	}
	message, e := RenewalSigningMessage(c, in.RequestID, now)
	if e != nil {
		return VerifiedRenewal{}, e
	}
	key, e := statusKey(publicKeyDER)
	if e != nil || !ed25519.Verify(key, message, signature) {
		return VerifiedRenewal{}, ErrProof
	}
	return VerifiedRenewal{seal: true, context: c, requestID: in.RequestID}, nil
}

// RenewalIdentityGeneration is unique to the original immutable issuance.
func RenewalIdentityGeneration(anchor Intent) (string, error) {
	if ValidateIntent(anchor) != nil || anchor.Profile != "tls" {
		return "", ErrContract
	}
	return "identity_" + hash(transcript("Tracebolt renewable identity generation v1", anchor.ManagerInstanceID, anchor.InvitationID, anchor.ClaimID, anchor.IntentID, anchor.DeviceID, anchor.KeyFingerprint))[:32], nil
}
