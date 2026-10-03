package enrollmentcrypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"localrmm/internal/keyvalidation"
	"strconv"
	"time"
)

type activationInput struct {
	SchemaVersion     string `json:"schemaVersion"`
	ManagerInstanceID string `json:"managerInstanceId"`
	Profile           string `json:"profile"`
	Origin            string `json:"origin"`
	DeviceID          string `json:"deviceId"`
	IntentID          string `json:"intentId"`
	CertificateHash   string `json:"certificateHash"`
	RequestID         string `json:"requestId"`
	Challenge         string `json:"challenge"`
	Proof             string `json:"proof"`
}

func activationContext(c ChallengeContext, i Intent, now time.Time) bool {
	return validContext(c, now) && c.ManagerInstanceID == i.ManagerInstanceID && c.Profile == i.Profile && c.Origin == i.Origin && c.CollectionProfile == i.CollectionProfile && c.InvitationID == i.InvitationID && c.ClaimID == i.ClaimID
}
func ActivationSigningMessage(c ChallengeContext, i Intent, requestID, certificateHash string, now time.Time) ([]byte, error) {
	if ValidateIntent(i) != nil || !activationContext(c, i, now) || !ValidID(requestID, "request_") || !ValidHash(certificateHash) {
		return nil, ErrContract
	}
	intentDigest, _ := IntentDigest(i)
	return transcript("Tracebolt enrollment activation possession v2", intentDigest, i.ManagerInstanceID, i.Profile, i.Origin, i.CollectionProfile, i.DeviceID, i.IntentID, i.KeyFingerprint, certificateHash, requestID, c.Challenge, strconv.FormatInt(c.ExpiresAt, 10)), nil
}

// VerifyActivation proves current possession of the issued key for one fresh,
// explicit activation request. A public certificate alone cannot activate.
func VerifyActivation(raw []byte, certificate VerifiedCertificate, c ChallengeContext, now time.Time) (VerifiedActivation, error) {
	var zero VerifiedActivation
	if !certificate.Valid() || !activationContext(c, certificate.intent, now) || now.Unix() < certificate.intent.NotBefore || now.Unix() >= certificate.intent.NotAfter {
		return zero, ErrProof
	}
	var in activationInput
	if strictObject(raw, &in, "schemaVersion", "managerInstanceId", "profile", "origin", "deviceId", "intentId", "certificateHash", "requestId", "challenge", "proof") != nil {
		return zero, ErrContract
	}
	i := certificate.intent
	if in.SchemaVersion != ActivationVersion || in.ManagerInstanceID != i.ManagerInstanceID || in.Profile != i.Profile || in.Origin != i.Origin || in.DeviceID != i.DeviceID || in.IntentID != i.IntentID || in.CertificateHash != certificate.certificateHash || in.Challenge != c.Challenge {
		return zero, ErrProof
	}
	message, e := ActivationSigningMessage(c, i, in.RequestID, in.CertificateHash, now)
	if e != nil {
		return zero, e
	}
	signature, e := decodeBase64(in.Proof, ed25519.SignatureSize)
	if e != nil || len(signature) != ed25519.SignatureSize {
		return zero, ErrProof
	}
	cert, e := x509.ParseCertificate(certificate.der)
	if e != nil {
		return zero, ErrProof
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !keyvalidation.Ed25519(pub) || !ed25519.Verify(pub, message, signature) {
		return zero, ErrProof
	}
	return VerifiedActivation{seal: true, intent: i, certificateHash: in.CertificateHash, requestID: in.RequestID, expiresAt: c.ExpiresAt}, nil
}
