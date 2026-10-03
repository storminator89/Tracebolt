package security_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
)

func enrollmentBoundaryID(prefix string, n byte) string {
	return prefix + hex.EncodeToString(bytes.Repeat([]byte{n}, 16))
}

func enrollmentBoundaryContext(now time.Time) enrollmentcrypto.ChallengeContext {
	return enrollmentcrypto.ChallengeContext{
		ManagerInstanceID: enrollmentBoundaryID("manager_", 1), Profile: "tls", Origin: "https://127.0.0.1:8443",
		CollectionProfile: enrollmentcrypto.CollectionProfile,
		InvitationID:      enrollmentBoundaryID("invite_", 2), ClaimID: enrollmentBoundaryID("claim_", 3),
		Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)), ExpiresAt: now.Unix() + 120,
	}
}

// This synthetic signer deliberately has no private key. The identity point
// with R = identity and S = 0 satisfies the uncofactored verification equation
// for every message, so generic Ed25519 verification is not proof of possession.
type enrollmentIdentitySigner struct{}

func (enrollmentIdentitySigner) Public() crypto.PublicKey {
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	pub[0] = 1
	return pub
}

func (enrollmentIdentitySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	sig := make([]byte, ed25519.SignatureSize)
	sig[0] = 1
	return sig, nil
}

func TestIndependentEnrollmentRejectsIdentityPointPossession(t *testing.T) {
	now := time.Unix(1800000000, 0)
	c := enrollmentBoundaryContext(now)
	signer := enrollmentIdentitySigner{}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "synthetic weak enrollment key"}}, signer)
	if err != nil {
		t.Fatal("synthetic CSR fixture:", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	requestID := enrollmentBoundaryID("request_", 6)
	message, err := enrollmentcrypto.ClaimSigningMessage(c, requestID, csr, secret, now)
	if err != nil {
		return // Rejecting the weak key before producing a transcript is correct.
	}
	sig, _ := signer.Sign(nil, message, crypto.Hash(0))
	body, err := json.Marshal(map[string]string{
		"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": c.ManagerInstanceID, "profile": c.Profile,
		"origin": c.Origin, "collectionProfile": c.CollectionProfile, "invitationId": c.InvitationID, "claimId": c.ClaimID,
		"requestId": requestID, "challenge": c.Challenge, "invitationSecret": secret,
		"csr": base64.RawStdEncoding.EncodeToString(csr), "proof": base64.RawStdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	if proof, err := enrollmentcrypto.VerifyClaim(body, c, now); err == nil || proof.Valid() {
		t.Fatal("identity-point key produced a verified claim without any private key")
	}
}
