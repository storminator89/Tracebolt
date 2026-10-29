// Package customerv3proof specifies isolated possession proofs. It supplies no
// network endpoint, replay fence, durable authority, credential or activation.
package customerv3proof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"strconv"
	"time"

	"localrmm/internal/customerclaim"
	"localrmm/internal/customerissuance"
	"localrmm/internal/enrollmentcrypto"
)

type Purpose string

const (
	Credential Purpose = "credential"
	Activation Purpose = "activation"
)

var ErrProof = errors.New("invalid customer v3 possession proof")

// SigningMessage builds fixed, length-prefixed bytes for the original device
// key. Credential retrieval intentionally has no certificate hash: the client
// cannot know the certificate before receiving it. For activation it must be
// the hash of the exact credential already received. An authenticated way to
// give the client the exact intent binding remains a separate runtime gate.
// Intent includes operator/review data and must not be sent to devices as a
// shortcut. A source-only public projection exists; authenticated distribution
// and persistent local binding are still needed.
// On the server intent and challenge MUST come from protected committed state,
// never from the request. A challenge is not made single-use by this function.
func SigningMessage(intent customerissuance.Intent, purpose Purpose, challenge customerclaim.Context, requestID, certificateHash string, now time.Time) ([]byte, error) {
	if !customerissuance.Current(intent, now) || !customerclaim.ValidChallengeContext(challenge, now) || !enrollmentcrypto.ValidID(requestID, "request_") {
		return nil, ErrProof
	}
	if purpose != Credential && purpose != Activation || purpose == Credential && certificateHash != "" || purpose == Activation && !enrollmentcrypto.ValidHash(certificateHash) {
		return nil, ErrProof
	}
	p := intent.Approval.Candidate.Pending
	if challenge.ManagerID != p.ManagerID || challenge.CustomerID != p.CustomerID || challenge.InstallerProfileID != p.InstallerProfileID || challenge.ClaimID != p.ClaimID || challenge.Origin != p.Origin || challenge.AgentOrigin != p.AgentOrigin || challenge.IssuerFingerprint != p.IssuerFingerprint {
		return nil, ErrProof
	}
	digest, err := customerissuance.Digest(intent)
	if err != nil {
		return nil, ErrProof
	}
	fields := []string{"Tracebolt customer Windows v3 credential possession v1", string(purpose), digest, p.ManagerID, p.CustomerID, p.InstallerProfileID, p.ClaimID, p.ClaimHash, p.KeyFingerprint, p.Origin, p.AgentOrigin, p.IssuerFingerprint, requestID, challenge.Challenge, strconv.FormatInt(challenge.ExpiresAt, 10), certificateHash}
	var out bytes.Buffer
	for _, value := range fields {
		_ = binary.Write(&out, binary.BigEndian, uint32(len(value)))
		out.WriteString(value)
	}
	return out.Bytes(), nil
}

// Verify checks only one exact key signature against server-owned committed
// intent, a server-verified certificate and a server-owned challenge. The
// VerifiedCertificate must have been created from the exact committed DER and
// trusted issuer/root, not from request-supplied certificate bytes. Callers must
// separately establish durable exact intent/certificate binding, original v3
// identity, current authority, revocation, and consume a distinct
// purpose-specific challenge once with final time/lease checks. The bounded
// challenge pool has separate v3 purposes, but is not wired to this verifier
// or protected state. Verification alone is
// neither replay protection nor permission to deliver, activate, or collect.
func Verify(intent customerissuance.Intent, cert customerissuance.VerifiedCertificate, purpose Purpose, challenge customerclaim.Context, requestID string, signature []byte, now time.Time) error {
	digest, err := customerissuance.Digest(intent)
	if err != nil || !cert.Valid() || cert.IntentDigest() != digest || !enrollmentcrypto.ValidHash(cert.CertificateHash()) {
		return ErrProof
	}
	certHash := ""
	if purpose == Activation {
		certHash = cert.CertificateHash()
	}
	msg, err := SigningMessage(intent, purpose, challenge, requestID, certHash, now)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrProof
	}
	parsed, err := x509.ParsePKIXPublicKey(intent.Approval.Candidate.Pending.PublicKeyDER)
	if err != nil {
		return ErrProof
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(pub, msg, signature) {
		return ErrProof
	}
	return nil
}
