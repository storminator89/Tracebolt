package customerissuance

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"time"

	"localrmm/internal/enrollmentauthority"
	"localrmm/internal/enrollmentcrypto"
)

// VerifiedPublicLeaf records only a point-in-time public template and local
// binding check. It does not establish authenticated projection provenance,
// approval, committed issuance, current revocation, activation or consent.
type VerifiedPublicLeaf struct {
	valid                                           bool
	intentDigest, projectionDigest, certificateHash string
	der                                             []byte
}

func (v VerifiedPublicLeaf) Valid() bool              { return v.valid }
func (v VerifiedPublicLeaf) IntentDigest() string     { return v.intentDigest }
func (v VerifiedPublicLeaf) ProjectionDigest() string { return v.projectionDigest }
func (v VerifiedPublicLeaf) CertificateHash() string  { return v.certificateHash }
func (v VerifiedPublicLeaf) DER() []byte              { return bytes.Clone(v.der) }
func (VerifiedPublicLeaf) String() string {
	return "customerissuance.VerifiedPublicLeaf{certificate:redacted}"
}
func (VerifiedPublicLeaf) GoString() string {
	return "customerissuance.VerifiedPublicLeaf{certificate:redacted}"
}
func (VerifiedPublicLeaf) MarshalJSON() ([]byte, error) {
	return []byte(`{"certificateRedacted":true}`), nil
}

// VerifyPublicLeaf checks one leaf against the independently protected original
// local key/profile/claim, an authenticated public projection and explicitly
// trusted issuer/root. Inputs must not all come from the same untrusted server
// response. The issuer/root chain and fingerprint, original pending deadline,
// exact template and leaf signature are checked without ambient trust.
// PublicIntent.IntentDigest is an asserted binding to server-side state; the
// leaf does not contain it and this function cannot prove the assertion.
// Caller must separately enforce approval, revocation, v3-only identity,
// local consent and fresh authority at any persistence or activation edge.
func VerifyPublicLeaf(der, issuerDER, rootDER []byte, public PublicIntent, local LocalPublicBinding, now time.Time) (VerifiedPublicLeaf, error) {
	if len(der) == 0 || len(der) > enrollmentcrypto.MaxCertificateBytes || len(issuerDER) == 0 || len(issuerDER) > enrollmentcrypto.MaxCertificateBytes || len(rootDER) == 0 || len(rootDER) > enrollmentcrypto.MaxCertificateBytes || len(local.PublicKeyDER) == 0 || len(local.PublicKeyDER) > 1024 {
		return VerifiedPublicLeaf{}, ErrCertificate
	}
	raw, issuerRaw, rootRaw := bytes.Clone(der), bytes.Clone(issuerDER), bytes.Clone(rootDER)
	local.PublicKeyDER = bytes.Clone(local.PublicKeyDER)
	if MatchLocalPublic(public, local, now) != nil || enrollmentauthority.ValidatePublicAuthority(issuerRaw, rootRaw, public.IssuerFingerprint, now) != nil {
		return VerifiedPublicLeaf{}, ErrCertificate
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return VerifiedPublicLeaf{}, ErrCertificate
	}
	issuer, err := x509.ParseCertificate(issuerRaw)
	if err != nil {
		return VerifiedPublicLeaf{}, ErrCertificate
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || cert.NotBefore.Before(issuer.NotBefore) || cert.NotAfter.After(issuer.NotAfter) || !fixedLeafFields(cert, issuer, public.DeviceID, local.PublicKeyDER, public.SerialHex, public.NotBefore, public.NotAfter) || cert.CheckSignatureFrom(issuer) != nil {
		return VerifiedPublicLeaf{}, ErrCertificate
	}
	projection, err := CanonicalPublic(public)
	if err != nil {
		return VerifiedPublicLeaf{}, ErrCertificate
	}
	h := sha256.New()
	_, _ = h.Write([]byte(PublicVersion + "\x00"))
	_, _ = h.Write(projection)
	certHash := sha256.Sum256(raw)
	return VerifiedPublicLeaf{valid: true, intentDigest: public.IntentDigest, projectionDigest: hex.EncodeToString(h.Sum(nil)), certificateHash: hex.EncodeToString(certHash[:]), der: raw}, nil
}
