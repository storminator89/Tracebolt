package customerissuance

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"time"

	"localrmm/internal/enrollmentcrypto"
)

var ErrCertificate = errors.New("customer certificate violates fixed issuance intent")

// VerifiedCertificate is a public verification result, not approval,
// persistence, credential delivery, activation or a currently valid lease.
// Current manager, issuer, enrollment and revocation checks remain mandatory
// immediately before persistence, delivery and use.
type VerifiedCertificate struct {
	valid        bool
	intentDigest string
	certHash     string
	der          []byte
}

func (v VerifiedCertificate) Valid() bool             { return v.valid }
func (v VerifiedCertificate) IntentDigest() string    { return v.intentDigest }
func (v VerifiedCertificate) CertificateHash() string { return v.certHash }
func (v VerifiedCertificate) DER() []byte             { return bytes.Clone(v.der) }
func (VerifiedCertificate) String() string {
	return "customerissuance.VerifiedCertificate{certificate:redacted}"
}
func (VerifiedCertificate) GoString() string {
	return "customerissuance.VerifiedCertificate{certificate:redacted}"
}
func (VerifiedCertificate) MarshalJSON() ([]byte, error) {
	return []byte(`{"certificateRedacted":true}`), nil
}

// fixedExtensions defines this v3 template's exact DER and criticality. The
// leaf has no SKI, SAN, AIA, policy, CRL or other extension. A nonempty issuer
// SKI is required so the leaf carries the exact authority-key identifier.
func fixedExtensions(cert *x509.Certificate, issuer *x509.Certificate) bool {
	if len(issuer.SubjectKeyId) == 0 || len(cert.Extensions) != 4 {
		return false
	}
	keyUsage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 1})
	if err != nil {
		return false
	}
	extended, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 2}})
	if err != nil {
		return false
	}
	constraints, err := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{false, -1})
	if err != nil {
		return false
	}
	aki, err := asn1.Marshal(struct {
		ID []byte `asn1:"optional,tag:0"`
	}{issuer.SubjectKeyId})
	if err != nil {
		return false
	}
	expected := map[string]struct {
		critical bool
		value    []byte
	}{
		"2.5.29.15": {true, keyUsage},
		"2.5.29.37": {false, extended},
		"2.5.29.19": {true, constraints},
		"2.5.29.35": {false, aki},
	}
	for _, ext := range cert.Extensions {
		want, ok := expected[ext.Id.String()]
		if !ok || ext.Critical != want.critical || !bytes.Equal(ext.Value, want.value) {
			return false
		}
		delete(expected, ext.Id.String())
	}
	return len(expected) == 0
}

func fixedLeaf(cert, issuer *x509.Certificate, expected Intent) bool {
	p := expected.Approval.Candidate.Pending
	return fixedLeafFields(cert, issuer, expected.Approval.Candidate.DeviceID, p.PublicKeyDER, expected.SerialHex, expected.NotBefore, expected.NotAfter)
}

// fixedLeafFields is shared by the server intent and the client public
// projection verifiers, so the fixed X.509 template cannot drift between them.
func fixedLeafFields(cert, issuer *x509.Certificate, deviceID string, publicKeyDER []byte, serialHex string, notBefore, notAfter int64) bool {
	subject, err := asn1.Marshal(pkix.Name{CommonName: deviceID}.ToRDNSequence())
	if err != nil || cert.Version != 3 || cert.IsCA || !cert.BasicConstraintsValid || cert.MaxPathLen != -1 || cert.MaxPathLenZero || cert.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 || len(cert.UnhandledCriticalExtensions) != 0 || cert.SignatureAlgorithm != x509.PureEd25519 ||
		!bytes.Equal(cert.RawSubject, subject) || !bytes.Equal(cert.RawIssuer, issuer.RawSubject) || !bytes.Equal(cert.RawSubjectPublicKeyInfo, publicKeyDER) ||
		len(cert.SubjectKeyId) != 0 || !bytes.Equal(cert.AuthorityKeyId, issuer.SubjectKeyId) ||
		len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses)+len(cert.URIs) != 0 ||
		cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 128 ||
		!cert.NotBefore.Equal(time.Unix(notBefore, 0)) || !cert.NotAfter.Equal(time.Unix(notAfter, 0)) || !fixedExtensions(cert, issuer) {
		return false
	}
	return hex.EncodeToString(cert.SerialNumber.FillBytes(make([]byte, 16))) == serialHex
}

// VerifyIssued checks a bounded external DER against an exact trusted public
// intent and issuer/root. It uses the original pending deadline during initial
// issuance. Issuer and root must be obtained from trusted manager configuration,
// not an unauthenticated response. This function never signs or writes state.
// It does not replace the separate final manager/issuer/identity/revocation
// checks, stored intent comparison, or proof-of-possession activation.
// The fixed leaf carries device, key, serial and time, not the customer or
// intent digest. Another intent with identical leaf fields can match the same
// DER. The authoritative transaction must bind the exact persisted intent and
// certificate hash; this result cannot prove that binding occurred.
// This template can also have the same X.509 shape as a v2 leaf: the caller
// must enforce v3-only original state and no adoption of v2 identities or grants.
func VerifyIssued(der, issuerDER, rootDER []byte, expected Intent, now time.Time) (VerifiedCertificate, error) {
	if len(der) == 0 || len(der) > enrollmentcrypto.MaxCertificateBytes || len(issuerDER) == 0 || len(issuerDER) > enrollmentcrypto.MaxCertificateBytes || len(rootDER) == 0 || len(rootDER) > enrollmentcrypto.MaxCertificateBytes {
		return VerifiedCertificate{}, ErrCertificate
	}
	// Work on a detached copy; returned DER must not alias the caller's buffer.
	raw := bytes.Clone(der)
	issuerRaw, rootRaw := bytes.Clone(issuerDER), bytes.Clone(rootDER)
	expected.Approval.Candidate.Pending.PublicKeyDER = bytes.Clone(expected.Approval.Candidate.Pending.PublicKeyDER)
	if ValidateIssuer(expected, issuerRaw, rootRaw, now) != nil {
		return VerifiedCertificate{}, ErrCertificate
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return VerifiedCertificate{}, ErrCertificate
	}
	issuer, err := x509.ParseCertificate(issuerRaw)
	if err != nil {
		return VerifiedCertificate{}, ErrCertificate
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || cert.NotBefore.Before(issuer.NotBefore) || cert.NotAfter.After(issuer.NotAfter) || !fixedLeaf(cert, issuer, expected) || cert.CheckSignatureFrom(issuer) != nil {
		return VerifiedCertificate{}, ErrCertificate
	}
	digest, err := Digest(expected)
	if err != nil {
		return VerifiedCertificate{}, ErrCertificate
	}
	h := sha256.Sum256(raw)
	return VerifiedCertificate{valid: true, intentDigest: digest, certHash: hex.EncodeToString(h[:]), der: raw}, nil
}
