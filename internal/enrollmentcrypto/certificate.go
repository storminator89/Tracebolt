package enrollmentcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"localrmm/internal/keyvalidation"
	"strconv"
	"time"
)

const MaxCertificateLifetimeSeconds = int64(30 * 24 * 60 * 60)

func ComparisonCode(instanceID, invitationID, claimID, keyFingerprint string) (string, error) {
	if !ValidID(instanceID, "manager_") || !ValidID(invitationID, "invite_") || !ValidID(claimID, "claim_") || !ValidHash(keyFingerprint) {
		return "", ErrContract
	}
	return hash(transcript("Tracebolt enrollment comparison v2", instanceID, invitationID, claimID, keyFingerprint))[:32], nil
}
func ValidateIntent(i Intent) error {
	for _, pair := range [][2]string{{i.ManagerInstanceID, "manager_"}, {i.InvitationID, "invite_"}, {i.ClaimID, "claim_"}, {i.RequestID, "request_"}, {i.DeviceID, "agent_"}, {i.IntentID, "intent_"}} {
		if !ValidID(pair[0], pair[1]) {
			return ErrContract
		}
	}
	if !canonicalOrigin(i.Origin, i.Profile) || i.CollectionProfile != CollectionProfile || i.TemplateVersion != TemplateVersion || i.KeyGeneration != 1 || !validHex(i.SerialHex, 32) || !ValidHash(i.KeyFingerprint) || !ValidHash(i.CSRHash) || !ValidHash(i.ClaimHash) || !ValidHash(i.IssuerFingerprint) {
		return ErrContract
	}
	if i.NotBefore <= 0 || i.NotAfter <= i.NotBefore || i.NotAfter > 253402300799 || i.NotAfter-i.NotBefore > MaxCertificateLifetimeSeconds {
		return ErrContract
	}
	key, e := decodeBase64(i.PublicKeyDERBase64, 128)
	if e != nil || hash(key) != i.KeyFingerprint {
		return ErrContract
	}
	pub, e := x509.ParsePKIXPublicKey(key)
	if e != nil {
		return ErrContract
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok || !keyvalidation.Ed25519(ed) {
		return ErrContract
	}
	canonical, e := x509.MarshalPKIXPublicKey(ed)
	if e != nil || !bytes.Equal(canonical, key) {
		return ErrContract
	}
	return nil
}
func fixedLeaf(cert *x509.Certificate, i Intent) bool {
	if cert.IsCA || !cert.BasicConstraintsValid || cert.MaxPathLen != -1 || cert.MaxPathLenZero || cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 || len(cert.UnhandledCriticalExtensions) != 0 || cert.SignatureAlgorithm != x509.PureEd25519 {
		return false
	}
	if cert.Subject.CommonName != i.DeviceID || len(cert.Subject.Names) != 1 || !cert.Subject.Names[0].Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) || len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses)+len(cert.URIs) != 0 {
		return false
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 128 {
		return false
	}
	serial := cert.SerialNumber.FillBytes(make([]byte, 16))
	if hex.EncodeToString(serial) != i.SerialHex {
		return false
	}
	if cert.NotBefore.Unix() != i.NotBefore || cert.NotAfter.Unix() != i.NotAfter || hash(cert.RawSubjectPublicKeyInfo) != i.KeyFingerprint {
		return false
	}
	allowed := map[string]bool{"2.5.29.14": true, "2.5.29.15": true, "2.5.29.19": true, "2.5.29.35": true, "2.5.29.37": true}
	seen := map[string]bool{}
	for _, e := range cert.Extensions {
		oid := e.Id.String()
		if !allowed[oid] || seen[oid] {
			return false
		}
		seen[oid] = true
	}
	return true
}

// VerifyIssued validates an external signing result against a previously recorded
// fixed intent and explicit trusted issuing certificate. It does not sign or
// generate a credential. Issuer chain/custody must be validated during setup.
func VerifyIssued(der, issuerDER []byte, expected Intent, now time.Time) (VerifiedCertificate, error) {
	var zero VerifiedCertificate
	if ValidateIntent(expected) != nil || len(der) == 0 || len(der) > MaxCertificateBytes || len(issuerDER) == 0 || len(issuerDER) > MaxCertificateBytes || hash(issuerDER) != expected.IssuerFingerprint {
		return zero, ErrCertificate
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		return zero, ErrCertificate
	}
	issuer, e := x509.ParseCertificate(issuerDER)
	if e != nil {
		return zero, ErrCertificate
	}
	if issuerKey, ok := issuer.PublicKey.(ed25519.PublicKey); !ok || !keyvalidation.Ed25519(issuerKey) || !issuer.IsCA || !issuer.BasicConstraintsValid || issuer.MaxPathLen != 0 || !issuer.MaxPathLenZero || issuer.KeyUsage&x509.KeyUsageCertSign == 0 || len(issuer.ExtKeyUsage) != 1 || issuer.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(issuer.UnknownExtKeyUsage) != 0 || len(issuer.UnhandledCriticalExtensions) != 0 {
		return zero, ErrCertificate
	}
	if now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || cert.NotBefore.Before(issuer.NotBefore) || cert.NotAfter.After(issuer.NotAfter) || !bytes.Equal(cert.RawIssuer, issuer.RawSubject) || !bytes.Equal(cert.AuthorityKeyId, issuer.SubjectKeyId) || !fixedLeaf(cert, expected) || cert.CheckSignatureFrom(issuer) != nil {
		return zero, ErrCertificate
	}
	if expected.Profile == "http-test" && base64.RawStdEncoding.EncodedLen(len(der)) > 4096 {
		return zero, ErrCertificate
	}
	return VerifiedCertificate{seal: true, intent: expected, certificateHash: hash(der), der: bytes.Clone(der)}, nil
}

// IntentDigest binds every immutable issuance field to later possession proofs.
func IntentDigest(i Intent) (string, error) {
	if ValidateIntent(i) != nil {
		return "", ErrContract
	}
	return hash(transcript("Tracebolt enrollment issuance intent v2", i.ManagerInstanceID, i.Profile, i.Origin, i.CollectionProfile, i.InvitationID, i.ClaimID, i.RequestID, i.DeviceID, i.IntentID, i.KeyFingerprint, i.PublicKeyDERBase64, i.CSRHash, i.ClaimHash, i.IssuerFingerprint, i.SerialHex, i.TemplateVersion, strconv.FormatUint(i.KeyGeneration, 10), strconv.FormatInt(i.NotBefore, 10), strconv.FormatInt(i.NotAfter, 10))), nil
}
