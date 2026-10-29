// Package enrollmentauthority validates the existing public client-auth issuer
// policy. It owns no private key, cannot sign and grants no enrollment authority.
package enrollmentauthority

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

var ErrConfiguration = errors.New("enrollment public authority is invalid")

// ParsePublicCertificate preserves the original bounded, defensive DER copy.
func ParsePublicCertificate(der []byte) (*x509.Certificate, error) {
	if len(der) == 0 || len(der) > enrollmentcrypto.MaxCertificateBytes {
		return nil, ErrConfiguration
	}
	cert, err := x509.ParseCertificate(bytes.Clone(der))
	if err != nil {
		return nil, ErrConfiguration
	}
	return cert, nil
}
func fingerprint(der []byte) string { h := sha256.Sum256(der); return hex.EncodeToString(h[:]) }
func strongPublicKey(public any) bool {
	switch key := public.(type) {
	case ed25519.PublicKey:
		return keyvalidation.Ed25519(key)
	case *rsa.PublicKey:
		return key != nil && key.N != nil && key.N.BitLen() >= 2048 && key.E >= 65537 && key.E%2 == 1
	case *ecdsa.PublicKey:
		return key != nil && key.X != nil && key.Y != nil && (key.Curve == elliptic.P256() || key.Curve == elliptic.P384() || key.Curve == elliptic.P521()) && key.Curve.IsOnCurve(key.X, key.Y)
	}
	return false
}
func validCA(cert *x509.Certificate, now time.Time) bool {
	if cert == nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || !strongPublicKey(cert.PublicKey) || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || len(cert.UnhandledCriticalExtensions) != 0 {
		return false
	}
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA, x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512, x509.PureEd25519:
		return true
	}
	return false
}

// Verify checks the exact provided issuer/root policy; it neither consults
// ambient trust nor authenticates the caller's provenance or signing rights.
func Verify(issuer, root *x509.Certificate, now time.Time) error {
	if !validCA(issuer, now) || !validCA(root, now) {
		return ErrConfiguration
	}
	public, ok := issuer.PublicKey.(ed25519.PublicKey)
	if !ok || !keyvalidation.Ed25519(public) || issuer.MaxPathLen != 0 || !issuer.MaxPathLenZero || issuer.KeyUsage & ^(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 || len(issuer.ExtKeyUsage) != 1 || issuer.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(issuer.UnknownExtKeyUsage) != 0 {
		return ErrConfiguration
	}
	if bytes.Equal(issuer.Raw, root.Raw) || bytes.Equal(issuer.RawSubjectPublicKeyInfo, root.RawSubjectPublicKeyInfo) || root.MaxPathLenZero || (root.MaxPathLen >= 0 && root.MaxPathLen < 1) || len(root.UnknownExtKeyUsage) != 0 || !bytes.Equal(root.RawSubject, root.RawIssuer) || root.CheckSignatureFrom(root) != nil {
		return ErrConfiguration
	}
	if !bytes.Equal(issuer.RawIssuer, root.RawSubject) || !bytes.Equal(issuer.AuthorityKeyId, root.SubjectKeyId) || issuer.NotBefore.Before(root.NotBefore) || issuer.NotAfter.After(root.NotAfter) || issuer.CheckSignatureFrom(root) != nil {
		return ErrConfiguration
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	chains, err := issuer.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return ErrConfiguration
	}
	for _, chain := range chains {
		if len(chain) == 2 && bytes.Equal(chain[0].Raw, issuer.Raw) && bytes.Equal(chain[1].Raw, root.Raw) {
			return nil
		}
	}
	return ErrConfiguration
}

// ValidatePublicAuthority validates bounded public DER and the explicit
// fingerprint; it is not a signing, grant, revocation or enrollment check.
func ValidatePublicAuthority(issuerDER, rootDER []byte, expectedFingerprint string, now time.Time) error {
	if now.Unix() <= 0 || now.Unix() > 253402300799 {
		return ErrConfiguration
	}
	issuer, err := ParsePublicCertificate(issuerDER)
	if err != nil || fingerprint(issuerDER) != expectedFingerprint {
		return ErrConfiguration
	}
	root, err := ParsePublicCertificate(rootDER)
	if err != nil {
		return ErrConfiguration
	}
	return Verify(issuer, root, now)
}
