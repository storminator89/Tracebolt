package enrollmentissuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

func parsePublicCertificate(der []byte) (*x509.Certificate, error) {
	if len(der) == 0 || len(der) > enrollmentcrypto.MaxCertificateBytes {
		return nil, ErrConfiguration
	}
	// x509.Certificate aliases its DER input. Parsing a private copy prevents
	// caller mutation of both the parsed chain and later fixed-template input.
	cert, err := x509.ParseCertificate(bytes.Clone(der))
	if err != nil {
		return nil, ErrConfiguration
	}
	return cert, nil
}

// strongPublicKey and signature policy match the existing LAN trust policy.
// The intermediate is narrower: only the shared canonical Ed25519 policy.
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
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512, x509.PureEd25519:
		return true
	}
	return false
}

func verifyAuthority(issuer, root *x509.Certificate, now time.Time) error {
	if !validCA(issuer, now) || !validCA(root, now) {
		return ErrConfiguration
	}
	public, ok := issuer.PublicKey.(ed25519.PublicKey)
	if !ok || !keyvalidation.Ed25519(public) || issuer.MaxPathLen != 0 || !issuer.MaxPathLenZero || issuer.KeyUsage & ^(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 || len(issuer.ExtKeyUsage) != 1 || issuer.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(issuer.UnknownExtKeyUsage) != 0 {
		return ErrConfiguration
	}
	// The root stays offline and distinct. A pathLen0 root cannot authorize an
	// intermediate, even when verification treats that CA as its target leaf.
	if bytes.Equal(issuer.Raw, root.Raw) || bytes.Equal(issuer.RawSubjectPublicKeyInfo, root.RawSubjectPublicKeyInfo) || root.MaxPathLenZero || (root.MaxPathLen >= 0 && root.MaxPathLen < 1) || len(root.UnknownExtKeyUsage) != 0 || !bytes.Equal(root.RawSubject, root.RawIssuer) || root.CheckSignatureFrom(root) != nil {
		return ErrConfiguration
	}
	if !bytes.Equal(issuer.RawIssuer, root.RawSubject) || !bytes.Equal(issuer.AuthorityKeyId, root.SubjectKeyId) || issuer.NotBefore.Before(root.NotBefore) || issuer.NotAfter.After(root.NotAfter) || issuer.CheckSignatureFrom(root) != nil {
		return ErrConfiguration
	}
	// Never consult ambient/system roots or fetch missing issuers. The accepted
	// path must be the exact provided intermediate followed by the exact root.
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

// ValidatePublicAuthority checks only the public bootstrap issuer/root policy.
// It grants no signing, enrollment or device authority and needs no private key.
// expectedFingerprint comes from locally selected bootstrap/configuration, never
// an unauthenticated enrollment response.
func ValidatePublicAuthority(issuerDER, rootDER []byte, expectedFingerprint string, now time.Time) error {
	if !validTime(now) {
		return ErrConfiguration
	}
	issuer, e := parsePublicCertificate(issuerDER)
	if e != nil || fingerprint(issuerDER) != expectedFingerprint {
		return ErrConfiguration
	}
	root, e := parsePublicCertificate(rootDER)
	if e != nil {
		return ErrConfiguration
	}
	return verifyAuthority(issuer, root, now)
}
