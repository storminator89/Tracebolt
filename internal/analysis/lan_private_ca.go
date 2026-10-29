package analysis

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"time"
)

// privateLANRoots admits precisely one current self-signed CA with explicit
// certificate-signing authority. Its pool is exclusive: there is no system
// root fallback. Actual peer identity is checked by the standard TLS verifier.
func privateLANRoots(text, expected string, now time.Time) (*x509.CertPool, error) {
	data := bytes.TrimSpace([]byte(text))
	if len(text) == 0 || len(text) > 4096 || len(expected) != 64 || !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, ErrInvalidConfig
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalidConfig
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || len(cert.UnhandledCriticalExtensions) != 0 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || !bytes.Equal(cert.RawSubject, cert.RawIssuer) || cert.CheckSignatureFrom(cert) != nil {
		return nil, ErrInvalidConfig
	}
	sum := sha256.Sum256(cert.Raw)
	if expected != hex.EncodeToString(sum[:]) {
		return nil, ErrInvalidConfig
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}
