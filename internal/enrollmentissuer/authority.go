package enrollmentissuer

import (
	"crypto/x509"
	"time"

	"localrmm/internal/enrollmentauthority"
)

// Keep the original public error identity and non-exported entry points while
// sharing the exact public CA policy with the customer-specific verifier.
func parsePublicCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := enrollmentauthority.ParsePublicCertificate(der)
	if err != nil {
		return nil, ErrConfiguration
	}
	return cert, nil
}
func verifyAuthority(issuer, root *x509.Certificate, now time.Time) error {
	if enrollmentauthority.Verify(issuer, root, now) != nil {
		return ErrConfiguration
	}
	return nil
}

// ValidatePublicAuthority checks only the public bootstrap issuer/root policy.
// It grants no signing, enrollment or device authority and needs no private key.
// expectedFingerprint comes from locally selected bootstrap/configuration, never
// an unauthenticated enrollment response.
func ValidatePublicAuthority(issuerDER, rootDER []byte, expectedFingerprint string, now time.Time) error {
	if enrollmentauthority.ValidatePublicAuthority(issuerDER, rootDER, expectedFingerprint, now) != nil {
		return ErrConfiguration
	}
	return nil
}
