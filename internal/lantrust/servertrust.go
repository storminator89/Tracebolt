package lantrust

import (
	"crypto/tls"
	"crypto/x509"
	"time"
)

// ValidateServerTrust checks a preprovided server key pair and explicit public
// trust against the same role/key/time policy used by ClientTLSConfig, plus
// normal chain and SAN verification for each configured listener identity.
// It performs no network, system-root lookup or trust installation.
func ValidateServerTrust(server tls.Certificate, rootsPEM []byte, names []string, now time.Time) error {
	if len(names) == 0 || len(names) > 2 || validateKeyPair(server, x509.ExtKeyUsageServerAuth, now) != nil {
		return ErrConfiguration
	}
	roots, e := certificatePool(rootsPEM, now)
	if e != nil {
		return ErrConfiguration
	}
	leaf, e := x509.ParseCertificate(server.Certificate[0])
	if e != nil {
		return ErrConfiguration
	}
	intermediates := x509.NewCertPool()
	for _, raw := range server.Certificate[1:] {
		cert, e := x509.ParseCertificate(raw)
		if e != nil {
			return ErrConfiguration
		}
		intermediates.AddCert(cert)
	}
	for _, name := range names {
		if !validServerName(name) {
			return ErrConfiguration
		}
		chains, e := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		if e != nil {
			return ErrConfiguration
		}
		accepted := false
		for _, chain := range chains {
			valid := len(chain) > 0 && len(chain) <= maxChainCertificates
			for _, cert := range chain {
				valid = valid && validCertificate(cert, now)
			}
			accepted = accepted || valid
		}
		if !accepted {
			return ErrConfiguration
		}
	}
	return nil
}
