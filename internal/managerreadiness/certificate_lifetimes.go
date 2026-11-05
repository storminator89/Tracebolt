package managerreadiness

import (
	"crypto/x509"
	"time"
)

// CertificateLifetime describes only the dates of already-loaded public
// material. It is not a trust, key-possession, reachability or renewal verdict.
// For a presented server chain the window is the intersection of all its
// certificates, never just the leaf's expiry.
type CertificateLifetime struct {
	Role       string     `json:"role"`
	State      string     `json:"state"`
	ValidFrom  *time.Time `json:"validFrom,omitempty"`
	ValidUntil *time.Time `json:"validUntil,omitempty"`
}

// CertificateLifetimes returns a fixed, redacted roster without filesystem,
// network, credential or signing access. It never changes readiness or grants
// renewal authority. Disabled roles stay distinct from missing/invalid material.
func CertificateLifetimes(now time.Time, serverEnabled bool, serverChain [][]byte, issuerEnabled bool, issuerDER, rootDER []byte) []CertificateLifetime {
	return []CertificateLifetime{
		certificateLifetime("server_chain", now, serverEnabled, serverChain),
		certificateLifetime("enrollment_issuer", now, issuerEnabled, [][]byte{issuerDER}),
		certificateLifetime("enrollment_root", now, issuerEnabled, [][]byte{rootDER}),
	}
}

func certificateLifetime(role string, now time.Time, enabled bool, certificates [][]byte) CertificateLifetime {
	v := CertificateLifetime{Role: role, State: "not_configured"}
	if !enabled {
		return v
	}
	v.State = "unavailable"
	// The production server loader accepts at most 64 KiB of certificate PEM.
	// Keep this pure diagnostic bounded even for a malformed in-memory source.
	if now.IsZero() || now.Year() < 1970 || now.Year() > 9999 || len(certificates) == 0 || len(certificates) > 64 {
		return v
	}
	var from, until time.Time
	total := 0
	for _, der := range certificates {
		if len(der) == 0 || len(der) > 65536-total {
			return v
		}
		total += len(der)
		cert, err := x509.ParseCertificate(der)
		if err != nil || cert.NotBefore.IsZero() || cert.NotAfter.IsZero() || !cert.NotBefore.Before(cert.NotAfter) || cert.NotBefore.Year() < 1 || cert.NotAfter.Year() > 9999 {
			return v
		}
		if from.IsZero() || cert.NotBefore.After(from) {
			from = cert.NotBefore.UTC()
		}
		if until.IsZero() || cert.NotAfter.Before(until) {
			until = cert.NotAfter.UTC()
		}
	}
	if !from.Before(until) {
		return v
	}
	v.ValidFrom, v.ValidUntil = &from, &until
	switch {
	case now.Before(from):
		v.State = "not_yet_valid"
	case !now.Before(until):
		v.State = "expired"
	case until.Sub(now) <= 7*24*time.Hour:
		v.State = "within_7_days"
	case until.Sub(now) <= 30*24*time.Hour:
		v.State = "within_30_days"
	default:
		v.State = "valid"
	}
	return v
}
