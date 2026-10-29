package enrollmentclient

import (
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/lanclient"
)

// ValidateCustomerProfileAt checks the public profile, issuer chain and TLS
// trust at a supplied instant without producing a client or contacting any
// server. It does not authenticate the supplied bytes, authorize installation,
// establish present trust or substitute for ParseCustomerProfile on active use.
func ValidateCustomerProfileAt(raw []byte, at time.Time) (CustomerProfile, error) {
	var p CustomerProfile
	if at.IsZero() || strictJSON(raw, &p) != nil || p.SchemaVersion != CustomerProfileVersion ||
		!enrollmentcrypto.ValidID(p.ManagerInstanceID, "manager_") ||
		!enrollmentcrypto.ValidID(p.CustomerID, "customer_") ||
		!enrollmentcrypto.ValidID(p.InstallerProfileID, "profile_") ||
		p.Profile != "tls" || p.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return CustomerProfile{}, ErrBootstrap
	}
	// The live bootstrap path applies these additional PEM/DER size, duplicate
	// and structure bounds when it prepares the public trust display.
	if _, err := publicCertificates(p.ServerCAPEM); err != nil {
		return CustomerProfile{}, ErrBootstrap
	}
	for _, origin := range []string{p.EnrollmentOrigin, p.AgentOrigin} {
		if lanclient.ValidateBootstrapTrustAt(origin, []byte(p.ServerCAPEM), at) != nil {
			return CustomerProfile{}, ErrBootstrap
		}
	}
	issuers, err := publicCertificates(p.IssuerPEM)
	if err != nil || len(issuers) != 1 {
		return CustomerProfile{}, ErrBootstrap
	}
	roots, err := publicCertificates(p.IssuerRootPEM)
	if err != nil || len(roots) != 1 || enrollmentissuer.ValidatePublicAuthority(issuers[0].Raw, roots[0].Raw, fingerprint(issuers[0].Raw), at) != nil {
		return CustomerProfile{}, ErrBootstrap
	}
	return p, nil
}
