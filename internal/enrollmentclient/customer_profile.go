package enrollmentclient

import (
	"localrmm/internal/enrollmentcrypto"
	"time"
)

// CustomerProfileVersion describes public installer configuration only. It is
// not a bearer credential, invitation, authorization or evidence of trust.
const CustomerProfileVersion = "tracebolt.customer-windows-profile.v1"

// CustomerProfile must be obtained through an independently authenticated
// channel. An attacker who can replace these public bytes can replace the trust
// roots as well. The profile does not grant any local collection permission.
type CustomerProfile struct {
	SchemaVersion      string `json:"schemaVersion"`
	ManagerInstanceID  string `json:"managerInstanceId"`
	CustomerID         string `json:"customerId"`
	InstallerProfileID string `json:"installerProfileId"`
	Profile            string `json:"profile"`
	EnrollmentOrigin   string `json:"enrollmentOrigin"`
	AgentOrigin        string `json:"agentOrigin"`
	CollectionProfile  string `json:"collectionProfile"`
	ServerCAPEM        string `json:"serverCaPem"`
	IssuerRootPEM      string `json:"issuerRootPem"`
	IssuerPEM          string `json:"issuerPem"`
}

// ParseCustomerProfile validates bounded public configuration without creating
// an identity or contacting a manager. The caller must authenticate its origin
// independently and check manager-side profile revocation before admission.
// TLS and authority validation never make untrusted configuration trustworthy.
// A future user-facing review must show the returned profile's customer and
// installer-profile IDs as well as the trust display; neither ID grants access.
func ParseCustomerProfile(raw []byte, now time.Time) (CustomerProfile, TrustDisplay, error) {
	var p CustomerProfile
	if strictJSON(raw, &p) != nil || p.SchemaVersion != CustomerProfileVersion ||
		!enrollmentcrypto.ValidID(p.ManagerInstanceID, "manager_") ||
		!enrollmentcrypto.ValidID(p.CustomerID, "customer_") ||
		!enrollmentcrypto.ValidID(p.InstallerProfileID, "profile_") ||
		p.Profile != "tls" || p.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return CustomerProfile{}, TrustDisplay{}, ErrBootstrap
	}
	b := Bootstrap{ManagerInstanceID: p.ManagerInstanceID, Profile: p.Profile,
		EnrollmentOrigin: p.EnrollmentOrigin, AgentOrigin: p.AgentOrigin,
		CollectionProfile: p.CollectionProfile, ServerCAPEM: p.ServerCAPEM,
		IssuerRootPEM: p.IssuerRootPEM, IssuerPEM: p.IssuerPEM}
	d, err := validateBootstrapTrust(b, now)
	if err != nil {
		return CustomerProfile{}, TrustDisplay{}, ErrBootstrap
	}
	return p, d, nil
}
