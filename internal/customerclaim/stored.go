package customerclaim

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

// ValidateStoredMetadata verifies the canonical, immutable public claim fields
// and key loaded from protected storage. It does not establish who wrote the
// record, reverify a discarded CSR/signature, or provide authorization.
func ValidateStoredMetadata(m Metadata, publicKeyDER []byte) bool {
	if !enrollmentcrypto.ValidID(m.ManagerID, "manager_") || !enrollmentcrypto.ValidID(m.CustomerID, "customer_") || !enrollmentcrypto.ValidID(m.InstallerProfileID, "profile_") || !enrollmentcrypto.ValidID(m.ClaimID, "claim_") || !enrollmentcrypto.ValidID(m.RequestID, "request_") || !canonicalTLSOrigin(m.Origin) || !canonicalTLSOrigin(m.AgentOrigin) || !enrollmentcrypto.ValidHash(m.IssuerFingerprint) || !enrollmentcrypto.ValidHash(m.KeyFingerprint) || !enrollmentcrypto.ValidHash(m.CSRHash) || !enrollmentcrypto.ValidHash(m.ClaimHash) {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(publicKeyDER)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || !keyvalidation.Ed25519(key) {
		return false
	}
	canonical, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(canonical, publicKeyDER) || digest(publicKeyDER) != m.KeyFingerprint {
		return false
	}
	claimHash, comparison := metadataDigests(m)
	return claimHash == m.ClaimHash && comparison == m.ComparisonCode
}

func metadataDigests(m Metadata) (string, string) {
	base := []string{m.ManagerID, m.CustomerID, m.InstallerProfileID, "tls", m.Origin, m.AgentOrigin, enrollmentcrypto.CollectionProfileWindowsInventory, m.IssuerFingerprint, m.ClaimID, m.RequestID, m.KeyFingerprint, m.CSRHash}
	return digest(transcript("Tracebolt customer Windows semantic claim v1", base...)), digest(transcript("Tracebolt customer Windows comparison v1", m.ManagerID, m.CustomerID, m.InstallerProfileID, m.Origin, m.AgentOrigin, m.IssuerFingerprint, m.ClaimID, m.KeyFingerprint))[:32]
}
