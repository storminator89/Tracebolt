package fixture

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lantrust"
)

// fixtureAuthorizer is public-certificate authorization for the single current
// activated identity. It neither grants authority nor authenticates possession.
// signedhttp.Verify independently proves possession and calls it twice.
type fixtureAuthorizer struct{ state *state }

func (a fixtureAuthorizer) AuthorizePublicCertificate(public []byte) (lantrust.Agent, error) {
	if a.state == nil {
		return lantrust.Agent{}, lantrust.ErrUnauthorized
	}
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return lantrust.Agent{}, lantrust.ErrUnauthorized
	}
	s := a.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authorizeCertificate(block.Bytes, s.now().UTC())
}

// Caller holds the receipt/authority lock, including the final post-Verify check.
func (s *state) authorizeCertificate(der []byte, now time.Time) (lantrust.Agent, error) {
	v, err := s.snapshot()
	if err != nil || !s.selection.HTTPTest() || !s.activeIdentity(v, now) || !bytes.Equal(der, s.issued.DER()) || digest(der) != v.Issuance.CertificateHash {
		return lantrust.Agent{}, lantrust.ErrUnauthorized
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil || s.issuerCert == nil || s.clientRoots == nil {
		return lantrust.Agent{}, lantrust.ErrUnauthorized
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: s.clientRoots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return lantrust.Agent{}, lantrust.ErrUnauthorized
	}
	for _, chain := range chains {
		if len(chain) == 2 && bytes.Equal(chain[1].Raw, s.issuerCert.Raw) {
			return lantrust.Agent{ID: v.Approval.DeviceID, FingerprintSHA256: lantrust.Fingerprint(leaf), ApprovedAt: time.Unix(v.Approval.At, 0).UTC(), NotBefore: leaf.NotBefore, ExpiresAt: leaf.NotAfter}, nil
		}
	}
	return lantrust.Agent{}, lantrust.ErrUnauthorized
}

func (s *state) activeIdentity(v enrollmentstate.Snapshot, now time.Time) bool {
	return !s.closed && !s.unavailable && s.ctx.Err() == nil && s.selection.Validate() == nil && v.State == enrollmentstate.Activated && v.Platform == "windows" && v.Binding.CollectionProfile == s.selection.CollectionProfile && v.Binding.Profile == s.selection.Transport && v.Binding.InstanceID == s.bootstrap.ManagerInstanceID && v.Binding.Origin == s.bootstrap.EnrollmentOrigin && s.issued.Valid() && s.issued.Intent().IntentID == v.Intent.IntentID && s.issued.Intent().DeviceID == v.Approval.DeviceID && s.issued.Intent().CollectionProfile == s.selection.CollectionProfile && s.issued.Intent().Profile == s.selection.Transport && s.issued.CertificateHash() == v.Issuance.CertificateHash && now.Unix() >= v.UpdatedAt && now.Unix() >= v.Intent.NotBefore && now.Unix() < v.Intent.NotAfter && (s.lastReceipt.ReceivedAt.IsZero() || !now.Before(s.lastReceipt.ReceivedAt))
}
