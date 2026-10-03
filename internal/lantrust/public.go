package lantrust

// AuthorizePublicCertificate verifies a bounded public certificate chain and its
// current approval/revocation state. THIS DOES NOT PROVE KEY POSSESSION and is
// not HTTP authentication by itself. Only a separately verified, domain-bound
// public-key signature can use this result on an explicitly insecure HTTP test
// surface. The HTTPS ingress must continue to use Authenticate with verified
// mutual TLS; this method must never serve as a TLS authentication fallback.
func (r *Registry) AuthorizePublicCertificate(publicPEM []byte) (Agent, error) {
	if r == nil {
		return Agent{}, ErrUnauthorized
	}
	certs, err := parsePublicCertificates(publicPEM)
	if err != nil {
		return Agent{}, ErrUnauthorized
	}
	now := r.now()
	if err := verifyAgentChain(certs, r.roots, now); err != nil {
		return Agent{}, ErrUnauthorized
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.unavailable {
		return Agent{}, ErrRegistryUnavailable
	}
	a, exists := r.byID[r.byFingerprint[Fingerprint(certs[0])]]
	if !exists || !a.RevokedAt.IsZero() || now.Before(a.NotBefore) || !now.Before(a.ExpiresAt) {
		return Agent{}, ErrUnauthorized
	}
	return a, nil
}
