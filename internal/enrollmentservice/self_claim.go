package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

// SelfClaimAvailable is deliberately restricted to the existing Windows TLS
// domain. It does not change Linux/macOS, HTTP, renewal or invitation behavior.
func (s *Service) SelfClaimAvailable() bool {
	return s != nil && s.serviceState != nil && s.binding.Profile == "tls" && s.binding.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && !s.AutomaticRenewal()
}

func (s *Service) SelfClaim(ctx context.Context, nonce string, raw []byte) (enrollmentstate.Snapshot, error) {
	if !s.SelfClaimAvailable() {
		return enrollmentstate.Snapshot{}, ErrPlatform
	}
	release, err := s.beginProof()
	if err != nil {
		return enrollmentstate.Snapshot{}, err
	}
	defer release()
	c, err := s.takeChallenge(nonce, "claim")
	if err != nil {
		return enrollmentstate.Snapshot{}, err
	}
	now := s.now().UTC()
	proof, err := enrollmentcrypto.VerifyClaim(raw, c, now)
	if err != nil {
		return enrollmentstate.Snapshot{}, err
	}
	return s.store.SelfClaim(ctx, proof, now.Unix())
}
