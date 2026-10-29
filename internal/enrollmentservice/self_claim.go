package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
)

// SelfClaimAvailable preserves the configured platform, profile and renewal fence.
func (s *Service) SelfClaimAvailable() bool {
	return s != nil && s.serviceState != nil && enrollmentstore.SelfRegistrationPlatform(s.store.Config()) != ""
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

// SelfClaimPlatform returns the configured self-registration identity domain.
func (s *Service) SelfClaimPlatform() string {
	if s == nil || s.serviceState == nil {
		return ""
	}
	return enrollmentstore.SelfRegistrationPlatform(s.store.Config())
}
