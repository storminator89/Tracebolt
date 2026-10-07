package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentstate"
	"time"
)

// AuthorizePackageDevice supplies current enrollment authority to the separate
// native package controller. It creates no grant, identity, state or collection.
func (s *Store) AuthorizePackageDevice(ctx context.Context, device, incarnation string, now time.Time) error {
	return s.transact(ctx, func(t *transaction) error {
		if !completeProfile(s.config.Binding.CollectionProfile) {
			return enrollmentstate.ErrProof
		}
		snap, e := systemDevice(t, device)
		if e != nil {
			return e
		}
		if incarnation != "sha256:"+snap.Issuance.CertificateHash {
			return enrollmentstate.ErrProof
		}
		_, e = s.systemAuthority(t, snap.InvitationID, snap.Issuance.CertificateHash, now)
		return e
	})
}
