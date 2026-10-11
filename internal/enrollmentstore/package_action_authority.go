package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"time"
)

// ErrPackageRenewalUnsupported identifies an intentional fail-closed boundary.
// Native package actions use a separate durable store and cannot yet atomically
// bind their final operation commit to renewal's current credential generation.
var ErrPackageRenewalUnsupported = errors.New("native_package_actions_unsupported_for_renewable_identity")

func packageRenewalSupported(snapshot enrollmentstate.Snapshot) error {
	if snapshot.Claim.RenewalPolicy != "" {
		return ErrPackageRenewalUnsupported
	}
	return nil
}

// InspectPackageInitialization reuses the existing genuinely read-only
// enrollment inspector. It never opens a writable enrollment Store or acquires
// a package-store session. All identities come from the protected ledger.
func InspectPackageInitialization(ctx context.Context, path string, issuerDER []byte, manager, device, incarnation string, now time.Time) error {
	inspection, err := InspectServiceActionSetup(ctx, path, issuerDER, device, now)
	if err != nil {
		return err
	}
	if inspection.Config.Binding.InstanceID != manager || inspection.Identity.Binding.InstanceID != manager || inspection.Identity.Approval.DeviceID != device || incarnation != "sha256:"+inspection.Identity.Issuance.CertificateHash {
		return enrollmentstate.ErrProof
	}
	return packageRenewalSupported(inspection.Identity)
}

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
		// Check the immutable fresh-enrollment policy, including disabled
		// renewal. Turning renewal off cannot promote this unsupported scope.
		if e = packageRenewalSupported(snap); e != nil {
			return e
		}
		if incarnation != "sha256:"+snap.Issuance.CertificateHash {
			return enrollmentstate.ErrProof
		}
		_, e = s.systemAuthority(t, snap.InvitationID, t.currentCertificateHash(snap), now)
		return e
	})
}
