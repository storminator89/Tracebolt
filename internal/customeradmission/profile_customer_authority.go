package customeradmission

import (
	"context"
	"time"

	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
	"localrmm/internal/customerprofiles"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
)

// ProfileCustomerAuthority composes the existing profile and customer leases.
// It is source-only: it does not establish protected storage, database alias
// exclusion, manager/issuer authority, a session, or permission to enroll.
// The caller must provide independently verified manager bindings and both
// live guards. The storage guard must ensure protected state, used markers and
// non-aliased databases; neither guard may reenter any of the locked stores.
// The required lock order is pending, profile, then operator.
type ProfileCustomerAuthority struct {
	profiles      *customerprofiles.Store
	customers     *store.Store
	managerID     string
	managerDigest string
	clock         func() time.Time
	storageGuard  func(context.Context) error
	managerGuard  func(context.Context, customerclaim.Metadata) error
}

func (a *ProfileCustomerAuthority) valid() bool {
	return a != nil && a.profiles != nil && a.customers != nil &&
		enrollmentcrypto.ValidID(a.managerID, "manager_") &&
		enrollmentcrypto.ValidHash(a.managerDigest) && a.clock != nil &&
		a.storageGuard != nil && a.managerGuard != nil
}

func NewProfileCustomerAuthority(profiles *customerprofiles.Store, customers *store.Store, managerID, managerDigest string, clock func() time.Time, storageGuard func(context.Context) error, managerGuard func(context.Context, customerclaim.Metadata) error) (*ProfileCustomerAuthority, error) {
	if profiles == nil || customers == nil || !enrollmentcrypto.ValidID(managerID, "manager_") || !enrollmentcrypto.ValidHash(managerDigest) || clock == nil || storageGuard == nil || managerGuard == nil {
		return nil, ErrInvalid
	}
	return &ProfileCustomerAuthority{profiles, customers, managerID, managerDigest, clock, storageGuard, managerGuard}, nil
}

// Acquire is for pending admission only; it reads the current customer revision
// itself and is not a reviewed operator approval. It must only be called by
// pending.Accept after it has acquired its
// transaction lock. The returned lease must remain held through its commit.
// Independent storage and manager guards are checked repeatedly, including by
// the pending store just before commit. The guards must not take store locks.
func (a *ProfileCustomerAuthority) Acquire(ctx context.Context, m customerclaim.Metadata) (customerpending.AuthorityLease, error) {
	return a.acquire(ctx, m, 0)
}

// AcquireReview holds the exact customer catalog revision displayed to the
// operator, along with the reviewed manager digest and original claim binding.
// A rename after review invalidates this lease; a caller must obtain a fresh
// review and explicit confirmation. This method does not approve a claim or
// issue credentials. The caller must already hold the original pending lock,
// and for any issuance path the enrollment lock before that pending lock.
func (a *ProfileCustomerAuthority) AcquireReview(ctx context.Context, m customerclaim.Metadata, expectedManagerDigest string, expectedCustomerRevision uint64) (customerpending.AuthorityLease, error) {
	if !a.valid() || expectedManagerDigest != a.managerDigest || expectedCustomerRevision == 0 || expectedCustomerRevision > store.MaxFleetGroupRevision {
		return nil, ErrInvalid
	}
	return a.acquire(ctx, m, expectedCustomerRevision)
}

// AcquireOriginal is only for continuation of an already committed v3 intent.
// It preserves the original manager/customer/profile/claim binding while using
// the current customer revision, so a later rename does not undo an approval.
// It is not a new review, approval, signing or delivery authority; the caller
// must first lock and check the exact committed v3 intent.
func (a *ProfileCustomerAuthority) AcquireOriginal(ctx context.Context, m customerclaim.Metadata, expectedManagerDigest string) (customerpending.AuthorityLease, error) {
	if !a.valid() || expectedManagerDigest != a.managerDigest {
		return nil, ErrInvalid
	}
	return a.acquire(ctx, m, 0)
}

func (a *ProfileCustomerAuthority) acquire(ctx context.Context, m customerclaim.Metadata, expectedCustomerRevision uint64) (customerpending.AuthorityLease, error) {
	if !a.valid() || ctx == nil || ctx.Err() != nil || m.ManagerID != a.managerID {
		return nil, ErrInvalid
	}
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.storageGuard(ctx); err != nil {
			return err
		}
		if err := a.managerGuard(ctx, m); err != nil {
			return err
		}
		return ctx.Err()
	}
	if err := guard(); err != nil {
		return nil, err
	}
	profileAcquire := func(ctx context.Context, customerID, profileID string) (customerprofiles.AuthorityLease, error) {
		if customerID != m.CustomerID || profileID != m.InstallerProfileID {
			return nil, ErrInvalid
		}
		if err := guard(); err != nil {
			return nil, err
		}
		revision := expectedCustomerRevision
		if revision == 0 {
			rows, err := a.customers.Customers(ctx, a.managerDigest)
			if err != nil {
				return nil, err
			}
			for _, c := range rows {
				if c.ID == customerID {
					revision = c.Revision
					break
				}
			}
		}
		if revision == 0 {
			return nil, store.ErrCustomerConflict
		}
		return a.customers.AcquireCustomerAuthority(ctx, a.managerDigest, customerID, revision, guard)
	}
	l, err := a.profiles.AcquireActive(ctx, m.CustomerID, m.InstallerProfileID, a.clock, profileAcquire)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			l.Release()
		}
	}()
	r, d, err := l.Snapshot()
	if err != nil {
		return nil, err
	}
	if r.ManagerID != m.ManagerID || r.CustomerID != m.CustomerID || r.ProfileID != m.InstallerProfileID || d.ManagerInstanceID != m.ManagerID || d.EnrollmentOrigin != m.Origin || d.AgentOrigin != m.AgentOrigin || d.IssuerFingerprint != m.IssuerFingerprint {
		return nil, customerprofiles.ErrConflict
	}
	if err = guard(); err != nil {
		return nil, err
	}
	retained = true
	return l, nil
}
