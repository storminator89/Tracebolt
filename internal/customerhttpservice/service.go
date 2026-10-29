// Package customerhttpservice composes an unregistered source-only HTTP service.
// It does not establish protected storage, aliases, lifecycle or a response edge.
package customerhttpservice

import (
	"context"
	"errors"
	"sync"
	"time"

	"localrmm/internal/customeradmission"
	"localrmm/internal/customerbudget"
	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
	"localrmm/internal/customerprofiles"
	"localrmm/internal/customerproofdomain"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
)

var ErrInvalid = errors.New("customer challenge service unavailable")
var ErrUncertain = errors.New("customer challenge handoff uncertain")

// ChallengeTarget contains only public, manager-selected configuration and
// requested public IDs. It is not a pending claim, identity or approval.
type ChallengeTarget struct {
	Binding                        customerchallenge.Binding
	CustomerID, ProfileID, ClaimID string
}

// ChallengeGuard must prove current manager/issuer authority independently of
// input IDs. It must not reenter profile, operator or pending stores.
type ChallengeGuard func(context.Context, ChallengeTarget) error

type Service struct {
	pool          *customerchallenge.Pool
	budget        *customerbudget.Budget
	domain        *customerproofdomain.Domain
	profiles      *customerprofiles.Store
	customers     *store.Store
	binding       customerchallenge.Binding
	managerDigest string
	clock         func() time.Time
	storageGuard  func(context.Context) error
	managerGuard  ChallengeGuard
}

// New retains the manager-owned pool shared by claim and all v3 proof paths.
// The supplied pool and budget must be the manager's only instances for those
// paths; their manager owner must retain the exact same objects for their lifetime.
// Stores/guards are borrowed; their provenance and durable used markers are
// not established here. Do not register this candidate as a live route.
func New(binding customerchallenge.Binding, pool *customerchallenge.Pool, managerDigest string, profiles *customerprofiles.Store, customers *store.Store, pending *customerpending.Store, budget *customerbudget.Budget, clock func() time.Time, storageGuard func(context.Context) error, managerGuard ChallengeGuard, claimGuard func(context.Context, customerclaim.Metadata) error) (*Service, error) {
	if profiles == nil || customers == nil || pending == nil || !pool.MatchesBinding(binding) || !budget.Valid() || !enrollmentcrypto.ValidHash(managerDigest) || clock == nil || storageGuard == nil || managerGuard == nil || claimGuard == nil {
		return nil, ErrInvalid
	}
	authority, err := customeradmission.NewProfileCustomerAuthority(profiles, customers, binding.ManagerID, managerDigest, clock, storageGuard, claimGuard)
	if err != nil {
		return nil, err
	}
	domain, err := customerproofdomain.NewWithBudget(pool, pending, clock, authority.Acquire, budget)
	if err != nil {
		return nil, err
	}
	return &Service{pool: pool, budget: budget, domain: domain, profiles: profiles, customers: customers, binding: binding, managerDigest: managerDigest, clock: clock, storageGuard: storageGuard, managerGuard: managerGuard}, nil
}

// Admit is pending-only. Its return is not a live lifecycle or response-edge
// lease, and cannot authorize a credential, activation or collection. Its
// bounded context cannot forcibly stop an uncooperative driver or guard.
func (s *Service) Admit(ctx context.Context, nonce string, raw []byte) (customerpending.Record, error) {
	if s == nil || s.domain == nil || ctx == nil {
		return customerpending.Record{}, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	return s.domain.Admit(bounded, nonce, raw)
}

// WithClaimChallenge holds a typed active-profile/customer lease during the
// synchronous callback. No pending lock is acquired in this path and emit
// must never reenter a locked store. No callback establishes receipt. Missing,
// failed or panicking response guard and callback failure are uncertain after
// handoff. A real response edge, bounded read/write time, trusted storage and
// multi-process limits remain external requirements.
func (s *Service) WithClaimChallenge(ctx context.Context, peer, customerID, profileID, claimID string, emit func(customerclaim.Context, func() error) error) (result error) {
	handed := false
	defer func() {
		if recover() != nil {
			if handed {
				result = ErrUncertain
			} else {
				result = ErrInvalid
			}
		}
	}()
	if s == nil || s.pool == nil || !s.budget.Valid() || s.profiles == nil || s.customers == nil || s.clock == nil || s.storageGuard == nil || s.managerGuard == nil || ctx == nil || emit == nil || !enrollmentcrypto.ValidID(customerID, "customer_") || !enrollmentcrypto.ValidID(profileID, "profile_") || !enrollmentcrypto.ValidID(claimID, "claim_") {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	started := s.clock().UTC()
	var clockMu sync.Mutex
	last := started
	checkedClock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		now := s.clock().UTC()
		if now.Before(last) || !now.Before(started.Add(25*time.Second)) {
			return time.Time{}
		}
		last = now
		return now
	}
	if started.Unix() <= 0 || ctx.Err() != nil {
		return ErrInvalid
	}
	slot, err := s.budget.Acquire(ctx)
	if err != nil {
		return err
	}
	defer slot.Release()
	target := ChallengeTarget{s.binding, customerID, profileID, claimID}
	baseGuard := func() error {
		if ctx.Err() != nil || s.storageGuard(ctx) != nil || s.managerGuard(ctx, target) != nil || ctx.Err() != nil {
			return ErrInvalid
		}
		return nil
	}
	if err = baseGuard(); err != nil {
		return err
	}
	acquire := func(ctx context.Context, customer, profile string) (customerprofiles.AuthorityLease, error) {
		if customer != customerID || profile != profileID || baseGuard() != nil {
			return nil, ErrInvalid
		}
		rows, err := s.customers.Customers(ctx, s.managerDigest)
		if err != nil {
			return nil, err
		}
		var revision uint64
		for _, row := range rows {
			if row.ID == customerID {
				revision = row.Revision
				break
			}
		}
		if revision == 0 {
			return nil, ErrInvalid
		}
		return s.customers.AcquireCustomerAuthority(ctx, s.managerDigest, customerID, revision, baseGuard)
	}
	lease, err := s.profiles.AcquireActive(ctx, customerID, profileID, checkedClock, acquire)
	if err != nil {
		return err
	}
	defer lease.Release()
	record, trust, err := lease.Snapshot()
	if err != nil || record.ManagerID != s.binding.ManagerID || record.CustomerID != customerID || record.ProfileID != profileID || trust.ManagerInstanceID != s.binding.ManagerID || trust.EnrollmentOrigin != s.binding.Origin || trust.AgentOrigin != s.binding.AgentOrigin || trust.IssuerFingerprint != s.binding.IssuerFingerprint {
		return ErrInvalid
	}
	c, err := s.pool.Issue(peer, customerID, profileID, claimID)
	if err != nil {
		return err
	}
	guard := func() error {
		if ctx.Err() != nil || lease.Check() != nil || baseGuard() != nil {
			return ErrInvalid
		}
		now := checkedClock()
		if now.IsZero() || !customerclaim.ValidChallengeContext(c, now) {
			return ErrInvalid
		}
		return nil
	}
	if err = guard(); err != nil {
		return err
	}
	var mu sync.Mutex
	active, called, failed := true, false, false
	defer func() { mu.Lock(); active = false; mu.Unlock() }()
	responseGuard := func() (out error) {
		mu.Lock()
		defer mu.Unlock()
		defer func() {
			if recover() != nil {
				failed = true
				out = ErrInvalid
			}
		}()
		if !active {
			return ErrInvalid
		}
		called = true
		if err := guard(); err != nil {
			failed = true
			return err
		}
		return nil
	}
	handed = true
	if err = emit(c, responseGuard); err != nil {
		return ErrUncertain
	}
	mu.Lock()
	active = false
	accepted := called && !failed
	mu.Unlock()
	if !accepted || guard() != nil {
		return ErrUncertain
	}
	return nil
}
