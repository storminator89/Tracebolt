// Package customeradmission composes source-only pending-claim primitives.
// It has no HTTP listener, installer, approval, certificate or host authority.
// The owner must provide protected storage and a real lease implementation;
// this package must not be exposed until those integration gates are complete.
package customeradmission

import (
	"context"
	"errors"
	"sync"
	"time"

	"localrmm/internal/customerbudget"
	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
)

var ErrInvalid = errors.New("customer admission input invalid")
var ErrBusy = errors.New("customer admission proof capacity exhausted")
var ErrClock = errors.New("customer admission clock moved backwards")

type Coordinator struct {
	pool    *customerchallenge.Pool
	store   *customerpending.Store
	clock   func() time.Time
	acquire customerpending.AcquireAuthority
	budget  *customerbudget.Budget
}

// New constructs an isolated budget for source fixtures and compatibility. It
// must not be used to create separate production claim/status budgets.
// NewWithBudget is required when composing one admission domain.
// acquire must implement a real, live lease over
// exact customer/profile/issuer authority and reject aliased databases; its lock
// order is pending, then profile, then operator. A future issuance path must
// acquire enrollment before pending. A permissive test lease is not production
// authority. The owning service must use one coordinator per admission domain.
func New(pool *customerchallenge.Pool, store *customerpending.Store, clock func() time.Time, acquire customerpending.AcquireAuthority) (*Coordinator, error) {
	return NewWithBudget(pool, store, clock, acquire, customerbudget.New())
}

// NewWithBudget requires the same explicitly owned budget as status proof work.
func NewWithBudget(pool *customerchallenge.Pool, store *customerpending.Store, clock func() time.Time, acquire customerpending.AcquireAuthority, budget *customerbudget.Budget) (*Coordinator, error) {
	if pool == nil || store == nil || clock == nil || acquire == nil || !budget.Valid() {
		return nil, ErrInvalid
	}
	return &Coordinator{pool: pool, store: store, clock: clock, acquire: acquire, budget: budget}, nil
}

// Submit consumes the exact manager-owned challenge before verifying the raw
// request, then persists a pending-only record while the store holds its write
// lock and authority lease. At most two proofs may run concurrently; a busy
// call does not consume a challenge. Invalid proofs consume their challenge.
// An uncertain result must be reconciled by a privileged read, not blindly
// replayed. Transport limits, request admission and response authorization are
// intentionally outside this package.
func (c *Coordinator) Submit(ctx context.Context, nonce string, raw []byte) (customerpending.Record, error) {
	if c == nil || c.pool == nil || c.store == nil || c.clock == nil || c.acquire == nil || !c.budget.Valid() || ctx == nil || len(raw) == 0 || len(raw) > customerclaim.MaxBytes {
		return customerpending.Record{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return customerpending.Record{}, err
	}
	slot, err := c.budget.Acquire(ctx)
	if errors.Is(err, customerbudget.ErrBusy) {
		return customerpending.Record{}, ErrBusy
	}
	if err != nil {
		return customerpending.Record{}, err
	}
	defer slot.Release()
	started := c.clock().UTC()
	challenge, err := c.pool.Take(nonce)
	if err != nil {
		return customerpending.Record{}, err
	}
	verifiedAt := c.clock().UTC()
	if verifiedAt.Before(started) {
		return customerpending.Record{}, ErrClock
	}
	proof, err := customerclaim.Verify(raw, challenge, verifiedAt)
	if err != nil {
		return customerpending.Record{}, err
	}
	var mu sync.Mutex
	last := verifiedAt
	// A zero time makes Store fail closed on clock regression. Each operation has
	// its own monotonic guard, while the pool separately checks its own clock.
	checkedClock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now := c.clock().UTC()
		if now.Before(last) {
			return time.Time{}
		}
		last = now
		return now
	}
	return c.store.Accept(ctx, proof, checkedClock, c.acquire)
}
