// Package customerstatus composes source-only pending-record checks. It does not
// establish current enrollment state or expose an HTTP route, grant, credential,
// approval or host action. Do not wire it to a manager without the lifecycle
// and response-edge guards documented below.
package customerstatus

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

var ErrInvalid = errors.New("customer status input invalid")
var ErrBusy = errors.New("customer status proof capacity exhausted")
var ErrClock = errors.New("customer status clock moved backwards")

type Coordinator struct {
	pool    *customerchallenge.Pool
	store   *customerpending.Store
	clock   func() time.Time
	acquire customerpending.AcquireAuthority
	budget  *customerbudget.Budget
}

// New uses a standalone fixture budget for compatibility. Production claim and
// status work must share one explicitly supplied budget via NewWithBudget.
// New borrows a manager-owned challenge pool and a protected pending store.
// acquire must establish current profile/customer/issuer authority under the
// pending→profile→operator lock order and prove database separation. The owner
// must provision protected paths, used markers and live guards independently.
func New(pool *customerchallenge.Pool, store *customerpending.Store, clock func() time.Time, acquire customerpending.AcquireAuthority) (*Coordinator, error) {
	return NewWithBudget(pool, store, clock, acquire, customerbudget.New())
}

// NewWithBudget borrows the single proof budget shared with claim admission.
// It remains process-local and does not bound other manager instances.
func NewWithBudget(pool *customerchallenge.Pool, store *customerpending.Store, clock func() time.Time, acquire customerpending.AcquireAuthority, budget *customerbudget.Budget) (*Coordinator, error) {
	if pool == nil || store == nil || clock == nil || acquire == nil || !budget.Valid() {
		return nil, ErrInvalid
	}
	return &Coordinator{pool: pool, store: store, clock: clock, acquire: acquire, budget: budget}, nil
}

// WithStatus consumes one status-purpose challenge, checks possession using the
// server-stored claim key, and synchronously calls emit with only a pending state
// and its original expiry. The lease and proof budget remain held during emit.
// emit must be a bounded synchronous response commitment, must honor ctx and
// must not reenter the locked stores; no unbounded network work may occur while
// holding this lease. The arbitrary callback itself can delay or ignore these
// obligations; this candidate does not enforce an actual HTTP response edge.
// A future HTTP adapter must hold an enrollment authority proving the claim
// remains pending ahead of this pending lock, recheck live authority and time
// at the actual response commitment, collapse errors appropriately, honor the
// original challenge deadline and limit request body/concurrency. In particular,
// a retained pending record cannot establish that a later approval or terminal
// transition has not occurred. No HTTP integration is authorized by these tests.
// Issuing a status challenge itself must use the protected original claim, not
// request-provided metadata. No status or callback occurs on any failed proof.
func (c *Coordinator) WithStatus(ctx context.Context, nonce string, raw []byte, emit func(customerpending.PendingStatus) error) error {
	if c == nil || c.pool == nil || c.store == nil || c.clock == nil || c.acquire == nil || !c.budget.Valid() || ctx == nil || emit == nil || len(raw) == 0 || len(raw) > customerclaim.MaxBytes {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	slot, err := c.budget.Acquire(ctx)
	if errors.Is(err, customerbudget.ErrBusy) {
		return ErrBusy
	}
	if err != nil {
		return err
	}
	defer slot.Release()
	started := c.clock().UTC()
	challenge, err := c.pool.TakeStatus(nonce)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	last := started
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
	if checkedClock().IsZero() {
		return ErrClock
	}
	lease, err := c.store.AcquireStatus(ctx, challenge, raw, checkedClock, c.acquire)
	if err != nil {
		return err
	}
	defer lease.Release()
	status, err := lease.Snapshot()
	if err != nil {
		return err
	}
	if err = lease.Check(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return emit(status)
}
