// Package customerbudget provides a process-local shared bound for customer
// enrollment proof work. It is not a rate limit, cluster-wide bound or grant.
package customerbudget

import (
	"context"
	"errors"
	"sync"
)

const MaxProofs = 2

var ErrInvalid = errors.New("customer proof budget unavailable")
var ErrBusy = errors.New("customer proof budget exhausted")

// Budget must be instantiated exactly once per admission domain and shared by
// its claim and status coordinators. It is deliberately process-local; callers
// must separately address restarts and multiple manager instances.
type Budget struct{ slots chan struct{} }

func New() *Budget { return &Budget{slots: make(chan struct{}, MaxProofs)} }

// Valid reports initialization, not any right to access protected state.
func (b *Budget) Valid() bool { return b != nil && b.slots != nil && cap(b.slots) == MaxProofs }

// InUse is a transient diagnostic snapshot, not a reservation or authority.
// A negative result means the budget is uninitialized.
func (b *Budget) InUse() int {
	if !b.Valid() {
		return -1
	}
	return len(b.slots)
}

// Lease retains exactly one proof slot. Release is idempotent, including under
// concurrent calls; callers must defer it across panic and error paths.
type leaseState struct {
	once  sync.Once
	slots chan struct{}
}
type Lease struct{ state *leaseState }

func (l *Lease) Release() {
	if l != nil && l.state != nil {
		l.state.once.Do(func() { <-l.state.slots })
	}
}

// Acquire never blocks while waiting for capacity. Busy does not consume a
// challenge; callers must acquire before the pool's one-time Take operation.
func (b *Budget) Acquire(ctx context.Context) (*Lease, error) {
	if !b.Valid() || ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case b.slots <- struct{}{}:
		l := &Lease{state: &leaseState{slots: b.slots}}
		if err := ctx.Err(); err != nil {
			l.Release()
			return nil, err
		}
		return l, nil
	default:
		return nil, ErrBusy
	}
}
