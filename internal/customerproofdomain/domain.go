// Package customerproofdomain composes claim and pending-status proof work with
// one explicitly owned process-local budget. It does not expose HTTP, establish
// protected storage, authorize enrollment, or attest current lifecycle state.
package customerproofdomain

import (
	"context"
	"errors"
	"time"

	"localrmm/internal/customeradmission"
	"localrmm/internal/customerbudget"
	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerpending"
	"localrmm/internal/customerstatus"
)

var ErrInvalid = errors.New("customer proof domain unavailable")

// Domain must be created once for an admission domain and retained for the
// lifetime of its manager. Creating a domain per request or multiple domains
// over the same manager bypasses its bound. Multiple processes and restarts
// require separate ingress limits; this type does not provide them.
type Domain struct {
	admission *customeradmission.Coordinator
	status    *customerstatus.Coordinator
	budget    *customerbudget.Budget
}

// New creates both coordinators using exactly the same pool, store, authority,
// clock and a private budget. Use NewWithBudget when v3 activation or other
// proof paths must share the manager's single process-local proof budget.
func New(pool *customerchallenge.Pool, store *customerpending.Store, clock func() time.Time, acquire customerpending.AcquireAuthority) (*Domain, error) {
	return NewWithBudget(pool, store, clock, acquire, customerbudget.New())
}

// NewWithBudget uses the manager-owned budget for both coordinators. One
// manager owner must retain and pass this exact budget and pool to every claim,
// status and v3 activation path; creating a separate budget per path or request
// bypasses the shared bound. This is process-local, not a cluster-wide limit.
// Callers must independently establish protected non-aliased stores, live
// manager/issuer/customer/profile guards and any outer lifecycle lease.
func NewWithBudget(pool *customerchallenge.Pool, store *customerpending.Store, clock func() time.Time, acquire customerpending.AcquireAuthority, budget *customerbudget.Budget) (*Domain, error) {
	if pool == nil || store == nil || clock == nil || acquire == nil || !budget.Valid() {
		return nil, ErrInvalid
	}
	admission, err := customeradmission.NewWithBudget(pool, store, clock, acquire, budget)
	if err != nil {
		return nil, err
	}
	status, err := customerstatus.NewWithBudget(pool, store, clock, acquire, budget)
	if err != nil {
		return nil, err
	}
	return &Domain{admission: admission, status: status, budget: budget}, nil
}

// Admit handles an unapproved claim only; it does not issue credentials.
func (d *Domain) Admit(ctx context.Context, nonce string, raw []byte) (customerpending.Record, error) {
	if d == nil || d.admission == nil || d.status == nil || !d.budget.Valid() {
		return customerpending.Record{}, ErrInvalid
	}
	return d.admission.Submit(ctx, nonce, raw)
}

// WithPendingStatus is a source-only fixture handoff, not an HTTP response
// authority. The retained pending record does not prove the claim has not been
// approved or terminated. Before exposing a response, the manager must hold an
// outer enrollment lifecycle lease, recheck actual status and prove final response
// timing; a delayed callback can otherwise outlive the validated deadline.
func (d *Domain) WithPendingStatus(ctx context.Context, nonce string, raw []byte, emit func(customerpending.PendingStatus) error) error {
	if d == nil || d.admission == nil || d.status == nil || !d.budget.Valid() {
		return ErrInvalid
	}
	return d.status.WithStatus(ctx, nonce, raw, emit)
}
