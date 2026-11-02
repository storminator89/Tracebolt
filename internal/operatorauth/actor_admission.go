package operatorauth

import (
	"context"
	"sync"
)

// ActorAdmission returns the context carrying its unforgeable held-lease proof.
// Every nested call must use that context; the release is mandatory on all paths.
type ActorAdmission func(context.Context, string, uint64, ...Capability) (context.Context, func(), error)
type approvalEpochKey struct{}

func WithApprovalEpoch(ctx context.Context, epoch uint64) context.Context {
	return context.WithValue(ctx, approvalEpochKey{}, epoch)
}
func ApprovalEpochFromContext(ctx context.Context) uint64 {
	if ctx == nil {
		return 0
	}
	epoch, _ := ctx.Value(approvalEpochKey{}).(uint64)
	return epoch
}

type actorProofKey struct{}
type actorProof struct {
	owner   *managerState
	actor   string
	epoch   uint64
	caps    uint32
	mu      sync.Mutex
	closed  bool
	refs    int
	release func()
}
type actorProofLink struct {
	proof    *actorProof
	previous *actorProofLink
}

func (p *actorProof) retain() (func(), bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, false
	}
	p.refs++
	var once sync.Once
	return func() { once.Do(func() { p.drop(false) }) }, true
}
func (p *actorProof) drop(root bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if root {
		p.closed = true
	}
	p.refs--
	if p.refs == 0 {
		p.release()
	}
}

// LeaseActor carries a reference-counted proof rather than reacquiring a reader
// beneath a pending revocation writer. New distinct actors must be acquired in
// lexicographic ID order; conflicting epoch/capability upgrades fail closed.
// The outer release closes reuse, but the underlying lease remains held until
// already admitted nested users also release it.
func (m *Manager) LeaseActor(ctx context.Context, actor string, epoch uint64, caps ...Capability) (context.Context, func(), error) {
	if m == nil || ctx == nil || ctx.Err() != nil || len(caps) == 0 {
		return ctx, nil, ErrForbidden
	}
	var bits uint32
	for _, c := range caps {
		b := capabilityBit(c)
		if b == 0 {
			return ctx, nil, ErrForbidden
		}
		bits |= b
	}
	head, _ := ctx.Value(actorProofKey{}).(*actorProofLink)
	for link := head; link != nil; link = link.previous {
		p := link.proof
		if p.owner != m.managerState {
			continue
		}
		if p.actor == actor {
			if p.epoch != epoch || p.caps&bits != bits {
				return ctx, nil, ErrForbidden
			}
			release, ok := p.retain()
			if !ok {
				return ctx, nil, ErrForbidden
			}
			return ctx, release, nil
		}
		if p.actor > actor {
			return ctx, nil, ErrForbidden
		}
	}
	release, err := m.BeginActorAdmission(ctx, actor, epoch, caps...)
	if err != nil {
		return ctx, nil, err
	}
	p := &actorProof{owner: m.managerState, actor: actor, epoch: epoch, caps: bits, refs: 1, release: release}
	var once sync.Once
	return context.WithValue(ctx, actorProofKey{}, &actorProofLink{p, head}), func() { once.Do(func() { p.drop(true) }) }, nil
}
