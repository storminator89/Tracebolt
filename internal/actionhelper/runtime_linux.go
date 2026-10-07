//go:build linux

package actionhelper

import (
	"context"
	"localrmm/internal/actionstate"
	"localrmm/internal/mutationfence"
	"os"
	"time"
)

// Run is the exclusive action-helper runtime entry point. It only accepts protected
// existing policy/key/state and one validated inherited socket. It provisions
// nothing and does not create a ledger or listen socket. A separate authorized
// installation and native acceptance review remain required before host use.
func Run(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || rootIdentity() != nil {
		return ErrRejected
	}
	authority, e := loadAuthority()
	if e != nil {
		return ErrRejected
	}
	verifier, e := authority.verifier()
	if e != nil {
		return ErrRejected
	}
	state, e := actionstate.Open(ctx, StateDirectory, verifier)
	if e != nil {
		return e
	}
	defer state.Close()
	listener, e := inheritedListener(authority.Policy)
	if e != nil {
		return ErrRejected
	}
	defer listener.Close()
	var fence *mutationfence.Fence
	required := false
	if _, statErr := os.Lstat(mutationfence.DefaultDirectory); !os.IsNotExist(statErr) {
		required = true
		if statErr != nil {
			return ErrRejected
		}
		p := authority.Policy
		fence, e = mutationfence.Open(ctx, mutationfence.DefaultDirectory, mutationfence.Binding{ManagerID: p.ManagerID, EndpointID: p.EndpointID, IncarnationDigest: p.IncarnationDigest})
		if e != nil {
			return ErrRejected
		}
		defer fence.Close()
	}
	s, e := New(Dependencies{Fence: fence, FenceRequired: required, Load: loadAuthority, Identity: func() error { return fenceRuntimeIdentity(mutationfence.DefaultDirectory, fence != nil, rootIdentity) }, Peer: peerIdentity, Backend: newSystemdBackend(), State: state, Now: func() time.Time { return time.Now().UTC() }})
	if e != nil {
		return e
	}
	return s.Serve(ctx, listener)
}

// An unfenced helper started before package setup cannot remain an admission
// authority after the shared directory appears. It must restart and open state.
func fenceRuntimeIdentity(directory string, hasFence bool, identity func() error) error {
	if identity == nil || identity() != nil {
		return ErrRejected
	}
	if !hasFence {
		if _, e := os.Lstat(directory); !os.IsNotExist(e) {
			return ErrRejected
		}
	}
	return nil
}
