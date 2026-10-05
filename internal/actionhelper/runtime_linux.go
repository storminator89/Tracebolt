//go:build linux

package actionhelper

import (
	"context"
	"localrmm/internal/actionstate"
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
	s, e := New(Dependencies{Load: loadAuthority, Identity: rootIdentity, Peer: peerIdentity, Backend: newSystemdBackend(), State: state, Now: func() time.Time { return time.Now().UTC() }})
	if e != nil {
		return e
	}
	return s.Serve(ctx, listener)
}
