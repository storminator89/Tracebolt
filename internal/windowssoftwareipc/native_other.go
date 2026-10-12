//go:build !windows

package windowssoftwareipc

import "context"

func callNative(context.Context, PeerConfig, request) (response, error) { return response{}, ErrPeer }
func Serve(context.Context, *Server) error                              { return ErrPeer }

// No non-Windows privilege or executable fallback exists.
type ForegroundGuard struct{}

func OpenForegroundGuard(context.Context, Config, bool) (*ForegroundGuard, error) {
	return nil, ErrPeer
}
func (*ForegroundGuard) Check(context.Context) error { return ErrPeer }
func (*ForegroundGuard) Close()                      {}
