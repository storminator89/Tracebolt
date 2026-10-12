//go:build !windows

package windowsmanagedmsiipc

import "context"

func callNative(context.Context, PeerConfig, request) (response, error) { return response{}, ErrPeer }
func Serve(context.Context, *Server) error                              { return ErrPeer }

// No non-Windows privilege or executable fallback exists.
type ServiceGuard struct{}

func OpenServiceGuard(context.Context, Config, bool) (*ServiceGuard, error) {
	return nil, ErrPeer
}
func (*ServiceGuard) Check(context.Context) error { return ErrPeer }
func (*ServiceGuard) Close()                      {}
