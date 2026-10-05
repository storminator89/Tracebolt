//go:build !linux

package actionhelper

import "net"

func rootIdentity() error                            { return ErrUnavailable }
func loadAuthority() (Authority, error)              { return Authority{}, ErrUnavailable }
func checkPinnedInput(FilePin) error                 { return ErrUnavailable }
func peerIdentity(net.Conn) (Peer, error)            { return Peer{}, ErrUnavailable }
func inheritedListener(Policy) (net.Listener, error) { return nil, ErrUnavailable }
