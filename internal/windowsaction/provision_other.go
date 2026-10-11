//go:build !windows

package windowsaction

import "context"

func nativeProvisionSession(context.Context) (provisionSession, error) { return nil, ErrUnavailable }
func ProvisionPath() (string, error)                                   { return "", ErrUnavailable }
func EnableObserverPeerQueries(context.Context, Binding, string) error { return ErrUnavailable }
func enableBrokerPeerQueries(Policy) error                             { return nil }
