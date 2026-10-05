//go:build !linux

package actionclient

import "context"

func connectProtected(context.Context) (connection, error) { return connection{}, ErrUnavailable }
