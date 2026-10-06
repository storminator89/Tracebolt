//go:build !linux

package socketowner

import "context"

func connectNativeClient(context.Context, Policy) (clientConnection, error) {
	return nil, ErrRejected
}
