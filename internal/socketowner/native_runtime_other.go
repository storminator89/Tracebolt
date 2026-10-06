//go:build !linux

package socketowner

import "context"

func Run(context.Context) error { return ErrRejected }
