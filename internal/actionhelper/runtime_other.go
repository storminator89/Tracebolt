//go:build !linux

package actionhelper

import "context"

func Run(context.Context) error { return ErrRejected }
