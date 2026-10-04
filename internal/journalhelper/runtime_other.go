//go:build !linux

package journalhelper

import "context"

func Run(context.Context) error { return ErrRejected }
