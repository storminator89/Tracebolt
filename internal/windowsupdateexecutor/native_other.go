//go:build !windows

package windowsupdateexecutor

import "context"

func openNative(context.Context) (comRuntime, error) { return nil, ErrUnavailable }
