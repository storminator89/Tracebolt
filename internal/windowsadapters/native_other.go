//go:build !windows

package windowsadapters

import "context"

func readNative(context.Context) Result { return Result{Err: ErrUnsupported} }
