//go:build windows && !amd64 && !arm64

package windowsadapters

import "context"

func readNative(context.Context) Result { return Result{Err: ErrUnsupported} }
