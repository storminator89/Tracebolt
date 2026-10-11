//go:build !windows || (!amd64 && !arm64)

package windowsnetworkcontext

import "context"

func Collect(ctx context.Context) (Capture, error) { return Capture{}, ErrUnsupported }
