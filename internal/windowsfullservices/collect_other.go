//go:build !windows

package windowsfullservices

import "context"

func Collect(ctx context.Context) (Capture, error) { return Capture{}, ErrUnsupported }
