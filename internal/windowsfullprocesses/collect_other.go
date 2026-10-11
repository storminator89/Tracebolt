//go:build !windows

package windowsfullprocesses

import "context"

func Collect(ctx context.Context) (Capture, error) { return Capture{}, ErrUnsupported }
