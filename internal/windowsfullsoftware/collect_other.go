//go:build !windows

package windowsfullsoftware

import "context"

func Collect(ctx context.Context) (Capture, error) { return Capture{}, ErrUnsupported }
