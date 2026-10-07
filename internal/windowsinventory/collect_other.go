//go:build !windows

package windowsinventory

import "context"

func Collect(ctx context.Context) (Report, error) { return Report{}, ErrUnsupported }
