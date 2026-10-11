//go:build !windows

package windowsstorageio

import "context"

func nativePerfDisk(context.Context) (PerfDisk, error) { return PerfDisk{}, ErrUnsupported }
