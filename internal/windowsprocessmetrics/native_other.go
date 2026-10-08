//go:build !windows

package windowsprocessmetrics

import "context"

func readNative(context.Context, uint32) reading {
	return reading{CPUErr: ErrUnsupported, MemoryErr: ErrUnsupported}
}
