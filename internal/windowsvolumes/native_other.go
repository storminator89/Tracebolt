//go:build !windows

package windowsvolumes

import "context"

func openNative(context.Context) (cursor, error) { return nil, ErrUnsupported }
