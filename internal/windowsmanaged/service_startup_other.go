//go:build !windows

package windowsmanaged

import "context"

func serviceStartupNativeReader(context.Context) (ServiceStartupReader, func(), error) {
	return nil, nil, ErrServiceStartupUnsupported
}
