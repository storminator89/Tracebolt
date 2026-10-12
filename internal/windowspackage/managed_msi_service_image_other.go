//go:build !windows

package windowspackage

import (
	"context"

	"localrmm/internal/windowsservice"
)

func nativeManagedMSIImageBackend(context.Context, windowsservice.Receipt) (managedMSIImageBackend, error) {
	return nil, ErrUnsupported
}
