//go:build !windows

package windowspackage

import (
	"context"

	"localrmm/internal/windowsservice"
)

func nativeUpdateImageBackend(context.Context, windowsservice.Receipt) (updateImageBackend, error) {
	return nil, ErrUnsupported
}

func nativeUpdateServiceImageBackend(context.Context, windowsservice.Receipt) (updateImageBackend, error) {
	return nil, ErrUnsupported
}
