//go:build !windows

package windowspackage

import (
	"context"

	"localrmm/internal/windowsservice"
)

func nativeSoftwareImageBackend(context.Context, windowsservice.Receipt) (softwareImageBackend, error) {
	return nil, ErrUnsupported
}
