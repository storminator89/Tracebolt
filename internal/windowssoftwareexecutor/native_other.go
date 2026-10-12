//go:build !windows

package windowssoftwareexecutor

import (
	"context"
	"localrmm/internal/windowspackage"
	job "localrmm/internal/windowssoftwarejob"
)

func openNative(context.Context, job.Consent, windowspackage.PreparedMSIReceipt) (nativeRuntime, error) {
	return nil, ErrUnavailable
}
