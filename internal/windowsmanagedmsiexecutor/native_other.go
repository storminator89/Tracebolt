//go:build !windows

package windowsmanagedmsiexecutor

import (
	"context"
	"localrmm/internal/windowspackage"
)

func openNative(context.Context, windowspackage.ManagedMSIReceipt) (nativeRuntime, error) {
	return nil, ErrUnavailable
}

func VerifyServiceToken() error { return ErrUnavailable }
