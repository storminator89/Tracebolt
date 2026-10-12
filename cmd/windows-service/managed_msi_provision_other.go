//go:build !windows

package main

import (
	"context"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiservice"
)

func nativeManagedMSIProvision(context.Context, managedMSIInput) (managedMSIResult, error) {
	return managedMSIResult{}, managed.ErrUnavailable
}
func nativeManagedMSIActivate(context.Context, string, *windowsmanagedmsiservice.BackgroundRegistrationProof) error {
	return managed.ErrUnavailable
}

func nativeManagedMSIExport(context.Context) (managedMSIResult, error) {
	return managedMSIResult{}, managed.ErrUnavailable
}
