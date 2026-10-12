//go:build !windows

package main

import (
	"context"
	managed "localrmm/internal/windowsmanagedmsi"
)

func nativeCoordinatedMutationProvision(context.Context, coordinatedMutationInput) (coordinatedMutationResult, error) {
	return coordinatedMutationResult{}, managed.ErrUnavailable
}
