//go:build !windows

package main

import (
	"context"
	job "localrmm/internal/windowssoftwarejob"
)

func nativeSoftwareProvision(context.Context, softwareProvisionInput) (softwareProvisionResult, error) {
	return softwareProvisionResult{}, errLifecycle
}

func nativeSoftwareExport(context.Context) (job.SetupRegistration, error) {
	return job.SetupRegistration{}, errLifecycle
}
