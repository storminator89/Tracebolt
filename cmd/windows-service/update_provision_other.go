//go:build !windows

package main

import (
	"context"
	job "localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdatesetup"
)

func nativeUpdateProvision(context.Context, updateProvisionInput) (updateProvisionResult, error) {
	return updateProvisionResult{}, errLifecycle
}
func nativeUpdateRemove(context.Context, bool, string) (windowsupdatesetup.RemovalPlan, error) {
	return windowsupdatesetup.RemovalPlan{}, errLifecycle
}
func nativeUpdateExport(context.Context) (job.SetupRegistration, error) {
	return job.SetupRegistration{}, errLifecycle
}
