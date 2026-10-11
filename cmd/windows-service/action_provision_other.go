//go:build !windows

package main

import (
	"context"
	"localrmm/internal/windowsaction"
)

func nativeActionProvision(context.Context, actionProvisionInput) (windowsaction.ProvisionPlan, error) {
	return windowsaction.ProvisionPlan{}, errLifecycle
}
