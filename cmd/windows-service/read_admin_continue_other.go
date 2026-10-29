//go:build !windows

package main

import "context"

func nativeReadAdminContinuation(context.Context, readAdminContinuationRequest) (readAdminContinuationPlan, error) {
	return readAdminContinuationPlan{}, errLifecycle
}
