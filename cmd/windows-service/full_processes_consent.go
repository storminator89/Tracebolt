package main

import (
	"context"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"path/filepath"
)

// fullProcessesOperation keeps local ownership/stopped verification ahead of
// every consent read or write. Tests inject both operations, never native APIs.
func fullProcessesOperation(ctx context.Context, r request, receipt windowsservice.Receipt,
	inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error),
	configure func(string, string, bool, bool) (lanclient.WindowsFullProcessesConsentResult, error),
) (lanclient.WindowsFullProcessesConsentResult, error) {
	zero := lanclient.WindowsFullProcessesConsentResult{}
	mode := map[string]string{"full-processes-preview": "preview", "full-processes-enable": "enable", "full-processes-disable": "disable"}[r.mode]
	if ctx == nil || mode == "" || inspect == nil || configure == nil {
		return zero, errLifecycle
	}
	snapshot, err := inspect(ctx, receipt)
	if err != nil || snapshot.State != windowsservice.Stopped {
		return zero, errLifecycle
	}
	return configure(filepath.Join(receipt.Layout.EnrollmentRoot, "agent.json"), mode, mode == "enable", r.insecureHTTP)
}
