package main

import (
	"context"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"path/filepath"
)

// sessionContextOperation keeps local ownership/stopped verification ahead of
// every consent read or write. Tests inject both operations, never native APIs.
func sessionContextOperation(ctx context.Context, r request, receipt windowsservice.Receipt,
	inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error),
	configure func(string, string, bool, bool) (lanclient.WindowsSessionContextConsentResult, error),
) (lanclient.WindowsSessionContextConsentResult, error) {
	zero := lanclient.WindowsSessionContextConsentResult{}
	mode := map[string]string{"session-context-preview": "preview", "session-context-enable": "enable", "session-context-disable": "disable"}[r.mode]
	if ctx == nil || mode == "" || inspect == nil || configure == nil {
		return zero, errLifecycle
	}
	snapshot, err := inspect(ctx, receipt)
	if err != nil || snapshot.State != windowsservice.Stopped {
		return zero, errLifecycle
	}
	return configure(filepath.Join(receipt.Layout.EnrollmentRoot, "agent.json"), mode, mode == "enable", r.insecureHTTP)
}
