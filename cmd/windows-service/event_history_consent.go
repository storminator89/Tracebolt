package main

import (
	"context"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"path/filepath"
)

// eventHistoryOperation keeps local ownership/stopped verification ahead of
// every consent read or write. Tests inject both operations, never native APIs.
func eventHistoryOperation(ctx context.Context, r request, receipt windowsservice.Receipt,
	inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error),
	configure func(string, string, bool, bool) (lanclient.WindowsEventHistoryConsentResult, error),
) (lanclient.WindowsEventHistoryConsentResult, error) {
	zero := lanclient.WindowsEventHistoryConsentResult{}
	mode := map[string]string{"event-history-preview": "preview", "event-history-enable": "enable", "event-history-disable": "disable"}[r.mode]
	if ctx == nil || mode == "" || inspect == nil || configure == nil {
		return zero, errLifecycle
	}
	snapshot, err := inspect(ctx, receipt)
	if err != nil || snapshot.State != windowsservice.Stopped || ctx.Err() != nil {
		return zero, errLifecycle
	}
	return configure(filepath.Join(receipt.Layout.EnrollmentRoot, "agent.json"), mode, mode == "enable", r.insecureHTTP)
}
