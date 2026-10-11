package main

import (
	"context"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"path/filepath"
)

// fullSoftwareOperation keeps local ownership/stopped verification ahead of
// every consent read or write. Tests inject both operations, never native APIs.
func fullSoftwareOperation(ctx context.Context, r request, receipt windowsservice.Receipt,
	inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error),
	configure func(string, string, bool, bool) (lanclient.WindowsFullSoftwareConsentResult, error),
) (lanclient.WindowsFullSoftwareConsentResult, error) {
	zero := lanclient.WindowsFullSoftwareConsentResult{}
	mode := map[string]string{"full-software-preview": "preview", "full-software-enable": "enable", "full-software-disable": "disable"}[r.mode]
	if ctx == nil || mode == "" || inspect == nil || configure == nil {
		return zero, errLifecycle
	}
	snapshot, err := inspect(ctx, receipt)
	if err != nil || snapshot.State != windowsservice.Stopped {
		return zero, errLifecycle
	}
	return configure(filepath.Join(receipt.Layout.EnrollmentRoot, "agent.json"), mode, mode == "enable", r.insecureHTTP)
}

// History shares the ordinary software protected state, but requires its own CLI
// acknowledgement and the same stopped-owned-service guard before any state access.
func softwareHistoryOperation(ctx context.Context, r request, receipt windowsservice.Receipt,
	inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error),
	configure func(string, string, bool, bool) (lanclient.WindowsFullSoftwareConsentResult, error),
) (lanclient.WindowsFullSoftwareConsentResult, error) {
	zero := lanclient.WindowsFullSoftwareConsentResult{}
	mode := map[string]string{"software-history-preview": "preview", "software-history-enable": "enable", "software-history-disable": "disable"}[r.mode]
	if ctx == nil || mode == "" || inspect == nil || configure == nil {
		return zero, errLifecycle
	}
	snapshot, err := inspect(ctx, receipt)
	if err != nil || snapshot.State != windowsservice.Stopped {
		return zero, errLifecycle
	}
	return configure(filepath.Join(receipt.Layout.EnrollmentRoot, "agent.json"), mode, mode == "enable", r.insecureHTTP)
}
