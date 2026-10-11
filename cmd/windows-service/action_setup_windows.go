//go:build windows

package main

import (
	"context"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsservice"
	"path/filepath"
	"time"
)

func nativeActionSetup(ctx context.Context, in actionSetupInput) error {
	_, e := withReceiptLease(ctx, openReceiptStore, func(receipt installReceipt, lease receiptStore) (any, error) {
		snapshot, e := windowsservice.InspectOwned(ctx, receipt.Service)
		if e != nil || snapshot.State != windowsservice.Stopped {
			return nil, errLifecycle
		}
		path := filepath.Join(receipt.Service.Layout.EnrollmentRoot, "agent.json")
		if e = lanclient.ValidateWindowsActionRelaySetup(path, in.policy.Binding, in.insecure); e != nil {
			return nil, e
		}
		if e = windowsaction.ReviewExistingSetup(in.policy); e != nil {
			return nil, e
		}
		if !in.apply {
			return nil, nil
		}
		if ctx.Err() != nil || lease.Verify() != nil {
			return nil, errLifecycle
		}
		root, e := windowsaction.AuthorityPath()
		if e != nil {
			return nil, e
		}
		if e = windowsaction.InitializeCreateOnly(root, in.policy, time.Now().UTC()); e != nil {
			return nil, e
		}
		if e = lanclient.InitializeWindowsActionRelayCreateOnly(path, in.policy.Binding, in.insecure); e != nil {
			return nil, e
		}
		return nil, lease.Verify()
	})
	return e
}
