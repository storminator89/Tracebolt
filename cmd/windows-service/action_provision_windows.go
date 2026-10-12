//go:build windows

package main

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowspackage"
	"path/filepath"

	"localrmm/internal/lanclient"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsservice"
)

func nativeActionProvision(ctx context.Context, in actionProvisionInput) (plan windowsaction.ProvisionPlan, err error) {
	_, err = withReceiptLease(ctx, openReceiptStore, func(receipt installReceipt, lease receiptStore) (any, error) {
		if e := windowspackage.CheckManagedMSIAbsent(ctx); e != nil {
			return nil, e
		}
		path := filepath.Join(receipt.Service.Layout.EnrollmentRoot, "agent.json")
		validate := func(ctx context.Context) error {
			if ctx.Err() != nil || lease.Verify() != nil {
				return errLifecycle
			}
			snapshot, e := windowsservice.InspectOwned(ctx, receipt.Service)
			if e != nil || snapshot.State != windowsservice.Stopped {
				return errLifecycle
			}
			return lanclient.ValidateWindowsActionRelaySetup(path, in.policy.Binding, in.insecure)
		}
		if e := validate(ctx); e != nil {
			return nil, e
		}
		if e := lanclient.ValidateWindowsActionRelayFreshSetup(path, in.policy.Binding, in.insecure); e != nil {
			return nil, e
		}
		raw, e := json.Marshal(receipt)
		if e != nil {
			return nil, e
		}
		plan, e = windowsaction.PlanProvision(ctx, in.policy, in.artifact, in.payload, windowsaction.Digest(raw), in.insecure)
		if e != nil {
			return nil, e
		}
		if !in.apply {
			return nil, validate(ctx)
		}
		hooks := windowsaction.ProvisionHooks{Validate: validate, CreateRelay: func(ctx context.Context) error {
			return lanclient.InitializeWindowsActionProvisionedRelay(path, in.policy.Binding, in.insecure, plan.Digest(), "sha256:"+in.artifact.SHA256)
		}, VerifyRelay: func(ctx context.Context) error {
			return lanclient.VerifyWindowsActionProvisionedRelay(path, in.policy.Binding, in.insecure, plan.Digest(), "sha256:"+in.artifact.SHA256)
		}}
		return nil, windowsaction.ApplyProvision(ctx, plan, in.payload, in.approved, hooks)
	})
	return
}
