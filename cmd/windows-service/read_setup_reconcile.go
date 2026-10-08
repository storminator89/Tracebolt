package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"

	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
)

var errReadSetupStillDisabled = errors.New("fresh read setup remains disabled; no completed startup transition was proved")

type readSetupReconcileSteps struct {
	identity       func(string, lanclient.WindowsCapabilityConsent) (string, error)
	grantDigests   func(string, lanclient.WindowsCapabilityConsent) ([]lanclient.WindowsCapabilityGrantDigest, error)
	inspectStartup func(context.Context, windowsservice.Receipt) (windowsservice.Receipt, error)
	// Only the completion receipt may change; compare both protected original
	// intent and previous receipt while holding the installer store lock.
	finalizeReceipt func(previous, next []byte) error
}
type readSetupReconciliation struct {
	ReceiptFinalized bool `json:"receiptFinalized"`
	AlreadyComplete  bool `json:"alreadyComplete"`
}

// reconcileReadObservation finalizes only a provably completed startup effect.
// There are no install, enable, enrollment, SCM mutation or Start callbacks. A
// disabled service or missing/changed intent/identity/grant is never recovered.
func reconcileReadObservation(ctx context.Context, intentRaw, receiptRaw []byte, hooks readSetupReconcileSteps) (readSetupReconciliation, error) {
	zero := readSetupReconciliation{}
	if ctx == nil || ctx.Err() != nil || hooks.identity == nil || hooks.grantDigests == nil || hooks.inspectStartup == nil || hooks.finalizeReceipt == nil {
		return zero, errLifecycle
	}
	if len(intentRaw) == 0 || len(intentRaw) > 64<<10 || len(receiptRaw) == 0 || len(receiptRaw) > 64<<10 {
		return zero, errLifecycle
	}
	var intent readSetupIntent
	var retained installReceipt
	if json.Unmarshal(intentRaw, &intent) != nil || json.Unmarshal(receiptRaw, &retained) != nil {
		return zero, errLifecycle
	}
	canonicalIntent, _ := json.Marshal(intent)
	canonicalReceipt, _ := json.Marshal(retained)
	if !bytes.Equal(intentRaw, canonicalIntent) || !bytes.Equal(receiptRaw, canonicalReceipt) {
		return zero, errLifecycle
	}
	p := retained.ReadSetup
	if retained.Version != 2 || !retained.Prepared || !retained.Service.Complete || p == nil || validateReadSetupConsent(p.Consent) != nil || !reflect.DeepEqual(intent.Consent, p.Consent) || !validReadSetupBinding(p.SenderBinding) || !validReadSetupDigests(p.GrantDigests) || !p.Grants.MetadataScopeVerified || p.Grants.FailedScope != "" || !reflect.DeepEqual(p.Grants.AppliedScopes, readSetupScopes()[1:]) {
		return zero, errLifecycle
	}
	already := completeReadSetup(retained)
	if !already && (p.Phase != "startup-transition-started" || retained.Service.Version != 2) {
		return zero, errLifecycle
	}
	plan := intent.Plan
	if plan.Existing.Exists || plan.Configuration.StartType != 4 || plan.Layout != retained.Service.Layout || plan.InstallationID != retained.Service.InstallationID || plan.ExecutableSHA256 != retained.Service.ExecutableSHA256 {
		return zero, errLifecycle
	}
	configRaw, _ := json.Marshal(plan.Configuration)
	digest := sha256.Sum256(configRaw)
	staged := retained.Service
	staged.Version = 2
	staged.ConfigurationSHA256 = hex.EncodeToString(digest[:])
	if !already && staged != retained.Service {
		return zero, errLifecycle
	}
	path := filepath.Join(retained.Service.Layout.EnrollmentRoot, "agent.json")
	binding, err := hooks.identity(path, p.Consent)
	if err != nil || binding != p.SenderBinding {
		return zero, errLifecycle
	}
	grants, err := hooks.grantDigests(path, p.Consent)
	if err != nil || !reflect.DeepEqual(grants, p.GrantDigests) {
		return zero, errLifecycle
	}
	observed, err := hooks.inspectStartup(ctx, staged)
	if err != nil {
		return zero, err
	}
	if observed.Version == 2 {
		return zero, errReadSetupStillDisabled
	}
	expected := staged
	expected.Version = 1
	expected.ConfigurationSHA256 = observed.ConfigurationSHA256
	if observed != expected || !validReadSetupBinding(observed.ConfigurationSHA256) {
		return zero, errLifecycle
	}
	if already {
		if observed != retained.Service {
			return zero, errLifecycle
		}
		return readSetupReconciliation{AlreadyComplete: true}, nil
	}
	// A second readback after SCM inspection prevents accepting an identity or
	// grant change observed during reconciliation. No new grant is issued.
	binding, err = hooks.identity(path, p.Consent)
	if err != nil || binding != p.SenderBinding {
		return zero, errLifecycle
	}
	grants, err = hooks.grantDigests(path, p.Consent)
	if err != nil || !reflect.DeepEqual(grants, p.GrantDigests) || ctx.Err() != nil {
		return zero, errLifecycle
	}
	retained.Service = observed
	p.Phase = "configured"
	if !completeReadSetup(retained) {
		return zero, errLifecycle
	}
	next, err := json.Marshal(retained)
	if err != nil {
		return zero, err
	}
	if err = hooks.finalizeReceipt(receiptRaw, next); err != nil {
		return zero, err
	}
	return readSetupReconciliation{ReceiptFinalized: true}, nil
}
