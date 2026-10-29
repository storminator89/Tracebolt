package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"

	"localrmm/internal/windowsservice"
)

// This is a provisional diagnostic, never an admission token or a recovery
// coordinator. Its only dependencies are bounded protected-file reads and the
// exact-owned staged-service inspector. It cannot open enrollment state, call
// a manager, acquire/create a store, finalize a receipt or change SCM/grants.
type readAdminRecoveryStatus struct {
	SchemaVersion string `json:"schemaVersion"`
	Phase         string `json:"phase"`
	Evidence      string `json:"evidence"`
	Service       string `json:"service"`
	Recovery      string `json:"recovery"`
}

func inspectReadAdminRecovery(ctx context.Context, layout windowsservice.Layout,
	read func(string, int64) ([]byte, error),
	inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error),
) (readAdminRecoveryStatus, error) {
	zero := readAdminRecoveryStatus{}
	if ctx == nil || ctx.Err() != nil || read == nil || inspect == nil {
		return zero, errLifecycle
	}
	root := layout.StateRoot + "-installer"
	load := func(name string) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, errLifecycle
		}
		raw, err := read(filepath.Join(root, name), 64<<10)
		if err != nil || ctx.Err() != nil || len(raw) == 0 || len(raw) > 64<<10 {
			clear(raw)
			return nil, errLifecycle
		}
		return raw, nil
	}
	intentRaw, err := load("intent.json")
	if err != nil {
		return zero, err
	}
	defer clear(intentRaw)
	receiptRaw, err := load("receipt.json")
	if err != nil {
		return zero, err
	}
	defer clear(receiptRaw)
	var intent readSetupIntent
	var receipt installReceipt
	if !canonicalRecoveryRecord(intentRaw, &intent) || !canonicalRecoveryRecord(receiptRaw, &receipt) {
		return zero, errLifecycle
	}
	p := receipt.ReadSetup
	if receipt.Version != 12 || !receipt.Prepared || receipt.Service.Version != 2 || !receipt.Service.Complete || receipt.Service.Layout != layout || p == nil || !reflect.DeepEqual(intent.Consent, p.Consent) ||
		!reflect.DeepEqual(p.Consent, freshReadAdminSetupConsent(p.Consent.InsecureHTTPAcknowledged)) {
		return zero, errLifecycle
	}
	// Transitions with uncertain SCM effects and completed installs require their
	// own stronger reconciliation. This command never labels them absent/disabled.
	switch p.Phase {
	case "install-started", "claim-started", "activation-started", "grants-started", "grants-incomplete", "grants-verified":
	default:
		return zero, errLifecycle
	}
	plan := intent.Plan
	configRaw, _ := json.Marshal(plan.Configuration)
	digest := sha256.Sum256(configRaw)
	if plan.Existing.Exists || plan.Configuration.StartType != 4 || plan.Layout != layout || plan.InstallationID != receipt.Service.InstallationID || plan.ExecutableSHA256 != receipt.Service.ExecutableSHA256 || receipt.Service.ConfigurationSHA256 != hex.EncodeToString(digest[:]) {
		return zero, errLifecycle
	}
	snapshot, err := inspect(ctx, receipt.Service)
	if err != nil || ctx.Err() != nil || !snapshot.Exists || snapshot.ServiceSID != receipt.Service.ServiceSID || snapshot.State != windowsservice.Stopped || snapshot.Configuration.StartType != 4 {
		return zero, errLifecycle
	}
	// This does not verify the store manifest or reserve a future operation.
	// Reject changes even to fields that are intentionally absent from output.
	for _, record := range []struct {
		name string
		raw  []byte
	}{{"intent.json", intentRaw}, {"receipt.json", receiptRaw}} {
		next, err := load(record.name)
		same := bytes.Equal(next, record.raw)
		clear(next)
		if err != nil || !same {
			return zero, errLifecycle
		}
	}
	if ctx.Err() != nil {
		return zero, errLifecycle
	}
	final, err := inspect(ctx, receipt.Service)
	if err != nil || ctx.Err() != nil || !reflect.DeepEqual(final, snapshot) {
		return zero, errLifecycle
	}
	return readAdminRecoveryStatus{
		SchemaVersion: "tracebolt.windows-read-admin-recovery-status.v1",
		Phase:         p.Phase, Evidence: "protected-file-snapshot-not-manifest-verified",
		Service: "process-visible-owned-stopped-disabled", Recovery: "no-resume-authority",
	}, nil
}

func canonicalRecoveryRecord(raw []byte, value any) bool {
	if json.Unmarshal(raw, value) != nil {
		return false
	}
	canonical, err := json.Marshal(value)
	defer clear(canonical)
	return err == nil && bytes.Equal(raw, canonical)
}
