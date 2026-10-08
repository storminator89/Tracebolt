package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
)

type reconcileSetupFixture struct {
	intent, receipt            []byte
	writes                     int
	fail                       string
	disabled                   bool
	identityCalls, digestCalls int
}

func reconcileSetupCase(t *testing.T) *reconcileSetupFixture {
	t.Helper()
	c := readSetupConsentFixture()
	plan := windowsservice.InstallPlan{Layout: windowsservice.Layout{EnrollmentRoot: "fixture"}, InstallationID: "fixture-id", ExecutableSHA256: strings.Repeat("a", 64), Configuration: windowsservice.Configuration{StartType: 4}}
	raw, _ := json.Marshal(plan.Configuration)
	digest := sha256.Sum256(raw)
	receipt := installReceipt{Version: 2, Prepared: true, Service: windowsservice.Receipt{Version: 2, Complete: true, Layout: plan.Layout, InstallationID: plan.InstallationID, ExecutableSHA256: plan.ExecutableSHA256, ConfigurationSHA256: hex.EncodeToString(digest[:])}, ReadSetup: &readSetupProgress{Consent: c, Phase: "startup-transition-started", SenderBinding: strings.Repeat("b", 64), Grants: lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: readSetupScopes()[1:]}, GrantDigests: readSetupDigestFixture()}}
	intentRaw, _ := json.Marshal(readSetupIntent{plan, c})
	receiptRaw, _ := json.Marshal(receipt)
	return &reconcileSetupFixture{intent: intentRaw, receipt: receiptRaw}
}
func (f *reconcileSetupFixture) hooks() readSetupReconcileSteps {
	return readSetupReconcileSteps{
		identity: func(string, lanclient.WindowsCapabilityConsent) (string, error) {
			f.identityCalls++
			if f.fail == "identity" || f.fail == "changed-identity" && f.identityCalls > 1 {
				return "different", nil
			}
			return strings.Repeat("b", 64), nil
		},
		grantDigests: func(string, lanclient.WindowsCapabilityConsent) ([]lanclient.WindowsCapabilityGrantDigest, error) {
			f.digestCalls++
			if f.fail == "grants" {
				return nil, errLifecycle
			}
			d := readSetupDigestFixture()
			if f.fail == "changed-grant" || f.fail == "changed-second-grant" && f.digestCalls > 1 {
				d[0].SHA256 = strings.Repeat("e", 64)
			}
			return d, nil
		},
		inspectStartup: func(_ context.Context, r windowsservice.Receipt) (windowsservice.Receipt, error) {
			if f.fail == "SCM" {
				return windowsservice.Receipt{}, errLifecycle
			}
			if !f.disabled {
				r.Version = 1
				r.ConfigurationSHA256 = strings.Repeat("c", 64)
			}
			return r, nil
		},
		finalizeReceipt: func(previous, next []byte) error {
			if !bytes.Equal(previous, f.receipt) {
				return errLifecycle
			}
			if f.fail == "write" {
				return errLifecycle
			}
			f.writes++
			f.receipt = append([]byte(nil), next...)
			return nil
		},
	}
}
func TestFreshReadSetupReconcileOnlyFinalizesCompletedEffect(t *testing.T) {
	f := reconcileSetupCase(t)
	got, err := reconcileReadObservation(context.Background(), f.intent, f.receipt, f.hooks())
	if err != nil || !got.ReceiptFinalized || got.AlreadyComplete || f.writes != 1 {
		t.Fatal("completed effect not finalized", err)
	}
	var r installReceipt
	_ = json.Unmarshal(f.receipt, &r)
	if !completeReadSetup(r) {
		t.Fatal("invalid finalized receipt")
	}
	got, err = reconcileReadObservation(context.Background(), f.intent, f.receipt, f.hooks())
	if err != nil || got.ReceiptFinalized || !got.AlreadyComplete || f.writes != 1 {
		t.Fatal("idempotent reconciliation rewrote state", err)
	}
}
func TestFreshReadSetupReconcileDisabledChangedOrUnknownNeverWrites(t *testing.T) {
	for _, failure := range []string{"disabled", "identity", "changed-identity", "grants", "changed-grant", "changed-second-grant", "SCM", "write"} {
		t.Run(failure, func(t *testing.T) {
			f := reconcileSetupCase(t)
			f.fail = failure
			f.disabled = failure == "disabled"
			_, err := reconcileReadObservation(context.Background(), f.intent, f.receipt, f.hooks())
			if err == nil || f.writes != 0 {
				t.Fatal("unproven completion written")
			}
			if f.disabled && !errors.Is(err, errReadSetupStillDisabled) {
				t.Fatal("lost precise disabled outcome")
			}
		})
	}
	for _, mutation := range []func(*readSetupIntent, *installReceipt){
		func(i *readSetupIntent, r *installReceipt) { r.ReadSetup.Phase = "grants-started" },
		func(i *readSetupIntent, r *installReceipt) { i.Plan.InstallationID = "other" },
		func(i *readSetupIntent, r *installReceipt) { i.Plan.Configuration.StartType = 2 },
		func(i *readSetupIntent, r *installReceipt) { i.Consent.InsecureHTTPAcknowledged = true },
		func(i *readSetupIntent, r *installReceipt) { r.ReadSetup.GrantDigests = nil },
		func(i *readSetupIntent, r *installReceipt) { r.ReadSetup.Grants.FailedScope = readSetupScopes()[4] },
		func(i *readSetupIntent, r *installReceipt) { r.Service.ConfigurationSHA256 = strings.Repeat("f", 64) },
	} {
		f := reconcileSetupCase(t)
		var i readSetupIntent
		var r installReceipt
		_ = json.Unmarshal(f.intent, &i)
		_ = json.Unmarshal(f.receipt, &r)
		mutation(&i, &r)
		f.intent, _ = json.Marshal(i)
		f.receipt, _ = json.Marshal(r)
		if _, err := reconcileReadObservation(context.Background(), f.intent, f.receipt, f.hooks()); err == nil || f.writes != 0 {
			t.Fatal("unknown protected intent/receipt accepted")
		}
	}
}
func TestFreshReadSetupReconcileStrictCanonicalAndCancellation(t *testing.T) {
	f := reconcileSetupCase(t)
	for _, bad := range [][]byte{nil, append(append([]byte(nil), f.intent...), ' '), bytes.Replace(f.intent, []byte(`"plan":`), []byte(`"unknown":true,"plan":`), 1)} {
		if _, err := reconcileReadObservation(context.Background(), bad, f.receipt, f.hooks()); err == nil || f.writes != 0 {
			t.Fatal("noncanonical intent accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reconcileReadObservation(ctx, f.intent, f.receipt, f.hooks()); err == nil || f.writes != 0 {
		t.Fatal("canceled reconciliation wrote")
	}
}
