package main

import (
	"context"
	"encoding/json"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowshistoryrequest"
	"strings"
	"testing"
)

func TestEventHistoryFreshReadAdminV14Receipt12ExactSeparateAuthority(t *testing.T) {
	c := freshReadAdminSetupConsent(false)
	if c.Validate() != nil || c.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV14 || len(c.Scopes) != 21 || c.Scopes[20] != windowshistoryrequest.Scope || readSetupReceiptVersion(c) != 12 {
		t.Fatal("fresh history scope missing")
	}
	f := &readSetupFixture{}
	if _, e := setupReadObservation(context.Background(), "fixture", c, freshReadAdminFixtureHooks(f)); e != nil {
		t.Fatal(e)
	}
	if f.record.Version != 12 || !completeReadSetup(f.record) || len(f.record.ReadSetup.GrantDigests) != 20 || f.record.ReadSetup.GrantDigests[19].Scope != windowshistoryrequest.Scope || f.started != 1 {
		t.Fatal("incomplete fresh history receipt")
	}
	if _, e := decodeInstallReceipt(f.raw, f.record.Service.Layout); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"old-receipt", "old-consent", "missing", "changed-scope", "missing-digest"} {
		var bad installReceipt
		json.Unmarshal(f.raw, &bad)
		switch kind {
		case "old-receipt":
			bad.Version = 11
		case "old-consent":
			bad.ReadSetup.Consent = historicalReadAdminV13Consent()
		case "missing":
			bad.ReadSetup.GrantDigests = bad.ReadSetup.GrantDigests[:19]
		case "changed-scope":
			bad.ReadSetup.GrantDigests[19].Scope = "windows-selected-application-system-event-content-v1"
		case "missing-digest":
			bad.ReadSetup.GrantDigests[19].SHA256 = ""
		}
		raw, _ := json.Marshal(bad)
		if _, e := decodeInstallReceipt(raw, bad.Service.Layout); e == nil {
			t.Fatal("history receipt widened", kind)
		}
	}
	for _, text := range []string{setupWizardReadAdminSummary(), setupWizardReadAdminDisclosure(false), setupWizardReadAdminDisclosure(true)} {
		for _, want := range []string{"21", "historical", "credentials", "personal", "secrets", "LocalService"} {
			if !strings.Contains(text, want) {
				t.Fatal("fresh history warning missing", want)
			}
		}
	}
	for _, insecure := range []bool{false, true} {
		text := setupWizardReadAdminDisclosure(insecure)
		if !strings.Contains(text, windowshistoryrequest.Privacy) || insecure && !strings.Contains(text, windowshistoryrequest.HTTPPrivacy) {
			t.Fatal("exact scope risk disclosure absent")
		}
	}
}
func TestEventHistoryFreshSetupFailureAndReconcileKeepOriginalReceipt(t *testing.T) {
	f := &readSetupFixture{partial: true}
	c := freshReadAdminSetupConsent(false)
	if _, e := setupReadObservation(context.Background(), "fixture", c, freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.transitioned != 0 || f.record.ReadSetup.Grants.FailedScope != windowshistoryrequest.Scope || len(f.record.ReadSetup.Grants.AppliedScopes) != 19 || f.record.ReadSetup.Phase != "grants-incomplete" {
		t.Fatal("history failure started service or erased evidence")
	}
}
