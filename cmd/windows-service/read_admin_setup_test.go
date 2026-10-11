package main

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/lanclient"
	"reflect"
	"strings"
	"testing"
)

func readAdminDigestFixture() []lanclient.WindowsCapabilityGrantDigest {
	r := []lanclient.WindowsCapabilityGrantDigest{}
	for _, scope := range lanclient.WindowsReadAdminScopes()[1:] {
		r = append(r, lanclient.WindowsCapabilityGrantDigest{Scope: scope, SHA256: strings.Repeat("d", 64)})
	}
	return r
}
func readAdminFixtureHooks(f *readSetupFixture) readSetupSteps {
	h := f.hooks()
	h.configure = func(_ string, c lanclient.WindowsCapabilityConsent) (lanclient.WindowsCapabilityConsentResult, error) {
		f.configured++
		if !reflect.DeepEqual(c, readAdminSetupConsent(false)) {
			return lanclient.WindowsCapabilityConsentResult{}, errLifecycle
		}
		if f.partial {
			return lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: c.Scopes[1:8], FailedScope: c.Scopes[8]}, errLifecycle
		}
		return lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: c.Scopes[1:]}, f.call("configure")
	}
	h.grantDigests = func(string, lanclient.WindowsCapabilityConsent) ([]lanclient.WindowsCapabilityGrantDigest, error) {
		return readAdminDigestFixture(), f.call("grant-digests")
	}
	return h
}
func TestReadAdminFreshProfileUsesDistinctReceiptAndExactElevenGrants(t *testing.T) {
	f := &readSetupFixture{}
	if _, e := setupReadObservation(context.Background(), "fixture", readAdminSetupConsent(false), readAdminFixtureHooks(f)); e != nil {
		t.Fatal(e)
	}
	if f.record.Version != 3 || !completeReadSetup(f.record) || len(f.record.ReadSetup.GrantDigests) != 11 || f.started != 1 {
		t.Fatal("missing v3 completion")
	}
	raw := append([]byte(nil), f.raw...)
	if _, e := decodeInstallReceipt(raw, f.record.Service.Layout); e != nil {
		t.Fatal(e)
	}
	f.record.Version = 2
	bad, _ := json.Marshal(f.record)
	if _, e := decodeInstallReceipt(bad, f.record.Service.Layout); e == nil {
		t.Fatal("v2 promoted to read admin")
	}
	old := &readSetupFixture{}
	if _, e := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), old.hooks()); e != nil {
		t.Fatal(e)
	}
	if old.record.Version != 2 || len(old.record.ReadSetup.GrantDigests) != 4 {
		t.Fatal("old receipt expanded")
	}
	old.record.Version = 3
	bad, _ = json.Marshal(old.record)
	if _, e := decodeInstallReceipt(bad, old.record.Service.Layout); e == nil {
		t.Fatal("old consent accepted under v3")
	}
}
func TestReadAdminFreshFailuresNeverStartIncompleteAuthority(t *testing.T) {
	for _, phase := range []string{"fresh-scopes", "grants-started", "configure", "verify-grants", "grant-digests", "grants-verified", "startup-transition-started"} {
		f := &readSetupFixture{fail: phase}
		if _, e := setupReadObservation(context.Background(), "fixture", readAdminSetupConsent(false), readAdminFixtureHooks(f)); e == nil || f.started != 0 || f.transitioned != 0 {
			t.Fatal(phase, e, f.started)
		}
	}
	f := &readSetupFixture{partial: true}
	if _, e := setupReadObservation(context.Background(), "fixture", readAdminSetupConsent(false), readAdminFixtureHooks(f)); e == nil || f.started != 0 || f.record.ReadSetup.Phase != "grants-incomplete" || f.record.ReadSetup.Grants.FailedScope != lanclient.WindowsReadAdminScopes()[8] {
		t.Fatal("partial grant lost")
	}
}
func TestReadAdminWizardGroupedChoiceDisclosureAndLegacyChoice(t *testing.T) {
	if setupWizardConsent().SchemaVersion != lanclient.WindowsCapabilityConsentVersionV3 || len(setupWizardConsent().Scopes) != 5 {
		t.Fatal("internal five-scope contract changed")
	}
	for _, insecure := range []bool{false, true} {
		text := setupWizardReadAdminDisclosure(insecure)
		for _, word := range []string{"12 explicit read scopes", "Users and sessions", "personal", "Provider presence has not been checked", "LocalService", "cached WUA", "service control", "Selected event-message"} {
			if !strings.Contains(text, word) {
				t.Fatal("missing", word)
			}
		}
		var exact bytes.Buffer
		if writeReadSetupDisclosure(&exact, readAdminSetupConsent(insecure)) != nil || !strings.Contains(text, exact.String()) {
			t.Fatal("full disclosure omitted")
		}
		if insecure && !strings.Contains(text, "plaintext") {
			t.Fatal("HTTP risk absent")
		}
	}
}

func TestReadAdminFreshGrantGuardPinsOriginalRecordedSender(t *testing.T) {
	f := &readSetupFixture{fail: "configure"}
	h := readAdminFixtureHooks(f)
	h.configure = func(_ string, c lanclient.WindowsCapabilityConsent) (lanclient.WindowsCapabilityConsentResult, error) {
		if _, e := readAdminFreshGrantReceipt(f.raw, c, strings.Repeat("a", 64)); e != nil {
			t.Fatal("original sender rejected", e)
		}
		if _, e := readAdminFreshGrantReceipt(f.raw, c, strings.Repeat("b", 64)); e == nil {
			t.Fatal("replacement sender admitted before writes")
		}
		for _, kind := range []string{"phase", "version", "binding", "prepared", "service", "extra"} {
			var r installReceipt
			json.Unmarshal(f.raw, &r)
			switch kind {
			case "phase":
				r.ReadSetup.Phase = "configured"
			case "version":
				r.Version = 2
			case "binding":
				r.ReadSetup.SenderBinding = ""
			case "prepared":
				r.Prepared = false
			case "service":
				r.Service.Version = 1
			}
			raw, _ := json.Marshal(r)
			if kind == "extra" {
				raw = append(raw[:len(raw)-1], []byte(`,"extra":true}`)...)
			}
			if _, e := readAdminFreshGrantReceipt(raw, c, strings.Repeat("a", 64)); e == nil {
				t.Fatal(kind, "phase admitted")
			}
		}
		return lanclient.WindowsCapabilityConsentResult{}, errLifecycle
	}
	if _, e := setupReadObservation(context.Background(), "fixture", readAdminSetupConsent(false), h); e == nil || f.started != 0 || f.transitioned != 0 {
		t.Fatal("guard failure started service")
	}
}

func TestReadAdminWizardSummaryKeepsAllGroupsAndExplicitExclusions(t *testing.T) {
	text := setupWizardReadAdminSummary()
	for _, group := range lanclient.WindowsReadAdminGroups() {
		if !strings.Contains(text, group.Name) || !strings.Contains(text, group.Summary) {
			t.Fatal("group scope omitted")
		}
	}
	for _, word := range []string{"12 read scopes", "personal", "LocalService", "unverified", "event-message", "cached WUA", "service control", "external-AI", "Scope details"} {
		if !strings.Contains(text, word) {
			t.Fatal("summary omits", word)
		}
	}
	if len(text) >= len(setupWizardReadAdminDisclosure(false)) || !strings.Contains(setupWizardReadAdminHTTPRiskSummary, "plaintext") || !strings.Contains(setupWizardReadAdminHTTPRiskSummary, "forged") {
		t.Fatal("summary/risk presentation incomplete")
	}
}
