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
		for _, word := range []string{"13 explicit read scopes", "physical chassis serial (Win32_SystemEnclosure)", "BIOS serial metadata", "manufacturer/model", "firmware vendor/version/date", "power/battery", "Users and sessions", "personal", "Provider presence has not been checked", "LocalService", "cached WUA", "service control", "Selected event-message"} {
			if !strings.Contains(text, word) {
				t.Fatal("missing", word)
			}
		}
		var exact bytes.Buffer
		if writeReadSetupDisclosure(&exact, freshReadAdminSetupConsent(insecure)) != nil || !strings.Contains(text, exact.String()) {
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
	for _, group := range lanclient.WindowsReadAdminGroupsV6() {
		if !strings.Contains(text, group.Name) || !strings.Contains(text, group.Summary) {
			t.Fatal("group scope omitted")
		}
	}
	for _, word := range []string{"13 read scopes", "physical chassis serial (Win32_SystemEnclosure)", "BIOS serial metadata", "personal", "LocalService", "unverified", "event-message", "cached WUA", "service control", "external-AI", "Scope details"} {
		if !strings.Contains(text, word) {
			t.Fatal("summary omits", word)
		}
	}
	if len(text) >= len(setupWizardReadAdminDisclosure(false)) || !strings.Contains(setupWizardReadAdminHTTPRiskSummary, "plaintext") || !strings.Contains(setupWizardReadAdminHTTPRiskSummary, "forged") {
		t.Fatal("summary/risk presentation incomplete")
	}
}

func freshReadAdminFixtureHooks(f *readSetupFixture) readSetupSteps {
	h := f.hooks()
	h.configure = func(_ string, c lanclient.WindowsCapabilityConsent) (lanclient.WindowsCapabilityConsentResult, error) {
		f.configured++
		if !reflect.DeepEqual(c, freshReadAdminSetupConsent(false)) {
			return lanclient.WindowsCapabilityConsentResult{}, errLifecycle
		}
		if f.partial {
			return lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: c.Scopes[1:12], FailedScope: c.Scopes[12]}, errLifecycle
		}
		return lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: c.Scopes[1:]}, f.call("configure")
	}
	h.grantDigests = func(_ string, c lanclient.WindowsCapabilityConsent) ([]lanclient.WindowsCapabilityGrantDigest, error) {
		digests := []lanclient.WindowsCapabilityGrantDigest{}
		for _, scope := range c.Scopes[1:] {
			digests = append(digests, lanclient.WindowsCapabilityGrantDigest{Scope: scope, SHA256: strings.Repeat("d", 64)})
		}
		return digests, f.call("grant-digests")
	}
	return h
}

func TestReadAdminV6FreshProfileReceipt4ExactTwelveGrants(t *testing.T) {
	f := &readSetupFixture{}
	c := freshReadAdminSetupConsent(false)
	if _, e := setupReadObservation(context.Background(), "fixture", c, freshReadAdminFixtureHooks(f)); e != nil {
		t.Fatal(e)
	}
	if f.record.Version != 4 || !completeReadSetup(f.record) || len(f.record.ReadSetup.GrantDigests) != 12 || f.record.ReadSetup.GrantDigests[11].Scope != "windows-hardware-context-v1" || f.started != 1 {
		t.Fatal("missing fresh receipt4 authority")
	}
	if _, e := decodeInstallReceipt(f.raw, f.record.Service.Layout); e != nil {
		t.Fatal(e)
	}
	for _, version := range []int{1, 2, 3} {
		bad := f.record
		bad.Version = version
		raw, _ := json.Marshal(bad)
		if _, e := decodeInstallReceipt(raw, f.record.Service.Layout); e == nil {
			t.Fatal("old receipt promoted", version)
		}
	}
	for _, consent := range []lanclient.WindowsCapabilityConsent{readSetupConsentFixture(), readAdminSetupConsent(false)} {
		bad := f.record
		progress := *f.record.ReadSetup
		bad.ReadSetup = &progress
		progress.Consent = consent
		raw, _ := json.Marshal(bad)
		if _, e := decodeInstallReceipt(raw, f.record.Service.Layout); e == nil {
			t.Fatal("old consent promoted to receipt4")
		}
	}
	for _, kind := range []string{"hardware-missing", "hardware-misordered", "hardware-invalid"} {
		var bad installReceipt
		json.Unmarshal(f.raw, &bad)
		switch kind {
		case "hardware-missing":
			bad.ReadSetup.GrantDigests = bad.ReadSetup.GrantDigests[:11]
		case "hardware-misordered":
			bad.ReadSetup.GrantDigests[10], bad.ReadSetup.GrantDigests[11] = bad.ReadSetup.GrantDigests[11], bad.ReadSetup.GrantDigests[10]
		case "hardware-invalid":
			bad.ReadSetup.GrantDigests[11].SHA256 = ""
		}
		raw, _ := json.Marshal(bad)
		if _, e := decodeInstallReceipt(raw, bad.Service.Layout); e == nil {
			t.Fatal("invalid hardware digest admitted", kind)
		}
	}
}

func TestReadAdminV6FreshGrantFailuresAndOriginalSenderGuard(t *testing.T) {
	for _, phase := range []string{"fresh-scopes", "grants-started", "configure", "verify-grants", "grant-digests", "grants-verified", "startup-transition-started"} {
		f := &readSetupFixture{fail: phase}
		if _, e := setupReadObservation(context.Background(), "fixture", freshReadAdminSetupConsent(false), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.transitioned != 0 {
			t.Fatal("incomplete authority started", phase, e)
		}
	}
	f := &readSetupFixture{partial: true}
	if _, e := setupReadObservation(context.Background(), "fixture", freshReadAdminSetupConsent(false), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.record.ReadSetup.Phase != "grants-incomplete" || f.record.ReadSetup.Grants.FailedScope != "windows-hardware-context-v1" || len(f.record.ReadSetup.Grants.AppliedScopes) != 11 {
		t.Fatal("partial hardware failure erased evidence")
	}
	f = &readSetupFixture{}
	h := freshReadAdminFixtureHooks(f)
	h.configure = func(_ string, c lanclient.WindowsCapabilityConsent) (lanclient.WindowsCapabilityConsentResult, error) {
		if _, e := readAdminFreshGrantReceipt(f.raw, c, strings.Repeat("a", 64)); e != nil {
			t.Fatal("original phase rejected", e)
		}
		if _, e := readAdminFreshGrantReceipt(f.raw, c, strings.Repeat("b", 64)); e == nil {
			t.Fatal("replacement identity admitted")
		}
		for _, kind := range []string{"version", "phase", "consent", "prepared", "service", "binding", "extra"} {
			var bad installReceipt
			json.Unmarshal(f.raw, &bad)
			switch kind {
			case "version":
				bad.Version = 3
			case "phase":
				bad.ReadSetup.Phase = "configured"
			case "consent":
				bad.ReadSetup.Consent = readAdminSetupConsent(false)
			case "prepared":
				bad.Prepared = false
			case "service":
				bad.Service.Version = 1
			case "binding":
				bad.ReadSetup.SenderBinding = ""
			}
			raw, _ := json.Marshal(bad)
			if kind == "extra" {
				raw = append(raw[:len(raw)-1], []byte(`,"extra":true}`)...)
			}
			if _, e := readAdminFreshGrantReceipt(raw, c, strings.Repeat("a", 64)); e == nil {
				t.Fatal("mutated fresh phase admitted", kind)
			}
		}
		return lanclient.WindowsCapabilityConsentResult{}, errLifecycle
	}
	if _, e := setupReadObservation(context.Background(), "fixture", freshReadAdminSetupConsent(false), h); e == nil || f.started != 0 || f.transitioned != 0 {
		t.Fatal("guard failure started")
	}
}

func TestFreshReadAdminV6LifecycleLeaseRequiresExactCompletedReceipt4(t *testing.T) {
	setup := &readSetupFixture{}
	if _, e := setupReadObservation(context.Background(), "fixture", freshReadAdminSetupConsent(false), freshReadAdminFixtureHooks(setup)); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"exact", "receipt2", "receipt3", "missing-hardware", "staged", "wrong-consent"} {
		var receipt installReceipt
		json.Unmarshal(setup.raw, &receipt)
		switch kind {
		case "receipt2":
			receipt.Version = 2
		case "receipt3":
			receipt.Version = 3
		case "missing-hardware":
			receipt.ReadSetup.GrantDigests = receipt.ReadSetup.GrantDigests[:11]
		case "staged":
			receipt.Service.Version = 2
		case "wrong-consent":
			receipt.ReadSetup.Consent = readAdminSetupConsent(false)
		}
		raw, _ := json.Marshal(receipt)
		lease := &lifecycleLeaseFixture{raw: raw, layout: receipt.Service.Layout}
		calls := 0
		_, e := withReceiptLease(context.Background(), lease.open, func(owned installReceipt, held receiptStore) (any, error) {
			calls++
			if !lease.held.Load() || held != lease || owned.Version != 4 || !completeReadSetup(owned) || owned.Service.Version != 1 {
				t.Fatal("lifecycle ownership not bound")
			}
			return nil, nil
		})
		wantCalls := 0
		if kind == "exact" {
			wantCalls = 1
		}
		if (e == nil) != (kind == "exact") || calls != wantCalls || lease.held.Load() || lease.closes != 1 {
			t.Fatal("wrong lifecycle admission", kind, e, calls)
		}
	}
}
