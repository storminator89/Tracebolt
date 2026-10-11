package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
		for _, word := range []string{"19 explicit read scopes", "physical chassis serial (Win32_SystemEnclosure)", "BIOS serial metadata", "manufacturer/model", "firmware vendor/version/date", "power/battery", "Users and sessions", "personal", "Provider presence has not been checked", "LocalService", "cached WUA", "service control", "Selected event-message"} {
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
	for _, group := range lanclient.WindowsReadAdminGroupsV12() {
		if !strings.Contains(text, group.Name) || !strings.Contains(text, group.Summary) {
			t.Fatal("group scope omitted")
		}
	}
	for _, word := range []string{"19 read scopes", "physical chassis serial (Win32_SystemEnclosure)", "BIOS serial metadata", "personal", "LocalService", "unverified", "event-message", "cached WUA", "service control", "external-AI", "Scope details"} {
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
		if !reflect.DeepEqual(c, freshReadAdminSetupConsent(false)) && !reflect.DeepEqual(c, historicalReadAdminV7Consent()) && !reflect.DeepEqual(c, historicalReadAdminV8Consent()) && !reflect.DeepEqual(c, historicalReadAdminV9Consent()) && !reflect.DeepEqual(c, historicalReadAdminV10Consent()) && !reflect.DeepEqual(c, historicalReadAdminV11Consent()) {
			return lanclient.WindowsCapabilityConsentResult{}, errLifecycle
		}
		if f.partial {
			return lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: c.Scopes[1 : len(c.Scopes)-1], FailedScope: c.Scopes[len(c.Scopes)-1]}, errLifecycle
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

func TestReadAdminV7FreshProfileReceipt5ExactThirteenGrants(t *testing.T) {
	f := &readSetupFixture{}
	c := historicalReadAdminV7Consent()
	if _, e := setupReadObservation(context.Background(), "fixture", c, freshReadAdminFixtureHooks(f)); e != nil {
		t.Fatal(e)
	}
	if f.record.Version != 5 || !completeReadSetup(f.record) || len(f.record.ReadSetup.GrantDigests) != 13 || f.record.ReadSetup.GrantDigests[12].Scope != "windows-storage-context-v1" || f.started != 1 {
		t.Fatal("missing fresh receipt5 authority")
	}
	if _, e := decodeInstallReceipt(f.raw, f.record.Service.Layout); e != nil {
		t.Fatal(e)
	}
	for _, version := range []int{1, 2, 3, 4} {
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
			t.Fatal("old consent promoted to receipt5")
		}
	}
	for _, kind := range []string{"storage-missing", "storage-misordered", "storage-invalid"} {
		var bad installReceipt
		json.Unmarshal(f.raw, &bad)
		switch kind {
		case "storage-missing":
			bad.ReadSetup.GrantDigests = bad.ReadSetup.GrantDigests[:12]
		case "storage-misordered":
			bad.ReadSetup.GrantDigests[11], bad.ReadSetup.GrantDigests[12] = bad.ReadSetup.GrantDigests[12], bad.ReadSetup.GrantDigests[11]
		case "storage-invalid":
			bad.ReadSetup.GrantDigests[12].SHA256 = ""
		}
		raw, _ := json.Marshal(bad)
		if _, e := decodeInstallReceipt(raw, bad.Service.Layout); e == nil {
			t.Fatal("invalid storage digest admitted", kind)
		}
	}
}

func TestReadAdminV7FreshGrantFailuresAndOriginalSenderGuard(t *testing.T) {
	for _, phase := range []string{"fresh-scopes", "grants-started", "configure", "verify-grants", "grant-digests", "grants-verified", "startup-transition-started"} {
		f := &readSetupFixture{fail: phase}
		if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV7Consent(), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.transitioned != 0 {
			t.Fatal("incomplete authority started", phase, e)
		}
	}
	f := &readSetupFixture{partial: true}
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV7Consent(), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.record.ReadSetup.Phase != "grants-incomplete" || f.record.ReadSetup.Grants.FailedScope != "windows-storage-context-v1" || len(f.record.ReadSetup.Grants.AppliedScopes) != 12 {
		t.Fatal("partial storage failure erased evidence")
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
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV7Consent(), h); e == nil || f.started != 0 || f.transitioned != 0 {
		t.Fatal("guard failure started")
	}
}

func TestFreshReadAdminV7LifecycleLeaseRequiresExactCompletedReceipt5(t *testing.T) {
	setup := &readSetupFixture{}
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV7Consent(), freshReadAdminFixtureHooks(setup)); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"exact", "receipt2", "receipt3", "missing-storage", "staged", "wrong-consent"} {
		var receipt installReceipt
		json.Unmarshal(setup.raw, &receipt)
		switch kind {
		case "receipt2":
			receipt.Version = 2
		case "receipt3":
			receipt.Version = 3
		case "missing-storage":
			receipt.ReadSetup.GrantDigests = receipt.ReadSetup.GrantDigests[:12]
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
			if !lease.held.Load() || held != lease || owned.Version != 5 || !completeReadSetup(owned) || owned.Service.Version != 1 {
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

func TestReadAdminHistoricalV6ReceiptBytesRemainSeparate(t *testing.T) {
	c := lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV6, CollectionProfile: "windows-inventory-v1", Scopes: lanclient.WindowsReadAdminScopesV6(), Acknowledged: true}
	f := &readSetupFixture{}
	h := freshReadAdminFixtureHooks(f)
	h.configure = func(_ string, r lanclient.WindowsCapabilityConsent) (lanclient.WindowsCapabilityConsentResult, error) {
		return lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: r.Scopes[1:]}, nil
	}
	if _, e := setupReadObservation(context.Background(), "fixture", c, h); e != nil || f.record.Version != 4 || len(f.record.ReadSetup.GrantDigests) != 12 || !completeReadSetup(f.record) {
		t.Fatal("historical V6 changed", e)
	}
	if _, e := decodeInstallReceipt(f.raw, f.record.Service.Layout); e != nil {
		t.Fatal(e)
	}
	old := f.record
	old.ReadSetup.Consent = freshReadAdminSetupConsent(false)
	raw, _ := json.Marshal(old)
	if _, e := decodeInstallReceipt(raw, old.Service.Layout); e == nil {
		t.Fatal("old receipt gained storage authority")
	}
}

func historicalReadAdminV7Consent() lanclient.WindowsCapabilityConsent {
	return lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV7, CollectionProfile: "windows-inventory-v1", Scopes: lanclient.WindowsReadAdminScopesV7(), Acknowledged: true}
}

func TestFreshReadAdminV8LifecycleLeaseRequiresExactCompletedReceipt6(t *testing.T) {
	setup := &readSetupFixture{}
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV8Consent(), freshReadAdminFixtureHooks(setup)); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"exact", "receipt2", "receipt3", "missing-security-coverage", "staged", "wrong-consent"} {
		var receipt installReceipt
		json.Unmarshal(setup.raw, &receipt)
		switch kind {
		case "receipt2":
			receipt.Version = 2
		case "receipt3":
			receipt.Version = 3
		case "missing-security-coverage":
			receipt.ReadSetup.GrantDigests = receipt.ReadSetup.GrantDigests[:13]
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
			if !lease.held.Load() || held != lease || owned.Version != 6 || !completeReadSetup(owned) || owned.Service.Version != 1 {
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

func TestReadAdminV8FreshGrantFailuresAndOriginalSenderGuard(t *testing.T) {
	for _, phase := range []string{"fresh-scopes", "grants-started", "configure", "verify-grants", "grant-digests", "grants-verified", "startup-transition-started"} {
		f := &readSetupFixture{fail: phase}
		if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV8Consent(), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.transitioned != 0 {
			t.Fatal("incomplete authority started", phase, e)
		}
	}
	f := &readSetupFixture{partial: true}
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV8Consent(), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.record.ReadSetup.Phase != "grants-incomplete" || f.record.ReadSetup.Grants.FailedScope != "windows-security-coverage-v1" || len(f.record.ReadSetup.Grants.AppliedScopes) != 13 {
		t.Fatal("partial security-coverage failure erased evidence")
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
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV8Consent(), h); e == nil || f.started != 0 || f.transitioned != 0 {
		t.Fatal("guard failure started")
	}
}

func TestReadAdminV8FreshProfileReceipt6ExactFourteenGrants(t *testing.T) {
	f := &readSetupFixture{}
	c := historicalReadAdminV8Consent()
	if _, e := setupReadObservation(context.Background(), "fixture", c, freshReadAdminFixtureHooks(f)); e != nil {
		t.Fatal(e)
	}
	if f.record.Version != 6 || !completeReadSetup(f.record) || len(f.record.ReadSetup.GrantDigests) != 14 || f.record.ReadSetup.GrantDigests[13].Scope != "windows-security-coverage-v1" || f.started != 1 {
		t.Fatal("missing fresh receipt6 authority")
	}
	if _, e := decodeInstallReceipt(f.raw, f.record.Service.Layout); e != nil {
		t.Fatal(e)
	}
	for _, version := range []int{1, 2, 3, 4, 5} {
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
			t.Fatal("old consent promoted to receipt6")
		}
	}
	for _, kind := range []string{"security-coverage-missing", "security-coverage-misordered", "security-coverage-invalid"} {
		var bad installReceipt
		json.Unmarshal(f.raw, &bad)
		switch kind {
		case "security-coverage-missing":
			bad.ReadSetup.GrantDigests = bad.ReadSetup.GrantDigests[:13]
		case "security-coverage-misordered":
			bad.ReadSetup.GrantDigests[12], bad.ReadSetup.GrantDigests[13] = bad.ReadSetup.GrantDigests[13], bad.ReadSetup.GrantDigests[12]
		case "security-coverage-invalid":
			bad.ReadSetup.GrantDigests[13].SHA256 = ""
		}
		raw, _ := json.Marshal(bad)
		if _, e := decodeInstallReceipt(raw, bad.Service.Layout); e == nil {
			t.Fatal("invalid security-coverage digest admitted", kind)
		}
	}
}

func historicalReadAdminV8Consent() lanclient.WindowsCapabilityConsent {
	return lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV8, CollectionProfile: "windows-inventory-v1", Scopes: lanclient.WindowsReadAdminScopesV8(), Acknowledged: true}
}
func TestFreshReadAdminV9LifecycleLeaseRequiresExactCompletedReceipt7(t *testing.T) {
	setup := &readSetupFixture{}
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV9Consent(), freshReadAdminFixtureHooks(setup)); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"exact", "receipt2", "receipt3", "missing-full-processes", "staged", "wrong-consent"} {
		var receipt installReceipt
		json.Unmarshal(setup.raw, &receipt)
		switch kind {
		case "receipt2":
			receipt.Version = 2
		case "receipt3":
			receipt.Version = 3
		case "missing-full-processes":
			receipt.ReadSetup.GrantDigests = receipt.ReadSetup.GrantDigests[:14]
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
			if !lease.held.Load() || held != lease || owned.Version != 7 || !completeReadSetup(owned) || owned.Service.Version != 1 {
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

func TestReadAdminV9FreshGrantFailuresAndOriginalSenderGuard(t *testing.T) {
	for _, phase := range []string{"fresh-scopes", "grants-started", "configure", "verify-grants", "grant-digests", "grants-verified", "startup-transition-started"} {
		f := &readSetupFixture{fail: phase}
		if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV9Consent(), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.transitioned != 0 {
			t.Fatal("incomplete authority started", phase, e)
		}
	}
	f := &readSetupFixture{partial: true}
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV9Consent(), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.record.ReadSetup.Phase != "grants-incomplete" || f.record.ReadSetup.Grants.FailedScope != "windows-complete-processes-v1" || len(f.record.ReadSetup.Grants.AppliedScopes) != 14 {
		t.Fatal("partial full-processes failure erased evidence")
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
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV9Consent(), h); e == nil || f.started != 0 || f.transitioned != 0 {
		t.Fatal("guard failure started")
	}
}

func TestReadAdminV9FreshProfileReceipt7ExactFifteenGrants(t *testing.T) {
	f := &readSetupFixture{}
	c := historicalReadAdminV9Consent()
	if _, e := setupReadObservation(context.Background(), "fixture", c, freshReadAdminFixtureHooks(f)); e != nil {
		t.Fatal(e)
	}
	if f.record.Version != 7 || !completeReadSetup(f.record) || len(f.record.ReadSetup.GrantDigests) != 15 || f.record.ReadSetup.GrantDigests[14].Scope != "windows-complete-processes-v1" || f.started != 1 {
		t.Fatal("missing fresh receipt7 authority")
	}
	if _, e := decodeInstallReceipt(f.raw, f.record.Service.Layout); e != nil {
		t.Fatal(e)
	}
	for _, version := range []int{1, 2, 3, 4, 5, 6} {
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
			t.Fatal("old consent promoted to receipt7")
		}
	}
	for _, kind := range []string{"full-processes-missing", "full-processes-misordered", "full-processes-invalid"} {
		var bad installReceipt
		json.Unmarshal(f.raw, &bad)
		switch kind {
		case "full-processes-missing":
			bad.ReadSetup.GrantDigests = bad.ReadSetup.GrantDigests[:14]
		case "full-processes-misordered":
			bad.ReadSetup.GrantDigests[13], bad.ReadSetup.GrantDigests[14] = bad.ReadSetup.GrantDigests[14], bad.ReadSetup.GrantDigests[13]
		case "full-processes-invalid":
			bad.ReadSetup.GrantDigests[14].SHA256 = ""
		}
		raw, _ := json.Marshal(bad)
		if _, e := decodeInstallReceipt(raw, bad.Service.Layout); e == nil {
			t.Fatal("invalid full-processes digest admitted", kind)
		}
	}
}

func historicalReadAdminV9Consent() lanclient.WindowsCapabilityConsent {
	return lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV9, CollectionProfile: "windows-inventory-v1", Scopes: lanclient.WindowsReadAdminScopesV9(), Acknowledged: true}
}
func TestFreshReadAdminV10LifecycleLeaseRequiresExactCompletedReceipt8(t *testing.T) {
	setup := &readSetupFixture{}
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV10Consent(), freshReadAdminFixtureHooks(setup)); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"exact", "receipt2", "receipt3", "missing-network-context", "staged", "wrong-consent"} {
		var receipt installReceipt
		json.Unmarshal(setup.raw, &receipt)
		switch kind {
		case "receipt2":
			receipt.Version = 2
		case "receipt3":
			receipt.Version = 3
		case "missing-network-context":
			receipt.ReadSetup.GrantDigests = receipt.ReadSetup.GrantDigests[:15]
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
			if !lease.held.Load() || held != lease || owned.Version != 8 || !completeReadSetup(owned) || owned.Service.Version != 1 {
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

func TestReadAdminV10FreshGrantFailuresAndOriginalSenderGuard(t *testing.T) {
	for _, phase := range []string{"fresh-scopes", "grants-started", "configure", "verify-grants", "grant-digests", "grants-verified", "startup-transition-started"} {
		f := &readSetupFixture{fail: phase}
		if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV10Consent(), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.transitioned != 0 {
			t.Fatal("incomplete authority started", phase, e)
		}
	}
	f := &readSetupFixture{partial: true}
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV10Consent(), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.record.ReadSetup.Phase != "grants-incomplete" || f.record.ReadSetup.Grants.FailedScope != "windows-network-context-v1" || len(f.record.ReadSetup.Grants.AppliedScopes) != 15 {
		t.Fatal("partial network-context failure erased evidence")
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
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV10Consent(), h); e == nil || f.started != 0 || f.transitioned != 0 {
		t.Fatal("guard failure started")
	}
}

func TestReadAdminV10FreshProfileReceipt8ExactSixteenGrants(t *testing.T) {
	f := &readSetupFixture{}
	c := historicalReadAdminV10Consent()
	if _, e := setupReadObservation(context.Background(), "fixture", c, freshReadAdminFixtureHooks(f)); e != nil {
		t.Fatal(e)
	}
	if f.record.Version != 8 || !completeReadSetup(f.record) || len(f.record.ReadSetup.GrantDigests) != 16 || f.record.ReadSetup.GrantDigests[15].Scope != "windows-network-context-v1" || f.started != 1 {
		t.Fatal("missing fresh receipt8 authority")
	}
	if _, e := decodeInstallReceipt(f.raw, f.record.Service.Layout); e != nil {
		t.Fatal(e)
	}
	for _, version := range []int{1, 2, 3, 4, 5, 6, 7} {
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
			t.Fatal("old consent promoted to receipt8")
		}
	}
	for _, kind := range []string{"network-context-missing", "network-context-misordered", "network-context-invalid"} {
		var bad installReceipt
		json.Unmarshal(f.raw, &bad)
		switch kind {
		case "network-context-missing":
			bad.ReadSetup.GrantDigests = bad.ReadSetup.GrantDigests[:15]
		case "network-context-misordered":
			bad.ReadSetup.GrantDigests[14], bad.ReadSetup.GrantDigests[15] = bad.ReadSetup.GrantDigests[15], bad.ReadSetup.GrantDigests[14]
		case "network-context-invalid":
			bad.ReadSetup.GrantDigests[15].SHA256 = ""
		}
		raw, _ := json.Marshal(bad)
		if _, e := decodeInstallReceipt(raw, bad.Service.Layout); e == nil {
			t.Fatal("invalid network-context digest admitted", kind)
		}
	}
}

func historicalReadAdminV10Consent() lanclient.WindowsCapabilityConsent {
	return lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV10, CollectionProfile: "windows-inventory-v1", Scopes: lanclient.WindowsReadAdminScopesV10(), Acknowledged: true}
}

func TestFreshReadAdminV11LifecycleLeaseRequiresExactCompletedReceipt9(t *testing.T) {
	setup := &readSetupFixture{}
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV11Consent(), freshReadAdminFixtureHooks(setup)); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"exact", "receipt2", "receipt3", "missing-resource-context", "staged", "wrong-consent"} {
		var receipt installReceipt
		json.Unmarshal(setup.raw, &receipt)
		switch kind {
		case "receipt2":
			receipt.Version = 2
		case "receipt3":
			receipt.Version = 3
		case "missing-resource-context":
			receipt.ReadSetup.GrantDigests = receipt.ReadSetup.GrantDigests[:16]
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
			if !lease.held.Load() || held != lease || owned.Version != 9 || !completeReadSetup(owned) || owned.Service.Version != 1 {
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

func TestReadAdminV11FreshGrantFailuresAndOriginalSenderGuard(t *testing.T) {
	for _, phase := range []string{"fresh-scopes", "grants-started", "configure", "verify-grants", "grant-digests", "grants-verified", "startup-transition-started"} {
		f := &readSetupFixture{fail: phase}
		if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV11Consent(), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.transitioned != 0 {
			t.Fatal("incomplete authority started", phase, e)
		}
	}
	f := &readSetupFixture{partial: true}
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV11Consent(), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.record.ReadSetup.Phase != "grants-incomplete" || f.record.ReadSetup.Grants.FailedScope != "windows-resource-context-v1" || len(f.record.ReadSetup.Grants.AppliedScopes) != 16 {
		t.Fatal("partial resource-context failure erased evidence")
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
	if _, e := setupReadObservation(context.Background(), "fixture", historicalReadAdminV11Consent(), h); e == nil || f.started != 0 || f.transitioned != 0 {
		t.Fatal("guard failure started")
	}
}

func TestReadAdminV11FreshProfileReceipt9ExactSeventeenGrants(t *testing.T) {
	f := &readSetupFixture{}
	c := historicalReadAdminV11Consent()
	if _, e := setupReadObservation(context.Background(), "fixture", c, freshReadAdminFixtureHooks(f)); e != nil {
		t.Fatal(e)
	}
	if f.record.Version != 9 || !completeReadSetup(f.record) || len(f.record.ReadSetup.GrantDigests) != 17 || f.record.ReadSetup.GrantDigests[16].Scope != "windows-resource-context-v1" || f.started != 1 {
		t.Fatal("missing fresh receipt9 authority")
	}
	if _, e := decodeInstallReceipt(f.raw, f.record.Service.Layout); e != nil {
		t.Fatal(e)
	}
	for _, version := range []int{1, 2, 3, 4, 5, 6, 7, 8} {
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
			t.Fatal("old consent promoted to receipt9")
		}
	}
	for _, kind := range []string{"resource-context-missing", "resource-context-misordered", "resource-context-invalid"} {
		var bad installReceipt
		json.Unmarshal(f.raw, &bad)
		switch kind {
		case "resource-context-missing":
			bad.ReadSetup.GrantDigests = bad.ReadSetup.GrantDigests[:16]
		case "resource-context-misordered":
			bad.ReadSetup.GrantDigests[14], bad.ReadSetup.GrantDigests[16] = bad.ReadSetup.GrantDigests[16], bad.ReadSetup.GrantDigests[14]
		case "resource-context-invalid":
			bad.ReadSetup.GrantDigests[16].SHA256 = ""
		}
		raw, _ := json.Marshal(bad)
		if _, e := decodeInstallReceipt(raw, bad.Service.Layout); e == nil {
			t.Fatal("invalid resource-context digest admitted", kind)
		}
	}
}

func TestReadAdminResourceContextDisclosureIncludesExactSemanticsAndHTTPRisk(t *testing.T) {
	for _, text := range []string{setupWizardReadAdminSummary(), setupWizardReadAdminDisclosure(false), setupWizardReadAdminDisclosure(true), setupWizardReadAdminHTTPRiskSummary} {
		for _, field := range []string{"CPU model", "source-labeled processor counts", "installed SMBIOS RAM", "OS-usable RAM", "commit current/limit", "remaining capacity", "aggregate pagefile allocated/in-use"} {
			if !strings.Contains(text, field) {
				t.Fatal("missing explicit resource disclosure", field)
			}
		}
	}
	for _, field := range []string{"Pagefile names and paths are excluded", "not paging I/O, thrashing or a health verdict", "CPU utilization sampler is unchanged"} {
		if !strings.Contains(setupWizardReadAdminDisclosure(false), field) {
			t.Fatal("missing resource limit", field)
		}
	}
	c := freshReadAdminSetupConsent(false)
	if c.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV12 || len(c.Scopes) != 19 || c.Scopes[17] != "windows-resource-context-v1" || c.Scopes[18] != "windows-storage-io-v1" || c.InsecureHTTPAcknowledged {
		t.Fatal("wrong fresh resource authority")
	}
}

// Fixed fixture hashes pin every pre-storage-I/O coordinator receipt.
// No historical receipt may gain the nineteenth scope or be rewritten as v10.
func TestReadAdminHistoricalReceiptBytesStayExactV2ThroughV9(t *testing.T) {
	for _, tc := range []struct {
		consent lanclient.WindowsCapabilityConsent
		version int
		sha256  string
	}{
		{readSetupConsentFixture(), 2, "95e5d6bb9af5a4df94dcd671a8ffa7ded4be21f48a9bd2d92c48026b6e3ca5a2"},
		{readAdminSetupConsent(false), 3, "a824a9379cf631d49d7f6cfef4fcf43f05b5d3d26cd20da35d186f7f7f88bb31"},
		{lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV6, CollectionProfile: "windows-inventory-v1", Scopes: lanclient.WindowsReadAdminScopesV6(), Acknowledged: true}, 4, "4c1b97961d450f641b130119f4476c1c1ddb4a6ef2fe06f8bbd7350d919fe475"},
		{historicalReadAdminV7Consent(), 5, "85c7eb8c411c89bb53dbb6a6309e481e5132091999fbd4b78853985c7ce3340e"},
		{historicalReadAdminV8Consent(), 6, "756750cb28c0be9f9e7b5fadfa0c11ca388d02d45bb252208563df15a3e14de1"},
		{historicalReadAdminV9Consent(), 7, "c51c37338f521ccaa28321676a7a2dfccd66dbed4d7ee9cb45c3e7da2377b694"},
		{historicalReadAdminV11Consent(), 9, "5ffbe399a98f3cd72f00e578effefffd21fb1095f8d2193d3d5c1f04fdf16394"},
		{historicalReadAdminV10Consent(), 8, "783593aa34bc65731972e80490c5e496f68f841db8fb2ffa0766f600f0d84472"},
	} {
		f := &readSetupFixture{}
		h := f.hooks()
		h.configure = func(_ string, c lanclient.WindowsCapabilityConsent) (lanclient.WindowsCapabilityConsentResult, error) {
			return lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: c.Scopes[1:]}, nil
		}
		h.grantDigests = func(_ string, c lanclient.WindowsCapabilityConsent) ([]lanclient.WindowsCapabilityGrantDigest, error) {
			result := []lanclient.WindowsCapabilityGrantDigest{}
			for _, scope := range c.Scopes[1:] {
				result = append(result, lanclient.WindowsCapabilityGrantDigest{Scope: scope, SHA256: strings.Repeat("d", 64)})
			}
			return result, nil
		}
		if _, err := setupReadObservation(context.Background(), "fixture", tc.consent, h); err != nil {
			t.Fatal(tc.version, err)
		}
		digest := sha256.Sum256(f.raw)
		if f.record.Version != tc.version || hex.EncodeToString(digest[:]) != tc.sha256 {
			t.Fatal("historical receipt changed", tc.version)
		}
		if _, err := decodeInstallReceipt(f.raw, f.record.Service.Layout); err != nil {
			t.Fatal("old receipt no longer accepted", tc.version, err)
		}
	}
}

func historicalReadAdminV11Consent() lanclient.WindowsCapabilityConsent {
	return lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV11, CollectionProfile: "windows-inventory-v1", Scopes: lanclient.WindowsReadAdminScopesV11(), Acknowledged: true}
}
func TestFreshReadAdminV12LifecycleLeaseRequiresExactCompletedReceipt10(t *testing.T) {
	setup := &readSetupFixture{}
	if _, e := setupReadObservation(context.Background(), "fixture", freshReadAdminSetupConsent(false), freshReadAdminFixtureHooks(setup)); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"exact", "receipt2", "receipt3", "missing-storage-io", "staged", "wrong-consent"} {
		var receipt installReceipt
		json.Unmarshal(setup.raw, &receipt)
		switch kind {
		case "receipt2":
			receipt.Version = 2
		case "receipt3":
			receipt.Version = 3
		case "missing-storage-io":
			receipt.ReadSetup.GrantDigests = receipt.ReadSetup.GrantDigests[:17]
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
			if !lease.held.Load() || held != lease || owned.Version != 10 || !completeReadSetup(owned) || owned.Service.Version != 1 {
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

func TestReadAdminV12FreshGrantFailuresAndOriginalSenderGuard(t *testing.T) {
	for _, phase := range []string{"fresh-scopes", "grants-started", "configure", "verify-grants", "grant-digests", "grants-verified", "startup-transition-started"} {
		f := &readSetupFixture{fail: phase}
		if _, e := setupReadObservation(context.Background(), "fixture", freshReadAdminSetupConsent(false), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.transitioned != 0 {
			t.Fatal("incomplete authority started", phase, e)
		}
	}
	f := &readSetupFixture{partial: true}
	if _, e := setupReadObservation(context.Background(), "fixture", freshReadAdminSetupConsent(false), freshReadAdminFixtureHooks(f)); e == nil || f.started != 0 || f.record.ReadSetup.Phase != "grants-incomplete" || f.record.ReadSetup.Grants.FailedScope != "windows-storage-io-v1" || len(f.record.ReadSetup.Grants.AppliedScopes) != 17 {
		t.Fatal("partial storage-io failure erased evidence")
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

func TestReadAdminV12FreshProfileReceipt10ExactEighteenGrants(t *testing.T) {
	f := &readSetupFixture{}
	c := freshReadAdminSetupConsent(false)
	if _, e := setupReadObservation(context.Background(), "fixture", c, freshReadAdminFixtureHooks(f)); e != nil {
		t.Fatal(e)
	}
	if f.record.Version != 10 || !completeReadSetup(f.record) || len(f.record.ReadSetup.GrantDigests) != 18 || f.record.ReadSetup.GrantDigests[17].Scope != "windows-storage-io-v1" || f.started != 1 {
		t.Fatal("missing fresh receipt10 authority")
	}
	if _, e := decodeInstallReceipt(f.raw, f.record.Service.Layout); e != nil {
		t.Fatal(e)
	}
	for _, version := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9} {
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
			t.Fatal("old consent promoted to receipt10")
		}
	}
	for _, kind := range []string{"storage-io-missing", "storage-io-misordered", "storage-io-invalid"} {
		var bad installReceipt
		json.Unmarshal(f.raw, &bad)
		switch kind {
		case "storage-io-missing":
			bad.ReadSetup.GrantDigests = bad.ReadSetup.GrantDigests[:17]
		case "storage-io-misordered":
			bad.ReadSetup.GrantDigests[14], bad.ReadSetup.GrantDigests[17] = bad.ReadSetup.GrantDigests[17], bad.ReadSetup.GrantDigests[14]
		case "storage-io-invalid":
			bad.ReadSetup.GrantDigests[17].SHA256 = ""
		}
		raw, _ := json.Marshal(bad)
		if _, e := decodeInstallReceipt(raw, bad.Service.Layout); e == nil {
			t.Fatal("invalid storage-io digest admitted", kind)
		}
	}
}

func TestReadAdminStorageIODisclosureIncludesExactSemanticsAndHTTPRisk(t *testing.T) {
	for _, text := range []string{setupWizardReadAdminSummary(), setupWizardReadAdminDisclosure(false), setupWizardReadAdminDisclosure(true), setupWizardReadAdminHTTPRiskSummary} {
		for _, field := range []string{"PerfDisk (_Total)", "read/write throughput", "operations per second", "latency", "queue lengths", "sample window"} {
			if !strings.Contains(text, field) {
				t.Fatal("missing explicit storage I/O disclosure", field)
			}
		}
	}
	for _, field := range []string{"Eight fixed local PDH", "idle latency is unavailable", "No per-disk completeness", "joins to drives/volumes/provider disks"} {
		if !strings.Contains(setupWizardReadAdminDisclosure(false), field) {
			t.Fatal("missing storage I/O limit", field)
		}
	}
	c := freshReadAdminSetupConsent(false)
	if c.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV12 || len(c.Scopes) != 19 || c.Scopes[18] != "windows-storage-io-v1" || c.InsecureHTTPAcknowledged {
		t.Fatal("wrong fresh storage I/O authority")
	}
}
