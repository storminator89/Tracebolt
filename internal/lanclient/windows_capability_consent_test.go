package lanclient

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsvolumes"
	"os"
	"reflect"
	"testing"
)

func capabilityFixture(scopes ...string) WindowsCapabilityConsent {
	return WindowsCapabilityConsent{SchemaVersion: WindowsCapabilityConsentVersion, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: scopes, Acknowledged: true}
}
func TestCombinedWindowsCapabilityConsentExactContract(t *testing.T) {
	metadata := enrollmentcrypto.CollectionProfileWindowsInventory
	good := capabilityFixture(metadata, windowseventhealth.Scope, windowsvolumes.Scope)
	raw, _ := json.Marshal(good)
	if _, err := DecodeWindowsCapabilityConsent(raw); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*WindowsCapabilityConsent){
		func(r *WindowsCapabilityConsent) { r.SchemaVersion = "future" },
		func(r *WindowsCapabilityConsent) { r.CollectionProfile = "basic-readonly-v1" },
		func(r *WindowsCapabilityConsent) { r.Acknowledged = false },
		func(r *WindowsCapabilityConsent) { r.Scopes = nil },
		func(r *WindowsCapabilityConsent) { r.Scopes = []string{windowsvolumes.Scope} },
		func(r *WindowsCapabilityConsent) { r.Scopes = []string{metadata, "future"} },
		func(r *WindowsCapabilityConsent) { r.Scopes = []string{metadata, metadata} },
	} {
		bad := good
		mutate(&bad)
		calls := 0
		if _, err := applyWindowsCapabilities(bad, func(string) error { calls++; return nil }); err == nil || calls != 0 {
			t.Fatal("invalid request applied")
		}
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), ' '), append(raw[:len(raw)-1:len(raw)-1], []byte(`,"acknowledged":true}`)...), append(raw[:len(raw)-1:len(raw)-1], []byte(`,"unknown":true}`)...)} {
		if _, err := DecodeWindowsCapabilityConsent(bad); err == nil {
			t.Fatal("noncanonical request accepted")
		}
	}
}
func TestCombinedWindowsCapabilitiesPreserveSelectionAndPartialResult(t *testing.T) {
	metadata := enrollmentcrypto.CollectionProfileWindowsInventory
	for _, selected := range [][]string{{metadata}, {metadata, windowsvolumes.Scope}, {windowseventhealth.Scope, metadata}, {metadata, windowsvolumes.Scope, windowseventhealth.Scope}} {
		var called []string
		r, err := applyWindowsCapabilities(capabilityFixture(selected...), func(scope string) error { called = append(called, scope); return nil })
		var want []string
		for _, s := range selected {
			if s != metadata {
				want = append(want, s)
			}
		}
		if err != nil || !r.MetadataScopeVerified || !reflect.DeepEqual(called, want) || len(r.AppliedScopes) != len(want) {
			t.Fatal("selection changed", r, called, err)
		}
	}
	r, err := applyWindowsCapabilities(capabilityFixture(metadata, windowseventhealth.Scope, windowsvolumes.Scope), func(scope string) error {
		if scope == windowsvolumes.Scope {
			return ErrState
		}
		return nil
	})
	if err == nil || r.FailedScope != windowsvolumes.Scope || !reflect.DeepEqual(r.AppliedScopes, []string{windowseventhealth.Scope}) {
		t.Fatal("partial commit hidden", r, err)
	}
}

func TestCombinedWindowsCapabilityV2ExactScopeCombinations(t *testing.T) {
	metadata := enrollmentcrypto.CollectionProfileWindowsInventory
	optional := []string{windowseventhealth.Scope, windowsvolumes.Scope, windowsprocessmetrics.Scope}
	for mask := 0; mask < 8; mask++ {
		scopes := []string{metadata}
		for i, scope := range optional {
			if mask&(1<<i) != 0 {
				scopes = append(scopes, scope)
			}
		}
		r := capabilityFixture(scopes...)
		r.SchemaVersion = WindowsCapabilityConsentVersionV2
		raw, _ := json.Marshal(r)
		if _, err := DecodeWindowsCapabilityConsent(raw); err != nil {
			t.Fatal(mask, err)
		}
		var called []string
		result, err := applyWindowsCapabilities(r, func(scope string) error { called = append(called, scope); return nil })
		if err != nil || !result.MetadataScopeVerified || len(called) != len(scopes)-1 {
			t.Fatal(mask, result, err)
		}
		for i, scope := range called {
			if scope != scopes[i+1] {
				t.Fatal("scope order changed")
			}
		}
		if mask&4 != 0 {
			r.SchemaVersion = WindowsCapabilityConsentVersion
			if r.Validate() == nil {
				t.Fatal("v1 granted new scope")
			}
		}
	}
	for _, scopes := range [][]string{{windowsprocessmetrics.Scope}, {metadata, windowsprocessmetrics.Scope, windowsprocessmetrics.Scope}, {metadata, "unknown"}} {
		r := capabilityFixture(scopes...)
		r.SchemaVersion = WindowsCapabilityConsentVersionV2
		if _, err := applyWindowsCapabilities(r, func(string) error { t.Fatal("invalid selection applied"); return nil }); err == nil {
			t.Fatal("invalid v2 accepted")
		}
	}
	r := capabilityFixture(metadata, windowsvolumes.Scope, windowsprocessmetrics.Scope, windowseventhealth.Scope)
	r.SchemaVersion = WindowsCapabilityConsentVersionV2
	result, err := applyWindowsCapabilities(r, func(scope string) error {
		if scope == windowsprocessmetrics.Scope {
			return ErrState
		}
		return nil
	})
	if err == nil || result.FailedScope != windowsprocessmetrics.Scope || !reflect.DeepEqual(result.AppliedScopes, []string{windowsvolumes.Scope}) {
		t.Fatal("partial result lost", result, err)
	}
}

func TestCombinedWindowsCapabilityV3ExactScopeCombinations(t *testing.T) {
	metadata := enrollmentcrypto.CollectionProfileWindowsInventory
	optional := []string{windowseventhealth.Scope, windowsvolumes.Scope, windowsprocessmetrics.Scope, windowsnetwork.Scope}
	for mask := 0; mask < 16; mask++ {
		for _, http := range []bool{false, true} {
			scopes := []string{metadata}
			for i, scope := range optional {
				if mask&(1<<i) != 0 {
					scopes = append(scopes, scope)
				}
			}
			r := capabilityFixture(scopes...)
			r.SchemaVersion = WindowsCapabilityConsentVersionV3
			r.InsecureHTTPAcknowledged = http
			raw, _ := json.Marshal(r)
			decoded, err := DecodeWindowsCapabilityConsent(raw)
			if err != nil || !reflect.DeepEqual(decoded, r) {
				t.Fatal(mask, http, "v3 request changed", err)
			}
			called := []string{}
			result, err := applyWindowsCapabilities(decoded, func(scope string) error { called = append(called, scope); return nil })
			if err != nil || !result.MetadataScopeVerified || !reflect.DeepEqual(called, scopes[1:]) || !reflect.DeepEqual(result.AppliedScopes, called) || result.FailedScope != "" {
				t.Fatal(mask, http, "unselected scope applied or selected scope omitted", result, called, err)
			}
			if mask&8 != 0 {
				for _, older := range []string{WindowsCapabilityConsentVersion, WindowsCapabilityConsentVersionV2} {
					r.SchemaVersion = older
					if _, err := applyWindowsCapabilities(r, func(string) error { t.Fatal("older approval granted network"); return nil }); err == nil {
						t.Fatal("older scope set expanded", older)
					}
				}
			}
		}
	}
}

func TestCombinedWindowsCapabilityV3StrictAndPartialFailures(t *testing.T) {
	metadata := enrollmentcrypto.CollectionProfileWindowsInventory
	good := capabilityFixture(metadata, windowsvolumes.Scope, windowsnetwork.Scope, windowsprocessmetrics.Scope, windowseventhealth.Scope)
	good.SchemaVersion = WindowsCapabilityConsentVersionV3
	for _, scopes := range [][]string{nil, {windowsnetwork.Scope}, {metadata, windowsnetwork.Scope, windowsnetwork.Scope}, {metadata, "unknown"}} {
		bad := good
		bad.Scopes = scopes
		if _, err := applyWindowsCapabilities(bad, func(string) error { t.Fatal("invalid v3 touched grant"); return nil }); err == nil {
			t.Fatal("invalid v3 accepted")
		}
	}
	for _, mutate := range []func(*WindowsCapabilityConsent){
		func(r *WindowsCapabilityConsent) { r.SchemaVersion = "tracebolt.windows-capability-consent.v999" },
		func(r *WindowsCapabilityConsent) { r.Acknowledged = false },
		func(r *WindowsCapabilityConsent) { r.CollectionProfile = enrollmentcrypto.CollectionProfile },
	} {
		bad := good
		mutate(&bad)
		if _, err := applyWindowsCapabilities(bad, func(string) error { t.Fatal("invalid v3 touched grant"); return nil }); err == nil {
			t.Fatal("invalid v3 accepted")
		}
	}
	raw, _ := json.Marshal(good)
	for _, bad := range [][]byte{append(append([]byte{}, raw...), ' '), append(raw[:len(raw)-1:len(raw)-1], []byte(`,"acknowledged":true}`)...), append(raw[:len(raw)-1:len(raw)-1], []byte(`,"network":true}`)...)} {
		if _, err := DecodeWindowsCapabilityConsent(bad); err == nil {
			t.Fatal("noncanonical v3 accepted")
		}
	}
	for failed := 1; failed < len(good.Scopes); failed++ {
		called := []string{}
		result, err := applyWindowsCapabilities(good, func(scope string) error {
			called = append(called, scope)
			if scope == good.Scopes[failed] {
				return ErrState
			}
			return nil
		})
		if err != ErrState || !result.MetadataScopeVerified || result.FailedScope != good.Scopes[failed] || !reflect.DeepEqual(result.AppliedScopes, good.Scopes[1:failed]) || !reflect.DeepEqual(called, good.Scopes[1:failed+1]) {
			t.Fatal("partial result lost or later scope touched", result, called, err)
		}
	}
}

type capabilityPresenceFixture struct{ closed bool }

func (s *capabilityPresenceFixture) Close() error { s.closed = true; return nil }
func TestFreshWindowsCapabilityScopePreflightOnlyAcceptsMissingRoots(t *testing.T) {
	root := `C:\ProgramData\Tracebolt\windows-agent`
	sid := "S-1-5-80-1-2-3-4-5"
	want := []string{root + "-event-metadata", root + "-visible-volumes", root + "-process-metrics", root + "-network"}
	var got []string
	absent := func(path string, o windowsstate.Options) (capabilityInspectionStore, error) {
		got = append(got, path)
		if o.Create || o.RuntimeSID != sid || !reflect.DeepEqual(o.Names, []string{"consent.json"}) {
			t.Fatal("preflight creation/schema mismatch")
		}
		return nil, os.ErrNotExist
	}
	if err := windowsCapabilityScopesAbsent(root, sid, absent); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("fresh scope paths mismatch", err, got)
	}
	for _, existing := range []bool{false, true} {
		calls := 0
		store := &capabilityPresenceFixture{}
		err := windowsCapabilityScopesAbsent(root, sid, func(string, windowsstate.Options) (capabilityInspectionStore, error) {
			calls++
			if existing {
				return store, nil
			}
			return nil, os.ErrPermission
		})
		if err == nil || calls != 1 || store.closed != existing {
			t.Fatal("unknown/existing state adopted")
		}
	}
}

func TestWindowsCapabilityGrantDigestDetectsReplacementWithoutCollection(t *testing.T) {
	r := capabilityFixture(enrollmentcrypto.CollectionProfileWindowsInventory, windowsvolumes.Scope)
	grant := windowsvolumes.Consent{SchemaVersion: windowsvolumes.ConsentVersion, Scope: windowsvolumes.Scope, SenderBinding: "fixture-binding", GrantID: "first", Enabled: true}
	read := func(scope string) (any, bool) {
		if scope != windowsvolumes.Scope {
			t.Fatal("unexpected scope")
		}
		return grant, true
	}
	first, err := windowsCapabilityGrantDigests(r, read)
	if err != nil || len(first) != 1 || first[0].Scope != windowsvolumes.Scope || len(first[0].SHA256) != 64 {
		t.Fatal("missing digest", err)
	}
	again, err := windowsCapabilityGrantDigests(r, read)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("unstable canonical digest")
	}
	grant.GrantID = "replacement"
	changed, err := windowsCapabilityGrantDigests(r, read)
	if err != nil || reflect.DeepEqual(first, changed) {
		t.Fatal("grant replacement undetected")
	}
	if got, err := windowsCapabilityGrantDigests(r, func(string) (any, bool) { return grant, false }); err == nil || got != nil {
		t.Fatal("denied grant digested as success")
	}
}
