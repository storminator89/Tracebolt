package lanclient

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsvolumes"
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
