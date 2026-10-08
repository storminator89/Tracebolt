package lanclient

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsvolumes"
	"reflect"
	"testing"
)

func TestWindowsServiceStartupCapabilityV4ExplicitSelectionsAndOlderScopeIsolation(t *testing.T) {
	optional := []string{windowseventhealth.Scope, windowsvolumes.Scope, windowsprocessmetrics.Scope, windowsnetwork.Scope, windowsmanaged.ServiceStartupScope}
	for bits := 0; bits < 32; bits++ {
		for _, http := range []bool{false, true} {
			r := capabilityFixture(enrollmentcrypto.CollectionProfileWindowsInventory)
			r.SchemaVersion = WindowsCapabilityConsentVersionV4
			r.InsecureHTTPAcknowledged = http
			for i, scope := range optional {
				if bits&(1<<i) != 0 {
					r.Scopes = append(r.Scopes, scope)
				}
			}
			raw, _ := json.Marshal(r)
			got, e := DecodeWindowsCapabilityConsent(raw)
			if e != nil || !reflect.DeepEqual(got, r) {
				t.Fatal(bits, http, e)
			}
			called := []string{}
			result, e := applyWindowsCapabilities(got, func(scope string) error { called = append(called, scope); return nil })
			if e != nil || !result.MetadataScopeVerified || !reflect.DeepEqual(called, r.Scopes[1:]) || !reflect.DeepEqual(result.AppliedScopes, called) {
				t.Fatal("selection changed", bits, http, result, e)
			}
			if bits&16 != 0 {
				for _, older := range []string{WindowsCapabilityConsentVersion, WindowsCapabilityConsentVersionV2, WindowsCapabilityConsentVersionV3} {
					r.SchemaVersion = older
					if _, e := applyWindowsCapabilities(r, func(string) error { t.Fatal("older approval granted startup"); return nil }); e == nil {
						t.Fatal("older scope set expanded")
					}
				}
			}
		}
	}
	r := capabilityFixture(enrollmentcrypto.CollectionProfileWindowsInventory, windowsnetwork.Scope, windowsmanaged.ServiceStartupScope, windowsvolumes.Scope)
	r.SchemaVersion = WindowsCapabilityConsentVersionV4
	result, e := applyWindowsCapabilities(r, func(scope string) error {
		if scope == windowsmanaged.ServiceStartupScope {
			return ErrState
		}
		return nil
	})
	if e != ErrState || result.FailedScope != windowsmanaged.ServiceStartupScope || !reflect.DeepEqual(result.AppliedScopes, []string{windowsnetwork.Scope}) {
		t.Fatal("partial write not reported")
	}
	for _, scopes := range [][]string{{windowsmanaged.ServiceStartupScope}, {enrollmentcrypto.CollectionProfileWindowsInventory, windowsmanaged.ServiceStartupScope, windowsmanaged.ServiceStartupScope}, {enrollmentcrypto.CollectionProfileWindowsInventory, "future"}} {
		r.Scopes = scopes
		if _, e := applyWindowsCapabilities(r, func(string) error { t.Fatal("invalid request wrote grant"); return nil }); e == nil {
			t.Fatal("invalid selection accepted")
		}
	}
}
