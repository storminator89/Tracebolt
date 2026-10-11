package lanclient

import (
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsstate"
	"os"
	"reflect"
	"strings"
	"testing"
)

func readAdminFixture() WindowsCapabilityConsent {
	return WindowsCapabilityConsent{SchemaVersion: WindowsCapabilityConsentVersionV5, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: WindowsReadAdminScopes(), Acknowledged: true}
}

func TestWindowsReadAdminRequiresExactNewConsent(t *testing.T) {
	c := readAdminFixture()
	raw, _ := json.Marshal(c)
	got, e := DecodeWindowsCapabilityConsent(raw)
	if e != nil || !reflect.DeepEqual(got, c) || len(c.Scopes) != 12 {
		t.Fatal("new exact profile rejected", e)
	}
	for _, version := range []string{WindowsCapabilityConsentVersion, WindowsCapabilityConsentVersionV2, WindowsCapabilityConsentVersionV3, WindowsCapabilityConsentVersionV4} {
		old := c
		old.SchemaVersion = version
		if old.Validate() == nil {
			t.Fatal("old receipt promoted", version)
		}
	}
	for _, mutate := range []func(*WindowsCapabilityConsent){
		func(c *WindowsCapabilityConsent) { c.Acknowledged = false },
		func(c *WindowsCapabilityConsent) { c.Scopes = c.Scopes[:11] },
		func(c *WindowsCapabilityConsent) { c.Scopes[1], c.Scopes[2] = c.Scopes[2], c.Scopes[1] },
		func(c *WindowsCapabilityConsent) { c.Scopes[11] = "windows-selected-event-content-v1" },
		func(c *WindowsCapabilityConsent) { c.Scopes = append(c.Scopes, "service-control") },
	} {
		bad := readAdminFixture()
		mutate(&bad)
		calls := 0
		if _, e := applyWindowsCapabilities(bad, func(string) error { calls++; return nil }); e == nil || calls != 0 {
			t.Fatal("bad profile reached writes")
		}
	}
	if _, e := ConfigureWindowsCapabilities("unused", c); e == nil {
		t.Fatal("unguarded v5 configuration admitted")
	}
	if _, e := ConfigureWindowsReadAdminCapabilities("unused", c, nil); e == nil {
		t.Fatal("missing guard admitted")
	}
	scopes := WindowsReadAdminScopes()
	scopes[0] = "changed"
	if WindowsReadAdminScopes()[0] == "changed" {
		t.Fatal("shared mutable scope slice")
	}
}
func TestWindowsReadAdminEveryPartialScopeRetainsExactOutcome(t *testing.T) {
	c := readAdminFixture()
	for fail := 1; fail < len(c.Scopes); fail++ {
		calls := []string{}
		result, e := applyWindowsCapabilities(c, func(scope string) error {
			calls = append(calls, scope)
			if scope == c.Scopes[fail] {
				return ErrState
			}
			return nil
		})
		if e == nil || result.FailedScope != c.Scopes[fail] || !reflect.DeepEqual(result.AppliedScopes, c.Scopes[1:fail]) || !reflect.DeepEqual(calls, c.Scopes[1:fail+1]) {
			t.Fatal(fail, result, calls)
		}
	}
}
func TestWindowsReadAdminFreshRootsNeverAdoptExistingOrUnknown(t *testing.T) {
	paths := []string{}
	if e := windowsReadAdminScopesAbsent("root", "sid", func(p string, o windowsstate.Options) (capabilityInspectionStore, error) {
		if o.Create {
			t.Fatal("absence inspection created state")
		}
		paths = append(paths, p)
		return nil, os.ErrNotExist
	}); e != nil || len(paths) != 11 {
		t.Fatal("not all roots checked", paths, e)
	}
	for _, fail := range paths {
		for _, failure := range []error{os.ErrPermission, errors.New("malformed")} {
			if e := windowsReadAdminScopesAbsent("root", "sid", func(p string, o windowsstate.Options) (capabilityInspectionStore, error) {
				if p == fail {
					return nil, failure
				}
				return nil, os.ErrNotExist
			}); e == nil {
				t.Fatal("unknown root adopted", fail)
			}
		}
	}
}
func TestWindowsReadAdminGroupedRequirementsDoNotAssertAccess(t *testing.T) {
	seen := map[string]bool{}
	for _, g := range WindowsReadAdminGroups() {
		if g.ProviderAvailability != "not_checked" || g.ServiceTokenAccess != "not_verified" || g.Prerequisites == "" {
			t.Fatal("unproved provider access")
		}
		for _, scope := range g.Scopes {
			if seen[scope] {
				t.Fatal("duplicate group scope")
			}
			seen[scope] = true
		}
	}
	if len(seen) != 12 {
		t.Fatal("missing grouped scopes")
	}
	for _, scope := range WindowsReadAdminScopes() {
		if !seen[scope] {
			t.Fatal(scope)
		}
	}
	notices := strings.Join(WindowsReadAdminNotices(true), "\n")
	for _, word := range []string{"personal", "plaintext", "Defender", "Firewall", "history", "HKLM"} {
		if !strings.Contains(notices, word) {
			t.Fatal("missing disclosure", word)
		}
	}
}
