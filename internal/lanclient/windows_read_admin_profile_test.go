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

func readAdminV6Fixture() WindowsCapabilityConsent {
	return WindowsCapabilityConsent{SchemaVersion: WindowsCapabilityConsentVersionV6, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: WindowsReadAdminScopesV6(), Acknowledged: true}
}

func TestWindowsReadAdminV6RequiresFreshExactSerialConsent(t *testing.T) {
	c := readAdminV6Fixture()
	raw, _ := json.Marshal(c)
	got, e := DecodeWindowsCapabilityConsent(raw)
	if e != nil || !reflect.DeepEqual(got, c) || len(c.Scopes) != 13 || c.Scopes[12] != "windows-hardware-context-v1" {
		t.Fatal("fresh exact profile rejected", e)
	}
	for _, version := range []string{WindowsCapabilityConsentVersion, WindowsCapabilityConsentVersionV2, WindowsCapabilityConsentVersionV3, WindowsCapabilityConsentVersionV4, WindowsCapabilityConsentVersionV5} {
		old := c
		old.SchemaVersion = version
		if old.Validate() == nil {
			t.Fatal("historical consent granted serial metadata", version)
		}
	}
	for _, mutate := range []func(*WindowsCapabilityConsent){
		func(c *WindowsCapabilityConsent) { c.Acknowledged = false },
		func(c *WindowsCapabilityConsent) { c.Scopes = c.Scopes[:12] },
		func(c *WindowsCapabilityConsent) { c.Scopes[11], c.Scopes[12] = c.Scopes[12], c.Scopes[11] },
		func(c *WindowsCapabilityConsent) { c.Scopes[12] = c.Scopes[11] },
		func(c *WindowsCapabilityConsent) { c.Scopes = append(c.Scopes, "service-control") },
	} {
		bad := readAdminV6Fixture()
		mutate(&bad)
		calls := 0
		if _, e := applyWindowsCapabilities(bad, func(string) error { calls++; return nil }); e == nil || calls != 0 {
			t.Fatal("invalid consent reached writes")
		}
	}
	if _, e := ConfigureWindowsCapabilities("unused", c); e == nil {
		t.Fatal("unguarded V6 admitted")
	}
	if _, e := ConfigureWindowsReadAdminCapabilities("unused", c, nil); e == nil {
		t.Fatal("missing guard admitted")
	}
	// The development reconsent interface does not become a hardware migration.
	if _, e := PreviewWindowsReadAdmin("unused", c, func() error { t.Fatal("V6 reached reconsent guard"); return nil }); e == nil {
		t.Fatal("V6 reconsent admitted")
	}
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
			t.Fatal("partial grant authority lost", fail)
		}
	}
}

func TestWindowsReadAdminV6FreshHardwareRootNeverAdopted(t *testing.T) {
	paths := []string{}
	if e := windowsReadAdminScopesV6Absent("root", "sid", func(p string, o windowsstate.Options) (capabilityInspectionStore, error) {
		if o.Create {
			t.Fatal("inspection creates state")
		}
		paths = append(paths, p)
		return nil, os.ErrNotExist
	}); e != nil || len(paths) != 12 || paths[11] != "root-hardware-context" {
		t.Fatal("incomplete fresh absence guard", paths, e)
	}
	for _, failure := range []error{os.ErrPermission, errors.New("malformed"), nil} {
		if e := windowsReadAdminScopesV6Absent("root", "sid", func(p string, _ windowsstate.Options) (capabilityInspectionStore, error) {
			if p == "root-hardware-context" {
				return nil, failure
			}
			return nil, os.ErrNotExist
		}); e == nil {
			t.Fatal("present or indeterminate hardware grant adopted")
		}
	}
}

func TestWindowsReadAdminV6HardwareDigestAndRequirements(t *testing.T) {
	c := readAdminV6Fixture()
	for _, missing := range []bool{false, true} {
		got, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			if missing && scope == "windows-hardware-context-v1" {
				return nil, false
			}
			return struct {
				GrantID string `json:"grantId"`
			}{strings.Repeat("a", 32)}, true
		})
		if missing {
			if e == nil {
				t.Fatal("missing hardware digest admitted")
			}
			continue
		}
		if e != nil || len(got) != 12 || got[11].Scope != "windows-hardware-context-v1" {
			t.Fatal("hardware digest absent", e)
		}
		changed, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			id := strings.Repeat("a", 32)
			if scope == "windows-hardware-context-v1" {
				id = strings.Repeat("b", 32)
			}
			return struct {
				GrantID string `json:"grantId"`
			}{id}, true
		})
		if e != nil || changed[11].SHA256 == got[11].SHA256 {
			t.Fatal("replacement hardware grant lost")
		}
	}
	seen := map[string]bool{}
	var summary strings.Builder
	for _, g := range WindowsReadAdminGroupsV6() {
		if g.ProviderAvailability != "not_checked" || g.ServiceTokenAccess != "not_verified" {
			t.Fatal("unproved native access")
		}
		summary.WriteString(g.Summary)
		for _, scope := range g.Scopes {
			if seen[scope] {
				t.Fatal("duplicate group scope")
			}
			seen[scope] = true
		}
	}
	if len(seen) != 13 {
		t.Fatal("missing grouped scopes")
	}
	for _, scope := range c.Scopes {
		if !seen[scope] {
			t.Fatal("scope omitted", scope)
		}
	}
	for _, text := range []string{"manufacturer/model", "physical chassis serial (Win32_SystemEnclosure)", "BIOS serial metadata", "firmware vendor/version/date", "power/battery"} {
		if !strings.Contains(summary.String(), text) {
			t.Fatal("identifying scope omitted", text)
		}
	}
}

func TestWindowsReadAdminV5ConsentBytesRemainHistorical(t *testing.T) {
	const original = `{"schemaVersion":"tracebolt.windows-capability-consent.v5","collectionProfile":"windows-inventory-v1","scopes":["windows-inventory-v1","windows-application-system-event-headers-v1","windows-visible-volumes-v1","windows-process-metrics-v1","windows-network-endpoints-v1","windows-service-startup-v1","windows-complete-services-v1","windows-complete-machine-software-v1","windows-adapter-context-v1","windows-patch-context-v1","windows-security-posture-v1","windows-session-context-v1"],"acknowledged":true,"insecureHTTPAcknowledged":false}`
	raw, _ := json.Marshal(readAdminFixture())
	if string(raw) != original {
		t.Fatal("V5 consent bytes changed")
	}
	if _, e := DecodeWindowsCapabilityConsent([]byte(original)); e != nil {
		t.Fatal("historical bytes rejected")
	}
}

func readAdminV7Fixture() WindowsCapabilityConsent {
	return WindowsCapabilityConsent{SchemaVersion: WindowsCapabilityConsentVersionV7, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: WindowsReadAdminScopesV7(), Acknowledged: true}
}

func TestWindowsReadAdminV7RequiresFreshExactStorageConsent(t *testing.T) {
	c := readAdminV7Fixture()
	raw, _ := json.Marshal(c)
	got, e := DecodeWindowsCapabilityConsent(raw)
	if e != nil || !reflect.DeepEqual(got, c) || len(c.Scopes) != 14 || c.Scopes[13] != "windows-storage-context-v1" {
		t.Fatal("fresh exact profile rejected", e)
	}
	for _, version := range []string{WindowsCapabilityConsentVersion, WindowsCapabilityConsentVersionV2, WindowsCapabilityConsentVersionV3, WindowsCapabilityConsentVersionV4, WindowsCapabilityConsentVersionV5, WindowsCapabilityConsentVersionV6} {
		old := c
		old.SchemaVersion = version
		if old.Validate() == nil {
			t.Fatal("historical consent granted storage context", version)
		}
	}
	for _, mutate := range []func(*WindowsCapabilityConsent){
		func(c *WindowsCapabilityConsent) { c.Acknowledged = false },
		func(c *WindowsCapabilityConsent) { c.Scopes = c.Scopes[:13] },
		func(c *WindowsCapabilityConsent) { c.Scopes[12], c.Scopes[13] = c.Scopes[13], c.Scopes[12] },
		func(c *WindowsCapabilityConsent) { c.Scopes[13] = c.Scopes[12] },
		func(c *WindowsCapabilityConsent) { c.Scopes = append(c.Scopes, "service-control") },
	} {
		bad := readAdminV7Fixture()
		mutate(&bad)
		calls := 0
		if _, e := applyWindowsCapabilities(bad, func(string) error { calls++; return nil }); e == nil || calls != 0 {
			t.Fatal("invalid consent reached writes")
		}
	}
	if _, e := ConfigureWindowsCapabilities("unused", c); e == nil {
		t.Fatal("unguarded V7 admitted")
	}
	if _, e := ConfigureWindowsReadAdminCapabilities("unused", c, nil); e == nil {
		t.Fatal("missing guard admitted")
	}
	// The development reconsent interface does not become a storage migration.
	if _, e := PreviewWindowsReadAdmin("unused", c, func() error { t.Fatal("V7 reached reconsent guard"); return nil }); e == nil {
		t.Fatal("V7 reconsent admitted")
	}
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
			t.Fatal("partial grant authority lost", fail)
		}
	}
}

func TestWindowsReadAdminV7FreshStorageRootNeverAdopted(t *testing.T) {
	paths := []string{}
	if e := windowsReadAdminScopesV7Absent("root", "sid", func(p string, o windowsstate.Options) (capabilityInspectionStore, error) {
		if o.Create {
			t.Fatal("inspection creates state")
		}
		paths = append(paths, p)
		return nil, os.ErrNotExist
	}); e != nil || len(paths) != 13 || paths[12] != "root-storage-context" {
		t.Fatal("incomplete fresh absence guard", paths, e)
	}
	for _, failure := range []error{os.ErrPermission, errors.New("malformed"), nil} {
		if e := windowsReadAdminScopesV7Absent("root", "sid", func(p string, _ windowsstate.Options) (capabilityInspectionStore, error) {
			if p == "root-storage-context" {
				return nil, failure
			}
			return nil, os.ErrNotExist
		}); e == nil {
			t.Fatal("present or indeterminate storage grant adopted")
		}
	}
}

func TestWindowsReadAdminV7StorageDigestAndRequirements(t *testing.T) {
	c := readAdminV7Fixture()
	for _, missing := range []bool{false, true} {
		got, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			if missing && scope == "windows-storage-context-v1" {
				return nil, false
			}
			return struct {
				GrantID string `json:"grantId"`
			}{strings.Repeat("a", 32)}, true
		})
		if missing {
			if e == nil {
				t.Fatal("missing storage digest admitted")
			}
			continue
		}
		if e != nil || len(got) != 13 || got[12].Scope != "windows-storage-context-v1" {
			t.Fatal("storage digest absent", e)
		}
		changed, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			id := strings.Repeat("a", 32)
			if scope == "windows-storage-context-v1" {
				id = strings.Repeat("b", 32)
			}
			return struct {
				GrantID string `json:"grantId"`
			}{id}, true
		})
		if e != nil || changed[12].SHA256 == got[12].SHA256 {
			t.Fatal("replacement storage grant lost")
		}
	}
	seen := map[string]bool{}
	var summary strings.Builder
	for _, g := range WindowsReadAdminGroupsV7() {
		if g.ProviderAvailability != "not_checked" || g.ServiceTokenAccess != "not_verified" {
			t.Fatal("unproved native access")
		}
		summary.WriteString(g.Summary)
		for _, scope := range g.Scopes {
			if seen[scope] {
				t.Fatal("duplicate group scope")
			}
			seen[scope] = true
		}
	}
	if len(seen) != 14 {
		t.Fatal("missing grouped scopes")
	}
	for _, scope := range c.Scopes {
		if !seen[scope] {
			t.Fatal("scope omitted", scope)
		}
	}
	for _, text := range []string{"Local drive letters", "volume GUID", "storage-provider device identifiers/friendly labels", "provider health/status"} {
		if !strings.Contains(summary.String(), text) {
			t.Fatal("identifying scope omitted", text)
		}
	}
}

func readAdminV8Fixture() WindowsCapabilityConsent {
	return WindowsCapabilityConsent{SchemaVersion: WindowsCapabilityConsentVersionV8, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: WindowsReadAdminScopesV8(), Acknowledged: true}
}

func TestWindowsReadAdminV8RequiresFreshExactCoverageConsent(t *testing.T) {
	c := readAdminV8Fixture()
	raw, _ := json.Marshal(c)
	got, e := DecodeWindowsCapabilityConsent(raw)
	if e != nil || !reflect.DeepEqual(got, c) || len(c.Scopes) != 15 || c.Scopes[14] != "windows-security-coverage-v1" {
		t.Fatal("fresh exact profile rejected", e)
	}
	for _, version := range []string{WindowsCapabilityConsentVersion, WindowsCapabilityConsentVersionV2, WindowsCapabilityConsentVersionV3, WindowsCapabilityConsentVersionV4, WindowsCapabilityConsentVersionV5, WindowsCapabilityConsentVersionV6, WindowsCapabilityConsentVersionV7} {
		old := c
		old.SchemaVersion = version
		if old.Validate() == nil {
			t.Fatal("historical consent granted security-coverage context", version)
		}
	}
	for _, mutate := range []func(*WindowsCapabilityConsent){
		func(c *WindowsCapabilityConsent) { c.Acknowledged = false },
		func(c *WindowsCapabilityConsent) { c.Scopes = c.Scopes[:14] },
		func(c *WindowsCapabilityConsent) { c.Scopes[13], c.Scopes[14] = c.Scopes[14], c.Scopes[13] },
		func(c *WindowsCapabilityConsent) { c.Scopes[14] = c.Scopes[13] },
		func(c *WindowsCapabilityConsent) { c.Scopes = append(c.Scopes, "service-control") },
	} {
		bad := readAdminV8Fixture()
		mutate(&bad)
		calls := 0
		if _, e := applyWindowsCapabilities(bad, func(string) error { calls++; return nil }); e == nil || calls != 0 {
			t.Fatal("invalid consent reached writes")
		}
	}
	if _, e := ConfigureWindowsCapabilities("unused", c); e == nil {
		t.Fatal("unguarded V8 admitted")
	}
	if _, e := ConfigureWindowsReadAdminCapabilities("unused", c, nil); e == nil {
		t.Fatal("missing guard admitted")
	}
	// The development reconsent interface does not become a security-coverage migration.
	if _, e := PreviewWindowsReadAdmin("unused", c, func() error { t.Fatal("V8 reached reconsent guard"); return nil }); e == nil {
		t.Fatal("V8 reconsent admitted")
	}
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
			t.Fatal("partial grant authority lost", fail)
		}
	}
}

func TestWindowsReadAdminV8FreshCoverageRootNeverAdopted(t *testing.T) {
	paths := []string{}
	if e := windowsReadAdminScopesV8Absent("root", "sid", func(p string, o windowsstate.Options) (capabilityInspectionStore, error) {
		if o.Create {
			t.Fatal("inspection creates state")
		}
		paths = append(paths, p)
		return nil, os.ErrNotExist
	}); e != nil || len(paths) != 14 || paths[13] != "root-security-coverage" {
		t.Fatal("incomplete fresh absence guard", paths, e)
	}
	for _, failure := range []error{os.ErrPermission, errors.New("malformed"), nil} {
		if e := windowsReadAdminScopesV8Absent("root", "sid", func(p string, _ windowsstate.Options) (capabilityInspectionStore, error) {
			if p == "root-security-coverage" {
				return nil, failure
			}
			return nil, os.ErrNotExist
		}); e == nil {
			t.Fatal("present or indeterminate security-coverage grant adopted")
		}
	}
}

func TestWindowsReadAdminV8CoverageDigestAndRequirements(t *testing.T) {
	c := readAdminV8Fixture()
	for _, missing := range []bool{false, true} {
		got, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			if missing && scope == "windows-security-coverage-v1" {
				return nil, false
			}
			return struct {
				GrantID string `json:"grantId"`
			}{strings.Repeat("a", 32)}, true
		})
		if missing {
			if e == nil {
				t.Fatal("missing security-coverage digest admitted")
			}
			continue
		}
		if e != nil || len(got) != 14 || got[13].Scope != "windows-security-coverage-v1" {
			t.Fatal("security-coverage digest absent", e)
		}
		changed, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			id := strings.Repeat("a", 32)
			if scope == "windows-security-coverage-v1" {
				id = strings.Repeat("b", 32)
			}
			return struct {
				GrantID string `json:"grantId"`
			}{id}, true
		})
		if e != nil || changed[13].SHA256 == got[13].SHA256 {
			t.Fatal("replacement security-coverage grant lost")
		}
	}
	seen := map[string]bool{}
	var summary strings.Builder
	for _, g := range WindowsReadAdminGroupsV8() {
		if g.ProviderAvailability != "not_checked" || g.ServiceTokenAccess != "not_verified" {
			t.Fatal("unproved native access")
		}
		summary.WriteString(g.Summary)
		for _, scope := range g.Scopes {
			if seen[scope] {
				t.Fatal("duplicate group scope")
			}
			seen[scope] = true
		}
	}
	if len(seen) != 15 {
		t.Fatal("missing grouped scopes")
	}
	for _, scope := range c.Scopes {
		if !seen[scope] {
			t.Fatal("scope omitted", scope)
		}
	}
	for _, text := range []string{"Security Center", "antivirus product names/state/signature status", "TPM supported-device presence/version"} {
		if !strings.Contains(summary.String(), text) {
			t.Fatal("identifying scope omitted", text)
		}
	}
}
