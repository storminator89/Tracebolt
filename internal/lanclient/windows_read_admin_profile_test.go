package lanclient

import (
	"crypto/sha256"
	"encoding/hex"
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

func readAdminV9Fixture() WindowsCapabilityConsent {
	return WindowsCapabilityConsent{SchemaVersion: WindowsCapabilityConsentVersionV9, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: WindowsReadAdminScopesV9(), Acknowledged: true}
}

func TestWindowsReadAdminV9RequiresFreshExactCoverageConsent(t *testing.T) {
	c := readAdminV9Fixture()
	raw, _ := json.Marshal(c)
	got, e := DecodeWindowsCapabilityConsent(raw)
	if e != nil || !reflect.DeepEqual(got, c) || len(c.Scopes) != 16 || c.Scopes[15] != "windows-complete-processes-v1" {
		t.Fatal("fresh exact profile rejected", e)
	}
	for _, version := range []string{WindowsCapabilityConsentVersion, WindowsCapabilityConsentVersionV2, WindowsCapabilityConsentVersionV3, WindowsCapabilityConsentVersionV4, WindowsCapabilityConsentVersionV5, WindowsCapabilityConsentVersionV6, WindowsCapabilityConsentVersionV7, WindowsCapabilityConsentVersionV8} {
		old := c
		old.SchemaVersion = version
		if old.Validate() == nil {
			t.Fatal("historical consent granted complete-processes context", version)
		}
	}
	for _, mutate := range []func(*WindowsCapabilityConsent){
		func(c *WindowsCapabilityConsent) { c.Acknowledged = false },
		func(c *WindowsCapabilityConsent) { c.Scopes = c.Scopes[:15] },
		func(c *WindowsCapabilityConsent) { c.Scopes[14], c.Scopes[15] = c.Scopes[15], c.Scopes[14] },
		func(c *WindowsCapabilityConsent) { c.Scopes[15] = c.Scopes[14] },
		func(c *WindowsCapabilityConsent) { c.Scopes = append(c.Scopes, "service-control") },
	} {
		bad := readAdminV9Fixture()
		mutate(&bad)
		calls := 0
		if _, e := applyWindowsCapabilities(bad, func(string) error { calls++; return nil }); e == nil || calls != 0 {
			t.Fatal("invalid consent reached writes")
		}
	}
	if _, e := ConfigureWindowsCapabilities("unused", c); e == nil {
		t.Fatal("unguarded V9 admitted")
	}
	if _, e := ConfigureWindowsReadAdminCapabilities("unused", c, nil); e == nil {
		t.Fatal("missing guard admitted")
	}
	// The development reconsent interface does not become a complete-processes migration.
	if _, e := PreviewWindowsReadAdmin("unused", c, func() error { t.Fatal("V9 reached reconsent guard"); return nil }); e == nil {
		t.Fatal("V9 reconsent admitted")
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

func TestWindowsReadAdminV9FreshCoverageRootNeverAdopted(t *testing.T) {
	paths := []string{}
	if e := windowsReadAdminScopesV9Absent("root", "sid", func(p string, o windowsstate.Options) (capabilityInspectionStore, error) {
		if o.Create {
			t.Fatal("inspection creates state")
		}
		paths = append(paths, p)
		return nil, os.ErrNotExist
	}); e != nil || len(paths) != 15 || paths[14] != "root-full-processes" {
		t.Fatal("incomplete fresh absence guard", paths, e)
	}
	for _, failure := range []error{os.ErrPermission, errors.New("malformed"), nil} {
		if e := windowsReadAdminScopesV9Absent("root", "sid", func(p string, _ windowsstate.Options) (capabilityInspectionStore, error) {
			if p == "root-full-processes" {
				return nil, failure
			}
			return nil, os.ErrNotExist
		}); e == nil {
			t.Fatal("present or indeterminate complete-processes grant adopted")
		}
	}
}

func TestWindowsReadAdminV9CoverageDigestAndRequirements(t *testing.T) {
	c := readAdminV9Fixture()
	for _, missing := range []bool{false, true} {
		got, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			if missing && scope == "windows-complete-processes-v1" {
				return nil, false
			}
			return struct {
				GrantID string `json:"grantId"`
			}{strings.Repeat("a", 32)}, true
		})
		if missing {
			if e == nil {
				t.Fatal("missing complete-processes digest admitted")
			}
			continue
		}
		if e != nil || len(got) != 15 || got[14].Scope != "windows-complete-processes-v1" {
			t.Fatal("complete-processes digest absent", e)
		}
		changed, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			id := strings.Repeat("a", 32)
			if scope == "windows-complete-processes-v1" {
				id = strings.Repeat("b", 32)
			}
			return struct {
				GrantID string `json:"grantId"`
			}{id}, true
		})
		if e != nil || changed[14].SHA256 == got[14].SHA256 {
			t.Fatal("replacement complete-processes grant lost")
		}
	}
	seen := map[string]bool{}
	var summary strings.Builder
	for _, g := range WindowsReadAdminGroupsV9() {
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
	if len(seen) != 16 {
		t.Fatal("missing grouped scopes")
	}
	for _, scope := range c.Scopes {
		if !seen[scope] {
			t.Fatal("scope omitted", scope)
		}
	}
	for _, text := range []string{"Toolhelp process inventory", "PID, parent PID", "executable name", "thread count"} {
		if !strings.Contains(summary.String(), text) {
			t.Fatal("identifying scope omitted", text)
		}
	}
}

func readAdminV10Fixture() WindowsCapabilityConsent {
	return WindowsCapabilityConsent{SchemaVersion: WindowsCapabilityConsentVersionV10, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: WindowsReadAdminScopesV10(), Acknowledged: true}
}

func TestWindowsReadAdminV10RequiresFreshExactCoverageConsent(t *testing.T) {
	c := readAdminV10Fixture()
	raw, _ := json.Marshal(c)
	got, e := DecodeWindowsCapabilityConsent(raw)
	if e != nil || !reflect.DeepEqual(got, c) || len(c.Scopes) != 17 || c.Scopes[16] != "windows-network-context-v1" {
		t.Fatal("fresh exact profile rejected", e)
	}
	for _, version := range []string{WindowsCapabilityConsentVersion, WindowsCapabilityConsentVersionV2, WindowsCapabilityConsentVersionV3, WindowsCapabilityConsentVersionV4, WindowsCapabilityConsentVersionV5, WindowsCapabilityConsentVersionV6, WindowsCapabilityConsentVersionV7, WindowsCapabilityConsentVersionV8, WindowsCapabilityConsentVersionV9} {
		old := c
		old.SchemaVersion = version
		if old.Validate() == nil {
			t.Fatal("historical consent granted network-context context", version)
		}
	}
	for _, mutate := range []func(*WindowsCapabilityConsent){
		func(c *WindowsCapabilityConsent) { c.Acknowledged = false },
		func(c *WindowsCapabilityConsent) { c.Scopes = c.Scopes[:16] },
		func(c *WindowsCapabilityConsent) { c.Scopes[14], c.Scopes[16] = c.Scopes[16], c.Scopes[14] },
		func(c *WindowsCapabilityConsent) { c.Scopes[16] = c.Scopes[14] },
		func(c *WindowsCapabilityConsent) { c.Scopes = append(c.Scopes, "service-control") },
	} {
		bad := readAdminV10Fixture()
		mutate(&bad)
		calls := 0
		if _, e := applyWindowsCapabilities(bad, func(string) error { calls++; return nil }); e == nil || calls != 0 {
			t.Fatal("invalid consent reached writes")
		}
	}
	if _, e := ConfigureWindowsCapabilities("unused", c); e == nil {
		t.Fatal("unguarded V10 admitted")
	}
	if _, e := ConfigureWindowsReadAdminCapabilities("unused", c, nil); e == nil {
		t.Fatal("missing guard admitted")
	}
	// The development reconsent interface does not become a network-context migration.
	if _, e := PreviewWindowsReadAdmin("unused", c, func() error { t.Fatal("V10 reached reconsent guard"); return nil }); e == nil {
		t.Fatal("V10 reconsent admitted")
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

func TestWindowsReadAdminV10FreshCoverageRootNeverAdopted(t *testing.T) {
	paths := []string{}
	if e := windowsReadAdminScopesV10Absent("root", "sid", func(p string, o windowsstate.Options) (capabilityInspectionStore, error) {
		if o.Create {
			t.Fatal("inspection creates state")
		}
		paths = append(paths, p)
		return nil, os.ErrNotExist
	}); e != nil || len(paths) != 16 || paths[15] != "root-network-context" {
		t.Fatal("incomplete fresh absence guard", paths, e)
	}
	for _, failure := range []error{os.ErrPermission, errors.New("malformed"), nil} {
		if e := windowsReadAdminScopesV10Absent("root", "sid", func(p string, _ windowsstate.Options) (capabilityInspectionStore, error) {
			if p == "root-network-context" {
				return nil, failure
			}
			return nil, os.ErrNotExist
		}); e == nil {
			t.Fatal("present or indeterminate network-context grant adopted")
		}
	}
}

func TestWindowsReadAdminV10CoverageDigestAndRequirements(t *testing.T) {
	c := readAdminV10Fixture()
	for _, missing := range []bool{false, true} {
		got, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			if missing && scope == "windows-network-context-v1" {
				return nil, false
			}
			return struct {
				GrantID string `json:"grantId"`
			}{strings.Repeat("a", 32)}, true
		})
		if missing {
			if e == nil {
				t.Fatal("missing network-context digest admitted")
			}
			continue
		}
		if e != nil || len(got) != 16 || got[15].Scope != "windows-network-context-v1" {
			t.Fatal("network-context digest absent", e)
		}
		changed, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			id := strings.Repeat("a", 32)
			if scope == "windows-network-context-v1" {
				id = strings.Repeat("b", 32)
			}
			return struct {
				GrantID string `json:"grantId"`
			}{id}, true
		})
		if e != nil || changed[15].SHA256 == got[15].SHA256 {
			t.Fatal("replacement network-context grant lost")
		}
	}
	seen := map[string]bool{}
	var summary strings.Builder
	for _, g := range WindowsReadAdminGroupsV10() {
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
	if len(seen) != 17 {
		t.Fatal("missing grouped scopes")
	}
	for _, scope := range c.Scopes {
		if !seen[scope] {
			t.Fatal("scope omitted", scope)
		}
	}
	for _, text := range []string{"route prefixes", "next-hop", "protocol/origin", "interface aliases", "unsigned 64-bit", "octet, error and discard"} {
		if !strings.Contains(summary.String(), text) {
			t.Fatal("identifying scope omitted", text)
		}
	}
}

func readAdminV11Fixture() WindowsCapabilityConsent {
	return WindowsCapabilityConsent{SchemaVersion: WindowsCapabilityConsentVersionV11, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: WindowsReadAdminScopesV11(), Acknowledged: true}
}

func TestWindowsReadAdminV11RequiresFreshExactCoverageConsent(t *testing.T) {
	c := readAdminV11Fixture()
	raw, _ := json.Marshal(c)
	got, e := DecodeWindowsCapabilityConsent(raw)
	if e != nil || !reflect.DeepEqual(got, c) || len(c.Scopes) != 18 || c.Scopes[17] != "windows-resource-context-v1" {
		t.Fatal("fresh exact profile rejected", e)
	}
	for _, version := range []string{WindowsCapabilityConsentVersion, WindowsCapabilityConsentVersionV2, WindowsCapabilityConsentVersionV3, WindowsCapabilityConsentVersionV4, WindowsCapabilityConsentVersionV5, WindowsCapabilityConsentVersionV6, WindowsCapabilityConsentVersionV7, WindowsCapabilityConsentVersionV8, WindowsCapabilityConsentVersionV9, WindowsCapabilityConsentVersionV10} {
		old := c
		old.SchemaVersion = version
		if old.Validate() == nil {
			t.Fatal("historical consent granted resource-context context", version)
		}
	}
	for _, mutate := range []func(*WindowsCapabilityConsent){
		func(c *WindowsCapabilityConsent) { c.Acknowledged = false },
		func(c *WindowsCapabilityConsent) { c.Scopes = c.Scopes[:17] },
		func(c *WindowsCapabilityConsent) { c.Scopes[14], c.Scopes[17] = c.Scopes[17], c.Scopes[14] },
		func(c *WindowsCapabilityConsent) { c.Scopes[17] = c.Scopes[14] },
		func(c *WindowsCapabilityConsent) { c.Scopes = append(c.Scopes, "service-control") },
	} {
		bad := readAdminV11Fixture()
		mutate(&bad)
		calls := 0
		if _, e := applyWindowsCapabilities(bad, func(string) error { calls++; return nil }); e == nil || calls != 0 {
			t.Fatal("invalid consent reached writes")
		}
	}
	if _, e := ConfigureWindowsCapabilities("unused", c); e == nil {
		t.Fatal("unguarded V11 admitted")
	}
	if _, e := ConfigureWindowsReadAdminCapabilities("unused", c, nil); e == nil {
		t.Fatal("missing guard admitted")
	}
	// The development reconsent interface does not become a resource-context migration.
	if _, e := PreviewWindowsReadAdmin("unused", c, func() error { t.Fatal("V11 reached reconsent guard"); return nil }); e == nil {
		t.Fatal("V11 reconsent admitted")
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

func TestWindowsReadAdminV11FreshCoverageRootNeverAdopted(t *testing.T) {
	paths := []string{}
	if e := windowsReadAdminScopesV11Absent("root", "sid", func(p string, o windowsstate.Options) (capabilityInspectionStore, error) {
		if o.Create {
			t.Fatal("inspection creates state")
		}
		paths = append(paths, p)
		return nil, os.ErrNotExist
	}); e != nil || len(paths) != 17 || paths[16] != "root-resource-context" {
		t.Fatal("incomplete fresh absence guard", paths, e)
	}
	for _, failure := range []error{os.ErrPermission, errors.New("malformed"), nil} {
		if e := windowsReadAdminScopesV11Absent("root", "sid", func(p string, _ windowsstate.Options) (capabilityInspectionStore, error) {
			if p == "root-resource-context" {
				return nil, failure
			}
			return nil, os.ErrNotExist
		}); e == nil {
			t.Fatal("present or indeterminate resource-context grant adopted")
		}
	}
}

func TestWindowsReadAdminV11CoverageDigestAndRequirements(t *testing.T) {
	c := readAdminV11Fixture()
	for _, missing := range []bool{false, true} {
		got, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			if missing && scope == "windows-resource-context-v1" {
				return nil, false
			}
			return struct {
				GrantID string `json:"grantId"`
			}{strings.Repeat("a", 32)}, true
		})
		if missing {
			if e == nil {
				t.Fatal("missing resource-context digest admitted")
			}
			continue
		}
		if e != nil || len(got) != 17 || got[16].Scope != "windows-resource-context-v1" {
			t.Fatal("resource-context digest absent", e)
		}
		changed, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			id := strings.Repeat("a", 32)
			if scope == "windows-resource-context-v1" {
				id = strings.Repeat("b", 32)
			}
			return struct {
				GrantID string `json:"grantId"`
			}{id}, true
		})
		if e != nil || changed[16].SHA256 == got[16].SHA256 {
			t.Fatal("replacement resource-context grant lost")
		}
	}
	seen := map[string]bool{}
	var summary strings.Builder
	for _, g := range WindowsReadAdminGroupsV11() {
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
	if len(seen) != 18 {
		t.Fatal("missing grouped scopes")
	}
	for _, scope := range c.Scopes {
		if !seen[scope] {
			t.Fatal("scope omitted", scope)
		}
	}
	for _, text := range []string{"CPU model", "source-labeled processor counts", "installed SMBIOS RAM", "OS-usable RAM", "commit current/limit", "remaining capacity", "aggregate pagefile allocated/in-use"} {
		if !strings.Contains(summary.String(), text) {
			t.Fatal("identifying scope omitted", text)
		}
	}
}

// Golden hashes were derived from the pre-resource-context source's exact
// canonical contracts. New fresh profiles must not widen or re-encode them.
func TestWindowsReadAdminHistoricalConsentBytesStayExactV1ThroughV10(t *testing.T) {
	for _, tc := range []struct {
		version string
		scopes  []string
		sha256  string
	}{
		{WindowsCapabilityConsentVersion, WindowsReadAdminScopes()[:3], "34b2403c24775e3e977f84a39a1ea707bc767f65c5f1b8cc6d52b520ad98ac29"},
		{WindowsCapabilityConsentVersionV2, WindowsReadAdminScopes()[:4], "c5363c3cb4ddac1699cb3f228fca15bae4c0d0b33f291ea2fbf758544e081c51"},
		{WindowsCapabilityConsentVersionV3, WindowsReadAdminScopes()[:5], "38200fe05e7e35d2e1fb5baa9689e11c896f6721021eba761fc8ca2fbb1c87fe"},
		{WindowsCapabilityConsentVersionV4, WindowsReadAdminScopes()[:6], "04efe473c47961e484373bd4b07cb00a21fd990d0ffa368ba85c5c94bd172824"},
		{WindowsCapabilityConsentVersionV5, WindowsReadAdminScopes(), "67ada8ce20ed99c2b76cb13285c227fa920dcaaa85eef127e96c2c565dfbbed9"},
		{WindowsCapabilityConsentVersionV6, WindowsReadAdminScopesV6(), "45f2471bab21362ce04da0cc499fac7dabb38762cd09c20577082252b4e1674c"},
		{WindowsCapabilityConsentVersionV7, WindowsReadAdminScopesV7(), "9eb564ae3f276989bf7d512225d97ad4ba33eec7bb9e2fb134d95ca98c1ca2a0"},
		{WindowsCapabilityConsentVersionV8, WindowsReadAdminScopesV8(), "59d7a240542b4d1cd60d2302cfc24c919b11da606ae8e7e21c04198004f9b9f1"},
		{WindowsCapabilityConsentVersionV9, WindowsReadAdminScopesV9(), "e1e15b9ae2d6c15cbbbf450304d52e2ad1ebf471220e4f2981856de9e22b5305"},
		{WindowsCapabilityConsentVersionV10, WindowsReadAdminScopesV10(), "0b5af9d9cd4714084ebdbcdef6668ec0c0b24f4741a91219cf765e65bb5f1336"},
	} {
		c := WindowsCapabilityConsent{SchemaVersion: tc.version, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: tc.scopes, Acknowledged: true}
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(raw)
		if hex.EncodeToString(h[:]) != tc.sha256 {
			t.Fatal("historical consent bytes changed", tc.version)
		}
		got, err := DecodeWindowsCapabilityConsent(raw)
		if err != nil || !reflect.DeepEqual(got, c) {
			t.Fatal("historical consent no longer accepted", tc.version, err)
		}
		for _, scope := range c.Scopes {
			if scope == "windows-resource-context-v1" {
				t.Fatal("old scope widened")
			}
		}
	}
}

func readAdminV12Fixture() WindowsCapabilityConsent {
	return WindowsCapabilityConsent{SchemaVersion: WindowsCapabilityConsentVersionV12, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: WindowsReadAdminScopesV12(), Acknowledged: true}
}

func TestWindowsReadAdminV12RequiresFreshExactCoverageConsent(t *testing.T) {
	c := readAdminV12Fixture()
	raw, _ := json.Marshal(c)
	got, e := DecodeWindowsCapabilityConsent(raw)
	if e != nil || !reflect.DeepEqual(got, c) || len(c.Scopes) != 19 || c.Scopes[18] != "windows-storage-io-v1" {
		t.Fatal("fresh exact profile rejected", e)
	}
	for _, version := range []string{WindowsCapabilityConsentVersion, WindowsCapabilityConsentVersionV2, WindowsCapabilityConsentVersionV3, WindowsCapabilityConsentVersionV4, WindowsCapabilityConsentVersionV5, WindowsCapabilityConsentVersionV6, WindowsCapabilityConsentVersionV7, WindowsCapabilityConsentVersionV8, WindowsCapabilityConsentVersionV9, WindowsCapabilityConsentVersionV10, WindowsCapabilityConsentVersionV11} {
		old := c
		old.SchemaVersion = version
		if old.Validate() == nil {
			t.Fatal("historical consent granted storage-io context", version)
		}
	}
	for _, mutate := range []func(*WindowsCapabilityConsent){
		func(c *WindowsCapabilityConsent) { c.Acknowledged = false },
		func(c *WindowsCapabilityConsent) { c.Scopes = c.Scopes[:18] },
		func(c *WindowsCapabilityConsent) { c.Scopes[14], c.Scopes[18] = c.Scopes[18], c.Scopes[14] },
		func(c *WindowsCapabilityConsent) { c.Scopes[18] = c.Scopes[14] },
		func(c *WindowsCapabilityConsent) { c.Scopes = append(c.Scopes, "service-control") },
	} {
		bad := readAdminV12Fixture()
		mutate(&bad)
		calls := 0
		if _, e := applyWindowsCapabilities(bad, func(string) error { calls++; return nil }); e == nil || calls != 0 {
			t.Fatal("invalid consent reached writes")
		}
	}
	if _, e := ConfigureWindowsCapabilities("unused", c); e == nil {
		t.Fatal("unguarded V12 admitted")
	}
	if _, e := ConfigureWindowsReadAdminCapabilities("unused", c, nil); e == nil {
		t.Fatal("missing guard admitted")
	}
	// The development reconsent interface does not become a storage-io migration.
	if _, e := PreviewWindowsReadAdmin("unused", c, func() error { t.Fatal("V12 reached reconsent guard"); return nil }); e == nil {
		t.Fatal("V12 reconsent admitted")
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

func TestWindowsReadAdminV12FreshCoverageRootNeverAdopted(t *testing.T) {
	paths := []string{}
	if e := windowsReadAdminScopesV12Absent("root", "sid", func(p string, o windowsstate.Options) (capabilityInspectionStore, error) {
		if o.Create {
			t.Fatal("inspection creates state")
		}
		paths = append(paths, p)
		return nil, os.ErrNotExist
	}); e != nil || len(paths) != 18 || paths[17] != "root-storage-io" {
		t.Fatal("incomplete fresh absence guard", paths, e)
	}
	for _, failure := range []error{os.ErrPermission, errors.New("malformed"), nil} {
		if e := windowsReadAdminScopesV12Absent("root", "sid", func(p string, _ windowsstate.Options) (capabilityInspectionStore, error) {
			if p == "root-storage-io" {
				return nil, failure
			}
			return nil, os.ErrNotExist
		}); e == nil {
			t.Fatal("present or indeterminate storage-io grant adopted")
		}
	}
}

func TestWindowsReadAdminV12CoverageDigestAndRequirements(t *testing.T) {
	c := readAdminV12Fixture()
	for _, missing := range []bool{false, true} {
		got, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			if missing && scope == "windows-storage-io-v1" {
				return nil, false
			}
			return struct {
				GrantID string `json:"grantId"`
			}{strings.Repeat("a", 32)}, true
		})
		if missing {
			if e == nil {
				t.Fatal("missing storage-io digest admitted")
			}
			continue
		}
		if e != nil || len(got) != 18 || got[17].Scope != "windows-storage-io-v1" {
			t.Fatal("storage-io digest absent", e)
		}
		changed, e := windowsCapabilityGrantDigests(c, func(scope string) (any, bool) {
			id := strings.Repeat("a", 32)
			if scope == "windows-storage-io-v1" {
				id = strings.Repeat("b", 32)
			}
			return struct {
				GrantID string `json:"grantId"`
			}{id}, true
		})
		if e != nil || changed[17].SHA256 == got[17].SHA256 {
			t.Fatal("replacement storage-io grant lost")
		}
	}
	seen := map[string]bool{}
	var summary strings.Builder
	for _, g := range WindowsReadAdminGroupsV12() {
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
	if len(seen) != 19 {
		t.Fatal("missing grouped scopes")
	}
	for _, scope := range c.Scopes {
		if !seen[scope] {
			t.Fatal("scope omitted", scope)
		}
	}
	for _, text := range []string{"PerfDisk (_Total)", "read/write throughput", "operations per second", "latency", "queue lengths", "sample window"} {
		if !strings.Contains(summary.String(), text) {
			t.Fatal("identifying scope omitted", text)
		}
	}
}

func TestWindowsReadAdminHistoricalV11ConsentBytesRemainExact(t *testing.T) {
	c := readAdminV11Fixture()
	raw, _ := json.Marshal(c)
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != "588ddbca6a9b670195e81c8c00ab732cde7d2dec4fae41d8b1d8b07250e3110a" {
		t.Fatal("historical v11 consent changed")
	}
	if _, err := DecodeWindowsCapabilityConsent(raw); err != nil {
		t.Fatal(err)
	}
}
