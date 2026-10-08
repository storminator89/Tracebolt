package lanclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsvolumes"
	"os"
)

// WindowsCapabilityConsentVersion is an upfront local approval contract for a
// fresh source-only installer coordinator. No released installer invokes it.
const WindowsCapabilityConsentVersion = "tracebolt.windows-capability-consent.v1"

// WindowsCapabilityConsentVersionV2 adds an explicitly selected process CPU/memory scope.
// V1 retains its original exact scope set and is never promoted implicitly.
const WindowsCapabilityConsentVersionV2 = "tracebolt.windows-capability-consent.v2"

// WindowsCapabilityConsentVersionV3 adds an explicitly selected network endpoint scope.
// Earlier versions retain their exact scope sets and never authorize network reads.
const WindowsCapabilityConsentVersionV3 = "tracebolt.windows-capability-consent.v3"

// WindowsCapabilityConsentVersionV4 adds explicitly selected service startup metadata.
// V1-V3 and the fresh five-scope coordinator remain unchanged.
const WindowsCapabilityConsentVersionV4 = "tracebolt.windows-capability-consent.v4"

// WindowsCapabilityConsent selects the exact scope disclosed to the human.
// Metadata is mandatory for this inventory profile; event headers and volumes
// remain optional in v1. V2 additionally permits process CPU/memory; V3 also
// permits network endpoints. V4 also permits service startup metadata.
// Acknowledged covers every selected scope's privacy notice;
// HTTP additionally requires the selected scopes' plaintext-risk disclosure.
// This is not an enrollment approval or a grant by itself.
type WindowsCapabilityConsent struct {
	SchemaVersion            string   `json:"schemaVersion"`
	CollectionProfile        string   `json:"collectionProfile"`
	Scopes                   []string `json:"scopes"`
	Acknowledged             bool     `json:"acknowledged"`
	InsecureHTTPAcknowledged bool     `json:"insecureHTTPAcknowledged"`
}

func (r WindowsCapabilityConsent) Validate() error {
	v2 := r.SchemaVersion == WindowsCapabilityConsentVersionV2
	v3 := r.SchemaVersion == WindowsCapabilityConsentVersionV3
	v4 := r.SchemaVersion == WindowsCapabilityConsentVersionV4
	maxScopes := 3
	if v2 {
		maxScopes = 4
	}
	if v3 {
		maxScopes = 5
	}
	if v4 {
		maxScopes = 6
	}
	if r.SchemaVersion != WindowsCapabilityConsentVersion && !v2 && !v3 && !v4 || r.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || !r.Acknowledged || len(r.Scopes) == 0 || len(r.Scopes) > maxScopes {
		return ErrConfiguration
	}
	seen := map[string]bool{}
	for _, scope := range r.Scopes {
		if seen[scope] || scope != enrollmentcrypto.CollectionProfileWindowsInventory && scope != windowseventhealth.Scope && scope != windowsvolumes.Scope && !((v2 || v3 || v4) && scope == windowsprocessmetrics.Scope) && !((v3 || v4) && scope == windowsnetwork.Scope) && !(v4 && scope == windowsmanaged.ServiceStartupScope) {
			return ErrConfiguration
		}
		seen[scope] = true
	}
	if !seen[enrollmentcrypto.CollectionProfileWindowsInventory] {
		return ErrConfiguration
	}
	return nil
}

// DecodeWindowsCapabilityConsent rejects unknown, duplicate and trailing fields
// and requires the exact canonical versioned representation.
func DecodeWindowsCapabilityConsent(raw []byte) (WindowsCapabilityConsent, error) {
	var r WindowsCapabilityConsent
	if len(raw) == 0 || len(raw) > 2048 || json.Unmarshal(raw, &r) != nil || r.Validate() != nil {
		return WindowsCapabilityConsent{}, ErrConfiguration
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return WindowsCapabilityConsent{}, ErrConfiguration
	}
	return r, nil
}

type WindowsCapabilityConsentResult struct {
	// AppliedScopes lists only successful extension operations in request order.
	// MetadataScopeVerified refers to the existing activated identity, not a write.
	MetadataScopeVerified bool     `json:"metadataScopeVerified"`
	AppliedScopes         []string `json:"appliedScopes"`
	FailedScope           string   `json:"failedScope,omitempty"`
}

// ConfigureWindowsCapabilities is reusable only after activation and after the
// caller verifies the owned service is stopped. The upfront acknowledgement is
// reused for the exact selected scopes. Individual protected writes are NOT
// atomic as a group: on failure the returned result preserves completed scopes,
// and FailedScope may have an indeterminate write outcome. Never rollback,
// erase, re-enroll or enable unselected scopes to recover.
func ConfigureWindowsCapabilities(path string, r WindowsCapabilityConsent) (WindowsCapabilityConsentResult, error) {
	if r.Validate() != nil {
		return WindowsCapabilityConsentResult{}, ErrConfiguration
	}
	if ValidateGuidedHandoff(path) != nil {
		return WindowsCapabilityConsentResult{}, ErrState
	}
	m, err := Load(path)
	if err != nil || !m.config.windowsInventory() || r.InsecureHTTPAcknowledged != (m.config.Profile == "http-test") {
		return WindowsCapabilityConsentResult{}, ErrConfiguration
	}
	return applyWindowsCapabilities(r, func(scope string) error {
		switch scope {
		case windowseventhealth.Scope:
			_, err := ConfigureWindowsEventMetadata(path, "enable", true, r.InsecureHTTPAcknowledged)
			return err
		case windowsmanaged.ServiceStartupScope:
			_, err := ConfigureWindowsServiceStartup(path, "enable", true, r.InsecureHTTPAcknowledged)
			return err
		case windowsnetwork.Scope:
			_, err := ConfigureWindowsNetwork(path, "enable", true, r.InsecureHTTPAcknowledged)
			return err
		case windowsprocessmetrics.Scope:
			_, err := ConfigureWindowsProcessMetrics(path, "enable", true, r.InsecureHTTPAcknowledged)
			return err
		case windowsvolumes.Scope:
			_, err := ConfigureWindowsVolumes(path, "enable", true, r.InsecureHTTPAcknowledged)
			return err
		}
		return ErrConfiguration
	})
}

func applyWindowsCapabilities(r WindowsCapabilityConsent, enable func(string) error) (WindowsCapabilityConsentResult, error) {
	result := WindowsCapabilityConsentResult{}
	if r.Validate() != nil || enable == nil {
		return result, ErrConfiguration
	}
	result.MetadataScopeVerified = true
	result.AppliedScopes = []string{}
	for _, scope := range r.Scopes {
		if scope == enrollmentcrypto.CollectionProfileWindowsInventory {
			continue
		}
		if err := enable(scope); err != nil {
			result.FailedScope = scope
			return result, err
		}
		result.AppliedScopes = append(result.AppliedScopes, scope)
	}
	return result, nil
}

// WindowsCapabilityIdentity validates the activated handoff and the exact
// transport/scope contract without collection. The opaque sender binding lets a
// fresh setup fence reject replacement identities without exposing credentials.
func WindowsCapabilityIdentity(path string, r WindowsCapabilityConsent) (string, error) {
	if r.Validate() != nil {
		return "", ErrConfiguration
	}
	if ValidateGuidedHandoff(path) != nil {
		return "", ErrState
	}
	m, err := Load(path)
	if err != nil || !m.config.windowsInventory() || r.InsecureHTTPAcknowledged != (m.config.Profile == "http-test") {
		return "", ErrConfiguration
	}
	return m.binding, nil
}

// WindowsCapabilityScopesAbsent is a read-only fresh-install precondition. Only
// actual absent roots are fresh; denied, malformed or existing stores are not.
func WindowsCapabilityScopesAbsent(root, sid string) error {
	return windowsCapabilityScopesAbsent(root, sid, func(path string, options windowsstate.Options) (capabilityInspectionStore, error) {
		store, err := windowsstate.Open(path, options)
		if err != nil {
			return nil, err
		}
		return store, nil
	})
}

type capabilityInspectionStore interface{ Close() error }

func windowsCapabilityScopesAbsent(root, sid string, open func(string, windowsstate.Options) (capabilityInspectionStore, error)) error {
	if open == nil {
		return ErrConfiguration
	}
	for _, item := range []struct {
		suffix  string
		options windowsstate.Options
	}{
		{"-event-metadata", windowsEventOptions(sid, false)},
		{"-visible-volumes", windowsVolumeOptions(sid, false)},
		{"-process-metrics", windowsProcessMetricsOptions(sid, false)},
		{"-network", windowsNetworkOptions(sid, false)},
	} {
		store, err := open(root+item.suffix, item.options)
		if store != nil {
			_ = store.Close()
			return ErrState
		}
		if !errors.Is(err, os.ErrNotExist) {
			return ErrState
		}
	}
	return nil
}

// VerifyWindowsCapabilities reads the exact identity-bound local grants, never
// native observations. It neither repairs, enables nor initializes any scope.
func VerifyWindowsCapabilities(path string, r WindowsCapabilityConsent) error {
	_, err := WindowsCapabilityGrantDigests(path, r)
	return err
}

type WindowsCapabilityGrantDigest struct {
	Scope  string `json:"scope"`
	SHA256 string `json:"sha256"`
}

// WindowsCapabilityGrantDigests reads canonical enabled identity-bound grants.
// Digests include each grant ID, so disable/re-enable or replacement cannot be
// mistaken for the exact grants verified before a startup transition.
func WindowsCapabilityGrantDigests(path string, r WindowsCapabilityConsent) ([]WindowsCapabilityGrantDigest, error) {
	if _, err := WindowsCapabilityIdentity(path, r); err != nil {
		return nil, err
	}
	m, err := Load(path)
	if err != nil {
		return nil, err
	}
	return windowsCapabilityGrantDigests(r, func(scope string) (any, bool) {
		switch scope {
		case windowseventhealth.Scope:
			c, ok := readWindowsEventConsent(m)
			return c, ok
		case windowsvolumes.Scope:
			c, ok := readWindowsVolumeConsent(m)
			return c, ok
		case windowsprocessmetrics.Scope:
			c, ok := readWindowsProcessMetricsConsent(m)
			return c, ok
		case windowsmanaged.ServiceStartupScope:
			c, ok := readWindowsServiceStartupConsent(m)
			return c, ok
		case windowsnetwork.Scope:
			c, ok := readWindowsNetworkConsent(m)
			return c, ok
		}
		return nil, false
	})
}
func windowsCapabilityGrantDigests(r WindowsCapabilityConsent, read func(string) (any, bool)) ([]WindowsCapabilityGrantDigest, error) {
	if r.Validate() != nil || read == nil {
		return nil, ErrConfiguration
	}
	result := []WindowsCapabilityGrantDigest{}
	for _, scope := range r.Scopes {
		if scope == enrollmentcrypto.CollectionProfileWindowsInventory {
			continue
		}
		c, ok := read(scope)
		if !ok || c == nil {
			return nil, ErrState
		}
		raw, err := json.Marshal(c)
		if err != nil {
			return nil, ErrState
		}
		digest := sha256.Sum256(raw)
		result = append(result, WindowsCapabilityGrantDigest{scope, hex.EncodeToString(digest[:])})
	}
	return result, nil
}
