package lanclient

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsvolumes"
)

// WindowsCapabilityConsentVersion is an upfront local approval contract for a
// future fresh installer. No current installer invokes it or grants extensions.
const WindowsCapabilityConsentVersion = "tracebolt.windows-capability-consent.v1"

// WindowsCapabilityConsent selects the exact scope disclosed to the human.
// Metadata is mandatory for this inventory profile; event headers and volumes
// remain optional. Acknowledged covers every selected scope's privacy notice;
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
	if r.SchemaVersion != WindowsCapabilityConsentVersion || r.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || !r.Acknowledged || len(r.Scopes) == 0 || len(r.Scopes) > 3 {
		return ErrConfiguration
	}
	seen := map[string]bool{}
	for _, scope := range r.Scopes {
		if seen[scope] || scope != enrollmentcrypto.CollectionProfileWindowsInventory && scope != windowseventhealth.Scope && scope != windowsvolumes.Scope {
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
