package lanclient

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanconfig"
	"localrmm/internal/renewalidentity"
	"path/filepath"
)

// MacOSInventoryConfig is a fresh-only contract. Generic Load/Run deliberately
// reject its schema; no ordinary telemetry may be sent under this scope.
const MacOSInventoryConfigVersion = "tracebolt.lan-agent.macos-inventory.v1"
const MacOSInventoryConsentName = "macos-inventory-consent.json"
const MacOSInventoryEnableName = "macos-inventory-enable.json"

type MacOSInventoryConfig struct {
	Config
	ConsentFile        string `json:"consentFile"`
	OriginalEnableFile string `json:"originalEnableFile"`
}

func (c MacOSInventoryConfig) Validate(path string) error {
	if c.SchemaVersion != MacOSInventoryConfigVersion || c.CollectionProfile != enrollmentcrypto.CollectionProfileMacOSInventory || c.Profile != "tls" || c.InsecureHTTPAcknowledged || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "agent.json" {
		return ErrConfiguration
	}
	dir := filepath.Dir(path)
	if c.CertificateFile != filepath.Join(dir, "agent-cert.pem") || c.PrivateKeyFile != filepath.Join(dir, "agent-key.pem") || c.ServerCAFile != filepath.Join(dir, "server-ca.pem") || c.StateDirectory != filepath.Join(dir, "telemetry") || c.ConsentFile != filepath.Join(dir, MacOSInventoryConsentName) || c.OriginalEnableFile != filepath.Join(dir, MacOSInventoryEnableName) || c.RenewalManifestFile != "" && c.RenewalManifestFile != filepath.Join(dir, renewalidentity.ManifestName) {
		return ErrConfiguration
	}
	// Reuse only origin/path syntax validation. This never selects the generic
	// sender or promotes a generic profile into inventory authority.
	base := c.Config
	base.SchemaVersion, base.CollectionProfile, base.RenewalManifestFile = GuidedConfigVersion, "", ""
	return base.Validate()
}
func ParseMacOSInventoryConfig(raw []byte, path string) (MacOSInventoryConfig, error) {
	var c MacOSInventoryConfig
	fields := []string{"schemaVersion", "profile", "managerOrigin", "agentId", "certificateFile", "privateKeyFile", "serverCAFile", "stateDirectory", "insecureHTTPAcknowledged", "collectionProfile", "renewalManifestFile", "consentFile", "originalEnableFile"}
	if len(raw) == 0 || len(raw) > 16384 || lanconfig.StrictObject(raw, &c, fields...) != nil || c.Validate(path) != nil {
		return MacOSInventoryConfig{}, ErrConfiguration
	}
	// Enrollment publishes this exact representation, preventing optional-field
	// spellings or partial/manual configuration from becoming an adoption path.
	want, e := json.MarshalIndent(c, "", "  ")
	if e != nil || !bytes.Equal(raw, want) {
		return MacOSInventoryConfig{}, ErrConfiguration
	}
	return c, nil
}

// IsMacOSInventoryConfig only dispatches to the strict reader; it grants nothing.
func IsMacOSInventoryConfig(path string) (bool, error) {
	raw, e := lanconfig.ReadProtected(path, true, 16384)
	if e != nil {
		return false, ErrConfiguration
	}
	var v struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return false, ErrConfiguration
	}
	if v.SchemaVersion != MacOSInventoryConfigVersion {
		return false, nil
	}
	_, e = ParseMacOSInventoryConfig(raw, path)
	return e == nil, e
}
