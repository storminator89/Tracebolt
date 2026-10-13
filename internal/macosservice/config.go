package macosservice

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/lanconfig"
	"localrmm/internal/renewalidentity"
)

// This prefilter is separate from the credential/ready/ledger validator. It
// prevents a broader supported schema or a different private path from being
// silently adopted into the fixed basic LaunchDaemon candidate.
func validateBasicConfig(raw []byte) error {
	var c lanclient.Config
	fields := []string{"schemaVersion", "profile", "managerOrigin", "agentId", "certificateFile", "privateKeyFile", "serverCAFile", "stateDirectory", "insecureHTTPAcknowledged", "collectionProfile"}
	var version struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if json.Unmarshal(raw, &version) != nil {
		return ErrPreflight
	}
	if version.SchemaVersion == lanclient.RenewalConfigVersion {
		fields = append(fields, "renewalManifestFile")
	}
	if lanconfig.StrictObject(raw, &c, fields...) != nil {
		return ErrPreflight
	}
	basic := c.SchemaVersion == lanclient.GuidedConfigVersion && c.CollectionProfile == "" && c.RenewalManifestFile == ""
	renewable := c.SchemaVersion == lanclient.RenewalConfigVersion && c.CollectionProfile == enrollmentcrypto.CollectionProfile && c.RenewalManifestFile == EnrollmentDirectory+"/"+renewalidentity.ManifestName
	if (!basic && !renewable) || c.Profile != "tls" || c.InsecureHTTPAcknowledged || c.CertificateFile != EnrollmentDirectory+"/agent-cert.pem" || c.PrivateKeyFile != EnrollmentDirectory+"/agent-key.pem" || c.ServerCAFile != EnrollmentDirectory+"/server-ca.pem" || c.StateDirectory != EnrollmentDirectory+"/telemetry" || c.Validate() != nil {
		return ErrPreflight
	}
	return nil
}

// Profile selection is explicit and never inferred from a broader config. The
// strict fresh inventory parser retains exact consent/enable/renewal paths and
// canonical enrollment bytes; accepting syntax alone creates no local grant.
func validateSelectedConfig(raw []byte, profile string) error {
	if len(raw) == 0 || len(raw) > 16384 {
		return ErrPreflight
	}
	switch profile {
	case BasicProfile:
		return validateBasicConfig(raw)
	case InventoryProfile:
		if _, err := lanclient.ParseMacOSInventoryConfig(raw, ConfigPath); err == nil {
			return nil
		}
	}
	return ErrPreflight
}

func validateSelectedHandoff(raw []byte, profile string, basic, inventory func(string) error) error {
	if validateSelectedConfig(raw, profile) != nil {
		return ErrPreflight
	}
	validator := basic
	if profile == InventoryProfile {
		validator = inventory
	}
	if validator == nil || validator(ConfigPath) != nil {
		return ErrPreflight
	}
	return nil
}
