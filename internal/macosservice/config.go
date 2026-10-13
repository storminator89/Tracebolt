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
// silently adopted into the fixed basic-only LaunchDaemon candidate.
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
