package lanclient

import (
	"crypto/sha256"
	"encoding/hex"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanconfig"
	"path/filepath"
)

// ValidateGuidedHandoff is a local, read-only service preflight. Call it as the
// dedicated state owner, never with elevated privileges. It neither collects,
// contacts the manager, initializes a ledger nor removes crash temporaries.
func ValidateGuidedHandoff(path string) error {
	raw, e := lanconfig.ReadProtected(path, true, 16384)
	if e != nil {
		return ErrConfiguration
	}
	var c Config
	if lanconfig.StrictObject(raw, &c, "schemaVersion", "profile", "managerOrigin", "agentId", "certificateFile", "privateKeyFile", "serverCAFile", "stateDirectory", "insecureHTTPAcknowledged") != nil || c.SchemaVersion != GuidedConfigVersion {
		return ErrConfiguration
	}
	m, e := loadConfig(c)
	if e != nil {
		return e
	}
	readyRaw, e := lanconfig.ReadProtected(filepath.Join(filepath.Dir(path), "ready.json"), true, 4096)
	if e != nil {
		return ErrState
	}
	var ready struct {
		Version             string `json:"version"`
		ConfigHash          string `json:"configHash"`
		CertificateHash     string `json:"certificateHash"`
		ServerAuthenticated *bool  `json:"serverAuthenticated"`
	}
	if lanconfig.StrictObject(readyRaw, &ready, "version", "configHash", "certificateHash", "serverAuthenticated") != nil || ready.Version != "tracebolt.enrollment-ready.v2" || ready.ServerAuthenticated == nil || *ready.ServerAuthenticated != (c.Profile == "tls") {
		return ErrState
	}
	h := sha256.Sum256(raw)
	leaf := sha256.Sum256(m.certificate.Certificate[0])
	if ready.ConfigHash != hex.EncodeToString(h[:]) || ready.CertificateHash != hex.EncodeToString(leaf[:]) {
		return ErrState
	}
	if lanclientstate.ValidateExisting(c.StateDirectory, m.binding) != nil {
		return ErrState
	}
	return nil
}
