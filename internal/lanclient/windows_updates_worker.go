package lanclient

import (
	"crypto/sha256"
	"encoding/hex"
	"localrmm/internal/lanconfig"
	"localrmm/internal/windowsupdates"
	"path/filepath"
)

// ValidateWindowsUpdatesWorkerRequest authenticates the fixed installed activated
// identity and separate protected grant. The caller derives path from the owned
// runtime layout; no path is accepted over worker IPC. This deliberately does
// not acquire the sender ledger: its parent owns that lock throughout capture.
func ValidateWindowsUpdatesWorkerRequest(path string, request windowsupdates.Request) (windowsupdates.Request, error) {
	m, err := Load(path)
	if err != nil || !m.config.windowsInventory() || m.binding != request.SenderBinding || validateUpdatesActivatedMaterial(path, m) != nil {
		return windowsupdates.Request{}, ErrState
	}
	c, ok := readWindowsUpdatesConsent(m)
	if !ok || c != request.Consent || !validUpdatesConsent(c, m.binding) {
		return windowsupdates.Request{}, ErrState
	}
	return request, nil
}

func validateUpdatesActivatedMaterial(path string, m Material) error {
	raw, err := lanconfig.ReadProtected(path, true, 16384)
	if err != nil {
		return ErrState
	}
	readyRaw, err := lanconfig.ReadProtected(filepath.Join(filepath.Dir(path), "ready.json"), true, 4096)
	if err != nil {
		return ErrState
	}
	return validateUpdatesActivatedBytes(raw, readyRaw, m)
}

func validateUpdatesActivatedBytes(raw, readyRaw []byte, m Material) error {
	var current Config
	if decodeConfig(raw, &current) != nil || current != m.config || len(m.authorityDER()) == 0 {
		return ErrState
	}
	var ready struct {
		Version             string `json:"version"`
		ConfigHash          string `json:"configHash"`
		CertificateHash     string `json:"certificateHash"`
		ServerAuthenticated *bool  `json:"serverAuthenticated"`
	}
	if lanconfig.StrictObject(readyRaw, &ready, "version", "configHash", "certificateHash", "serverAuthenticated") != nil || ready.Version != "tracebolt.enrollment-ready.v2" || ready.ServerAuthenticated == nil || *ready.ServerAuthenticated != (m.config.Profile == "tls") {
		return ErrState
	}
	configHash := sha256.Sum256(raw)
	certHash := sha256.Sum256(m.authorityDER())
	if ready.ConfigHash != hex.EncodeToString(configHash[:]) || ready.CertificateHash != hex.EncodeToString(certHash[:]) {
		return ErrState
	}
	return nil
}
