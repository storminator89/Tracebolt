//go:build linux

package lanclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"localrmm/internal/lanclientstate"
)

// Portable regression for the actual handoff dependency used by Windows
// completion verification. Only a temporary synthetic sender/fixture is used;
// this does not exercise Windows locks or native installation acceptance.
func TestGuidedHandoffRejectsLiveSenderUntilStopped(t *testing.T) {
	var requests atomic.Int32
	fixture := integrationFixture(t, "tls", func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); next.ServeHTTP(w, r) })
	})
	config := fixture.material.config
	config.SchemaVersion = GuidedConfigVersion
	if InitializeGuidedState(config) != nil {
		t.Fatal("fixture state")
	}
	material, err := loadConfig(config)
	if err != nil {
		t.Fatal("fixture material")
	}
	dir := filepath.Dir(config.PrivateKeyFile)
	path := filepath.Join(dir, "agent.json")
	raw, _ := json.Marshal(config)
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("fixture config")
	}
	configHash := sha256.Sum256(raw)
	certHash := sha256.Sum256(material.certificate.Certificate[0])
	ready, _ := json.Marshal(map[string]any{"version": "tracebolt.enrollment-ready.v2", "configHash": hex.EncodeToString(configHash[:]), "certificateHash": hex.EncodeToString(certHash[:]), "serverAuthenticated": true})
	if os.WriteFile(filepath.Join(dir, "ready.json"), ready, 0600) != nil {
		t.Fatal("fixture ready")
	}
	if ValidateGuidedHandoff(path) != nil {
		t.Fatal("stopped fixture rejected")
	}
	sender, err := openSenderState(material)
	if err != nil {
		t.Fatal("fixture sender")
	}
	defer sender.Close()
	before, err := os.ReadFile(filepath.Join(config.StateDirectory, "state.json"))
	if err != nil {
		t.Fatal("fixture ledger")
	}
	for i := 0; i < 3; i++ {
		if ValidateGuidedHandoff(path) == nil {
			t.Fatal("live sender lock bypassed")
		}
		if lanclientstate.ValidateExisting(config.StateDirectory, material.binding) == nil {
			t.Fatal("exclusive ledger lock bypassed")
		}
	}
	if sender.Close() != nil {
		t.Fatal("fixture close")
	}
	if ValidateGuidedHandoff(path) != nil {
		t.Fatal("released sender rejected")
	}
	after, err := os.ReadFile(filepath.Join(config.StateDirectory, "state.json"))
	if err != nil || string(before) != string(after) || requests.Load() != 0 {
		t.Fatal("read-only reproduction modified or transmitted state")
	}
}
