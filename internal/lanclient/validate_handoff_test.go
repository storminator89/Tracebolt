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
)

func TestValidateGuidedHandoffIsLocalAndPreservesState(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			var calls atomic.Int32
			f := integrationFixture(t, profile, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); next.ServeHTTP(w, r) })
			})
			c := f.material.config
			c.SchemaVersion = GuidedConfigVersion
			if InitializeGuidedState(c) != nil {
				t.Fatal("initialize fixture")
			}
			dir := filepath.Dir(c.PrivateKeyFile)
			path := filepath.Join(dir, "agent.json")
			raw, _ := json.Marshal(c)
			if os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("config")
			}
			h := sha256.Sum256(raw)
			leaf := sha256.Sum256(f.material.certificate.Certificate[0])
			ready := map[string]any{"version": "tracebolt.enrollment-ready.v2", "configHash": hex.EncodeToString(h[:]), "certificateHash": hex.EncodeToString(leaf[:]), "serverAuthenticated": profile == "tls"}
			write := func() {
				b, _ := json.Marshal(ready)
				if os.WriteFile(filepath.Join(dir, "ready.json"), b, 0600) != nil {
					t.Fatal("ready")
				}
			}
			write()
			sentinel := filepath.Join(c.StateDirectory, ".state.tmp")
			if os.WriteFile(sentinel, []byte("retained temporary"), 0600) != nil {
				t.Fatal("temporary")
			}
			if ValidateGuidedHandoff(path) != nil {
				t.Fatal("valid local handoff rejected")
			}
			if b, e := os.ReadFile(sentinel); e != nil || string(b) != "retained temporary" {
				t.Fatal("validation cleaned state")
			}
			ready["certificateHash"] = "wrong"
			write()
			if ValidateGuidedHandoff(path) == nil {
				t.Fatal("bad marker accepted")
			}
			delete(ready, "serverAuthenticated")
			write()
			if ValidateGuidedHandoff(path) == nil {
				t.Fatal("missing field accepted")
			}
			if calls.Load() != 0 {
				t.Fatal("validation sent a request")
			}
		})
	}
}
