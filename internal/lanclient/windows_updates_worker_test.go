//go:build linux

package lanclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestWindowsUpdatesWorkerActivatedReceiptBinding(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	raw, _ := json.Marshal(m.config)
	ch := sha256.Sum256(raw)
	cert := sha256.Sum256(m.certificate.Certificate[0])
	ready := map[string]any{"version": "tracebolt.enrollment-ready.v2", "configHash": hex.EncodeToString(ch[:]), "certificateHash": hex.EncodeToString(cert[:]), "serverAuthenticated": false}
	readyRaw, _ := json.Marshal(ready)
	if validateUpdatesActivatedBytes(raw, readyRaw, m) != nil {
		t.Fatal("valid activated receipt rejected")
	}
	for key, value := range map[string]any{"version": "tracebolt.enrollment-ready.v1", "configHash": strings.Repeat("f", 64), "certificateHash": strings.Repeat("f", 64), "serverAuthenticated": true, "extra": true} {
		copied := map[string]any{}
		for k, v := range ready {
			copied[k] = v
		}
		copied[key] = value
		bad, _ := json.Marshal(copied)
		if validateUpdatesActivatedBytes(raw, bad, m) == nil {
			t.Fatal("foreign/partial receipt admitted", key)
		}
	}
	changed := m.config
	changed.AgentID += "changed"
	bad, _ := json.Marshal(changed)
	hash := sha256.Sum256(bad)
	ready["configHash"] = hex.EncodeToString(hash[:])
	readyRaw, _ = json.Marshal(ready)
	if validateUpdatesActivatedBytes(bad, readyRaw, m) == nil {
		t.Fatal("configuration changed between reads")
	}
	if validateUpdatesActivatedBytes(raw, []byte(`{}`), m) == nil || validateUpdatesActivatedBytes(raw, readyRaw, Material{}) == nil {
		t.Fatal("missing identity admitted")
	}
}
