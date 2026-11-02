package packagecontroller

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePackageConfigInventoriesWithoutOpeningDependencies(t *testing.T) {
	dir := t.TempDir()
	c := Config{Version: ConfigVersion, Enabled: true, ManagerID: "manager_" + strings.Repeat("a", 32), EndpointID: "agent_" + strings.Repeat("b", 32), IncarnationDigest: "sha256:" + strings.Repeat("c", 64), RootPolicyDigest: "sha256:" + strings.Repeat("d", 64), TransportProfile: "production-tls", StateFile: filepath.Join(dir, "absent-state"), PrivateKeyFile: filepath.Join(dir, "absent-key"), LocalScopeAcknowledged: true}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseConfig(raw)
	if err != nil || got != c {
		t.Fatalf("configuration-only parse failed: %v", err)
	}
	for _, path := range []string{c.StateFile, c.PrivateKeyFile} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("configuration-only parsing materialized a dependency")
		}
	}
	// Preserve the existing parser's disabled-configuration semantics exactly;
	// parsing never constitutes a grant or substitutes for runtime admission.
	c.Enabled = false
	raw, _ = json.Marshal(c)
	if got, err = ParseConfig(raw); err != nil || got != c {
		t.Fatal("existing configuration semantics changed")
	}
	for _, change := range []func(string) string{
		func(s string) string { return strings.Replace(s, `"stateFile":`, `"StateFile":`, 1) },
		func(s string) string {
			return strings.Replace(s, `"enabled":false`, `"enabled":false,"enabled":true`, 1)
		},
		func(s string) string {
			return strings.Replace(s, `"localScopeAcknowledged":true`, `"localScopeAcknowledged":false`, 1)
		},
	} {
		if got, err = ParseConfig([]byte(change(string(raw)))); err != ErrConfiguration || got != (Config{}) {
			t.Fatal("invalid configuration escaped the shared boundary")
		}
	}
	// The filesystem read bound is also enforced for in-memory callers.
	padding := bytes.Repeat([]byte(" "), MaxConfigBytes-len(raw))
	if _, err = ParseConfig(append(append([]byte(nil), raw...), padding...)); err != nil {
		t.Fatal("exact byte limit rejected")
	}
	if got, err = ParseConfig(append(append(raw, padding...), ' ')); err != ErrConfiguration || got != (Config{}) {
		t.Fatal("oversized configuration accepted")
	}
}
