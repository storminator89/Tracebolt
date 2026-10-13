package lanconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictConfigAndSecretDiagnostics(t *testing.T) {
	for _, raw := range []string{`{"profile":null}`, `{"profile":"tls","profile":"http-test"}`, `{"Profile":"tls"}`, `{"profile":{}}`, `{"profile":true}`, `{"profile":"tls"} {}`} {
		var c Config
		if StrictObject([]byte(raw), &c, "profile") == nil {
			t.Fatalf("accepted ambiguous config")
		}
	}
	var c Config
	if StrictObject([]byte(`{}`), &c, "profile") != nil {
		t.Fatal("documented omitted defaults should parse")
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	m := Material{Server: tls.Certificate{PrivateKey: key}, PasswordHash: "sensitive-fixture-marker"}
	secret := base64.StdEncoding.EncodeToString(key)
	for _, value := range []any{m, &m} {
		b, e := json.Marshal(value)
		if e != nil || string(b) != `{"redacted":true}` {
			t.Fatal("material JSON not redacted")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			out := fmt.Sprintf(format, value)
			if strings.Contains(out, "sensitive-fixture-marker") || strings.Contains(out, secret) {
				t.Fatal("material diagnostic leaked")
			}
		}
	}
}
func TestProtectedFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fixture")
	if os.WriteFile(p, []byte("fixture"), 0600) != nil {
		t.Fatal("fixture write")
	}
	if _, e := ReadProtected(p, true, 20); e != nil {
		t.Fatal("private fixture rejected")
	}
	if _, e := ReadProtected(p, true, 2); e == nil {
		t.Fatal("cap bypass")
	}
	if os.Chmod(p, 0644) != nil {
		t.Fatal("fixture mode")
	}
	if _, e := ReadProtected(p, true, 20); e == nil {
		t.Fatal("shared private file accepted")
	}
	link := filepath.Join(dir, "link")
	if os.Symlink(p, link) != nil {
		t.Fatal("fixture symlink")
	}
	if _, e := ReadProtected(link, false, 20); e == nil {
		t.Fatal("symlink accepted")
	}
	insecure := filepath.Join(dir, "writable")
	os.Mkdir(insecure, 0777)
	os.Chmod(insecure, 0777)
	q := filepath.Join(insecure, "file")
	os.WriteFile(q, []byte("fixture"), 0600)
	if _, e := ReadProtected(q, true, 20); e == nil {
		t.Fatal("replaceable ancestor accepted")
	}
}
func TestProfileValidation(t *testing.T) {
	base := Config{SchemaVersion: SchemaVersion, Profile: HTTPTest, OperatorListen: "127.0.0.1:8080", AgentListen: "127.0.0.1:8081", OperatorOrigin: "http://127.0.0.1:8080", AgentOrigin: "http://127.0.0.1:8081", AgentClientCAFile: "/tmp/ca", OperatorAuthFile: "/tmp/auth", StateDirectory: "/tmp/state", WebDirectory: "/tmp/web", InsecureHTTPAcknowledged: true}
	if base.Validate() != nil {
		t.Fatal("valid explicit test profile rejected")
	}
	changes := []func(*Config){func(c *Config) { c.InsecureHTTPAcknowledged = false }, func(c *Config) { c.TLSPrivateKeyFile = "/tmp/key" }, func(c *Config) { c.OperatorListen = ":8080" }, func(c *Config) { c.OperatorOrigin = "http://localhost:80" }, func(c *Config) { c.OperatorOrigin = "http://evil.test/" }, func(c *Config) { c.OperatorOrigin = "http://localhost@evil.test" }, func(c *Config) { c.AgentClientCAFile = "relative" }, func(c *Config) { c.Profile = "typo" }}
	for _, mutate := range changes {
		c := base
		mutate(&c)
		if c.Validate() == nil {
			t.Fatal("invalid profile accepted")
		}
	}
}

func TestWindowsUpdateJobsConfigurationIsSeparateDefaultOffTLSOnly(t *testing.T) {
	base := Config{SchemaVersion: SchemaVersion, Profile: TLS, OperatorListen: "127.0.0.1:8080", AgentListen: "127.0.0.1:8081", OperatorOrigin: "https://manager.invalid:8080", AgentOrigin: "https://manager.invalid:8081", TLSCertificateFile: "/tmp/cert", TLSPrivateKeyFile: "/tmp/key", AgentClientCAFile: "/tmp/ca", OperatorAuthFile: "/tmp/auth", StateDirectory: "/tmp/state", WebDirectory: "/tmp/web", WindowsInventoryEnabled: true}
	if base.Validate() != nil || base.WindowsUpdateJobsConfigFile != "" {
		t.Fatal("default configuration changed")
	}
	base.WindowsUpdateJobsConfigFile = "/tmp/windows-update-jobs.json"
	if base.Validate() != nil {
		t.Fatal("explicit TLS config rejected")
	}
	for _, change := range []func(*Config){func(c *Config) { c.WindowsInventoryEnabled = false }, func(c *Config) { c.Profile = HTTPTest }, func(c *Config) { c.WindowsUpdateJobsConfigFile = "relative" }, func(c *Config) { c.WindowsUpdateJobsConfigFile = "/tmp/a/../b" }} {
		other := base
		change(&other)
		if other.Validate() == nil {
			t.Fatal("invalid update-job config admitted")
		}
	}
}

func TestWindowsSoftwareJobsConfigurationIsSeparateDefaultOffTLSOnly(t *testing.T) {
	base := Config{SchemaVersion: SchemaVersion, Profile: TLS, OperatorListen: "127.0.0.1:8080", AgentListen: "127.0.0.1:8081", OperatorOrigin: "https://manager.invalid:8080", AgentOrigin: "https://manager.invalid:8081", TLSCertificateFile: "/tmp/cert", TLSPrivateKeyFile: "/tmp/key", AgentClientCAFile: "/tmp/ca", OperatorAuthFile: "/tmp/auth", StateDirectory: "/tmp/state", WebDirectory: "/tmp/web", WindowsInventoryEnabled: true}
	if base.Validate() != nil || base.WindowsSoftwareJobsConfigFile != "" {
		t.Fatal("default configuration changed")
	}
	base.WindowsSoftwareJobsConfigFile = "/tmp/windows-software-jobs.json"
	if base.Validate() != nil {
		t.Fatal("explicit TLS config rejected")
	}
	for _, change := range []func(*Config){func(c *Config) { c.WindowsInventoryEnabled = false }, func(c *Config) { c.Profile = HTTPTest }, func(c *Config) { c.WindowsSoftwareJobsConfigFile = "relative" }, func(c *Config) { c.WindowsSoftwareJobsConfigFile = "/tmp/a/../b" }} {
		other := base
		change(&other)
		if other.Validate() == nil {
			t.Fatal("invalid software-job config admitted")
		}
	}
}

func TestWindowsManagedMSIConfigurationSeparateDefaultOff(t *testing.T) {
	c := Config{SchemaVersion: SchemaVersion, Profile: TLS, OperatorListen: "127.0.0.1:8080", AgentListen: "127.0.0.1:8081", OperatorOrigin: "https://manager.invalid:8080", AgentOrigin: "https://manager.invalid:8081", TLSCertificateFile: "/tmp/cert", TLSPrivateKeyFile: "/tmp/key", AgentClientCAFile: "/tmp/ca", OperatorAuthFile: "/tmp/auth", StateDirectory: "/tmp/state", WebDirectory: "/tmp/web", WindowsInventoryEnabled: true}
	if c.WindowsManagedMSIConfigFile != "" {
		t.Fatal("managed MSI default on")
	}
	c.WindowsManagedMSIConfigFile = "/tmp/managed-msi.json"
	c.WindowsInventoryEnabled = true
	if c.Validate() != nil {
		t.Fatal("explicit TLS path rejected")
	}
	c.Profile = HTTPTest
	if c.Validate() == nil {
		t.Fatal("managed MSI accepted plaintext")
	}
}

// Composition changes only a new activation value; neither staged source is
// rewritten and neither domain config is replaced or promoted.
func TestCoordinatedWindowsMutationActivationKeepsBothReferences(t *testing.T) {
	base := Config{SchemaVersion: SchemaVersion, Profile: TLS, OperatorListen: "127.0.0.1:8080", AgentListen: "127.0.0.1:8081", OperatorOrigin: "https://manager.invalid:8080", AgentOrigin: "https://manager.invalid:8081", TLSCertificateFile: "/protected/cert", TLSPrivateKeyFile: "/protected/key", AgentClientCAFile: "/protected/ca", OperatorAuthFile: "/protected/auth", StateDirectory: "/protected/state", WebDirectory: "/protected/web", WindowsInventoryEnabled: true}
	msi, wua := base, base
	msi.WindowsManagedMSIConfigFile = "/protected/state/windows-managed-msi-setup/manager.json"
	wua.WindowsUpdateJobsConfigFile = "/protected/state/windows-update-setup/manager.json"
	beforeM, _ := json.Marshal(msi)
	beforeW, _ := json.Marshal(wua)
	activation := wua
	activation.WindowsManagedMSIConfigFile = msi.WindowsManagedMSIConfigFile
	raw, _ := json.Marshal(activation)
	var decoded Config
	if json.Unmarshal(raw, &decoded) != nil || decoded.Validate() != nil || decoded.WindowsManagedMSIConfigFile != msi.WindowsManagedMSIConfigFile || decoded.WindowsUpdateJobsConfigFile != wua.WindowsUpdateJobsConfigFile {
		t.Fatal("exact two-domain activation rejected")
	}
	afterM, _ := json.Marshal(msi)
	afterW, _ := json.Marshal(wua)
	if string(beforeM) != string(afterM) || string(beforeW) != string(afterW) {
		t.Fatal("composition rewrote staged inputs")
	}
	decoded.WindowsManagedMSIConfigFile = ""
	decoded.WindowsUpdateJobsConfigFile = ""
	if decoded != base {
		t.Fatal("unrelated activation field changed")
	}
}

func TestMacOSInventoryConfigurationDefaultOffTLSOnly(t *testing.T) {
	c := Config{SchemaVersion: SchemaVersion, Profile: TLS, OperatorListen: "127.0.0.1:8080", AgentListen: "127.0.0.1:8081", OperatorOrigin: "https://manager.invalid:8080", AgentOrigin: "https://manager.invalid:8081", TLSCertificateFile: "/tmp/cert", TLSPrivateKeyFile: "/tmp/key", AgentClientCAFile: "/tmp/ca", OperatorAuthFile: "/tmp/auth", StateDirectory: "/tmp/state", WebDirectory: "/tmp/web"}
	before, _ := json.Marshal(c)
	if c.Validate() != nil || c.MacOSInventoryEnabled || strings.Contains(string(before), "macosInventoryEnabled") {
		t.Fatal("inventory defaults changed")
	}
	c.MacOSInventoryEnabled = true
	if c.Validate() != nil {
		t.Fatal("explicit TLS inventory rejected")
	}
	c.Profile = HTTPTest
	c.OperatorOrigin = "http://manager.invalid:8080"
	c.AgentOrigin = "http://manager.invalid:8081"
	c.TLSCertificateFile, c.TLSPrivateKeyFile = "", ""
	c.InsecureHTTPAcknowledged = true
	if c.Validate() == nil {
		t.Fatal("plaintext inventory admitted")
	}
	c.MacOSInventoryEnabled = false
	if c.Validate() != nil {
		t.Fatal("historical HTTP fixture changed")
	}
}
