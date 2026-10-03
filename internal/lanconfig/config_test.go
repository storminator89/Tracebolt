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
