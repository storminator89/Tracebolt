package security_test

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"localrmm/internal/lanconfig"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestIndependentLANMaterialDoesNotSerializePrivateKey(t *testing.T) {
	ca := makeReviewCA(t)
	pair, _ := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Time{})
	material := lanconfig.Material{Server: pair, PasswordHash: "synthetic-password-hash"}
	for _, value := range []any{material, &material} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "PrivateKey") || strings.Contains(string(raw), "synthetic-password-hash") {
			t.Fatal("key-bearing material is JSON-serializable")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if !strings.Contains(fmt.Sprintf(format, value), "secrets:redacted") {
				t.Fatal("material formatting lacks redaction")
			}
		}
	}
}

func TestIndependentLANProtectedProfileAndServerIdentity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux manager protected-file contract")
	}
	dir := t.TempDir()
	ca := makeReviewCA(t)
	pair, cert := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Time{})
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if e := os.WriteFile(path, raw, mode); e != nil {
			t.Fatal(e)
		}
		return path
	}
	certPath := write("server.pem", cert, 0644)
	keyPath := write("synthetic-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600)
	caPath := write("ca.pem", ca.pem, 0644)
	auth, _ := json.Marshal(map[string]string{"schemaVersion": "tracebolt.operator-auth.v1", "profile": "tls", "passwordHash": reviewPasswordHash()})
	authPath := write("synthetic-auth.json", auth, 0600)
	c := lanconfig.Config{SchemaVersion: lanconfig.SchemaVersion, Profile: lanconfig.TLS, OperatorListen: "127.0.0.1:19443", AgentListen: "127.0.0.1:19444", OperatorOrigin: "https://127.0.0.1:19443", AgentOrigin: "https://127.0.0.1:19444", TLSCertificateFile: certPath, TLSPrivateKeyFile: keyPath, AgentClientCAFile: caPath, OperatorAuthFile: authPath, StateDirectory: filepath.Join(dir, "private"), WebDirectory: dir}
	configPath := filepath.Join(dir, "config.json")
	load := func(c lanconfig.Config) error {
		t.Helper()
		raw, _ := json.Marshal(c)
		if e := os.WriteFile(configPath, raw, 0600); e != nil {
			t.Fatal(e)
		}
		_, e := lanconfig.Load(configPath)
		return e
	}
	if err = load(c); err != nil {
		t.Fatal("protected synthetic TLS profile failed")
	}
	wrong := c
	wrong.AgentOrigin = "https://127.0.0.2:19444"
	if load(wrong) == nil {
		t.Fatal("server certificate SAN mismatch accepted")
	}
	wrong = c
	wrong.Profile = lanconfig.HTTPTest
	wrong.InsecureHTTPAcknowledged = true
	wrong.OperatorOrigin = "http://127.0.0.1:19443"
	wrong.AgentOrigin = "http://127.0.0.1:19444"
	wrong.TLSCertificateFile = ""
	wrong.TLSPrivateKeyFile = ""
	if load(wrong) == nil {
		t.Fatal("TLS auth material reused in plaintext profile")
	}
	if err = os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if load(c) == nil {
		t.Fatal("group/world-readable server key accepted")
	}
	if err = os.Chmod(keyPath, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "key-link.pem")
	if err = os.Symlink(keyPath, link); err != nil {
		t.Fatal(err)
	}
	wrong = c
	wrong.TLSPrivateKeyFile = link
	if load(wrong) == nil {
		t.Fatal("symlink key path accepted")
	}
}
