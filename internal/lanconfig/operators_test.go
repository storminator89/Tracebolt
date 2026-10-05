package lanconfig

import (
	"encoding/base64"
	"encoding/json"
	"localrmm/internal/operatorauth"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A syntactically valid, deliberately non-login fixture verifier. This test
// only loads protected configuration; it never provisions real credentials.
func operatorConfigHash() string {
	return "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString([]byte("synthetic-salt-12")) + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
}
func namedAuthJSON() string {
	return `{"schemaVersion":"tracebolt.operator-auth.v2","profile":"http-test","operators":[{"id":"operator_0123456789abcdef0123456789abcdef","username":"reader","passwordHash":"` + operatorConfigHash() + `","capabilities":["read","restart_service"]}]}`
}

func TestNamedAuthStrictVersionProfileAndNestedParsing(t *testing.T) {
	valid := namedAuthJSON()
	hash, ops, err := loadOperatorAuth([]byte(valid), HTTPTest)
	if err != nil || hash != "" || len(ops) != 1 || ops[0].Username != "reader" || len(ops[0].Capabilities) != 2 {
		t.Fatal("valid named auth config rejected")
	}
	if _, _, err := loadOperatorAuth([]byte(valid), TLS); err == nil {
		t.Fatal("HTTP auth material reused as production TLS authority")
	}
	legacy := `{"schemaVersion":"tracebolt.operator-auth.v1","profile":"http-test","passwordHash":"` + operatorConfigHash() + `"}`
	if hash, ops, err := loadOperatorAuth([]byte(legacy), HTTPTest); err != nil || hash == "" || ops != nil {
		t.Fatal("v1 shared config compatibility changed")
	}
	for _, raw := range []string{
		valid + `{}`,
		strings.Replace(valid, `"profile":"http-test"`, `"profile":"http-test","profile":"http-test"`, 1),
		strings.Replace(valid, `"profile"`, `"Profile"`, 1),
		strings.Replace(valid, `"operators"`, `"Operators"`, 1),
		strings.Replace(valid, `"username":"reader"`, `"username":"reader","username":"reader"`, 1),
		strings.Replace(valid, `"username"`, `"Username"`, 1),
		strings.Replace(valid, `"username":"reader"`, `"username":null`, 1),
		strings.Replace(valid, `"username":"reader"`, `"username":{"name":"reader"}`, 1),
		strings.Replace(valid, `"capabilities":["read","restart_service"]`, `"capabilities":["read","read"]`, 1),
		strings.Replace(valid, `"capabilities":["read","restart_service"]`, `"capabilities":["read",null]`, 1),
		strings.Replace(valid, `"capabilities":["read","restart_service"]`, `"capabilities":["read","admin"]`, 1),
		strings.Replace(valid, `"capabilities":["read","restart_service"]`, `"capabilities":["restart_service"]`, 1),
		strings.Replace(valid, `"capabilities":["read","restart_service"]`, `"capabilities":null`, 1),
		strings.Replace(valid, `"capabilities":["read","restart_service"]`, `"capabilities":[]`, 1),
		strings.Replace(valid, `"capabilities"`, `"capability"`, 1),
		strings.Replace(valid, `"schemaVersion":"tracebolt.operator-auth.v2"`, `"schemaVersion":"tracebolt.operator-auth.v3"`, 1),
		strings.Replace(valid, `"schemaVersion":"tracebolt.operator-auth.v2"`, `"schemaVersion":"tracebolt.operator-auth.v1"`, 1),
		strings.Replace(valid, `"profile":"http-test"`, `"passwordHash":"extra","profile":"http-test"`, 1),
		strings.Replace(valid, `"profile":"http-test"`, `"allowLegacy":true,"profile":"http-test"`, 1),
		strings.Replace(valid, `"operators":[{`, `"operators":[null,{`, 1),
		`{"schemaVersion":"tracebolt.operator-auth.v2","profile":"http-test","operators":[]}`,
		`{"schemaVersion":"tracebolt.operator-auth.v2","profile":"http-test","operators":null}`,
		`{"schemaVersion":"tracebolt.operator-auth.v2","profile":"http-test"}`,
		strings.Replace(valid, `"reader"`, `"r\ufffd"`, 1),
	} {
		if _, _, err := loadOperatorAuth([]byte(raw), HTTPTest); err == nil {
			t.Fatal("ambiguous or unsupported named auth config accepted")
		}
	}
}

func TestNamedProtectedConfigLoadAndSnapshotIsolation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux protected manager configuration contract")
	}
	dir := t.TempDir()
	write := func(name string, raw []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, mode); err != nil {
			t.Fatal("fixture write failed")
		}
		return path
	}
	authPath := write("fixture-auth.json", []byte(namedAuthJSON()), 0600)
	c := Config{SchemaVersion: SchemaVersion, Profile: HTTPTest, OperatorListen: "127.0.0.1:8080", AgentListen: "127.0.0.1:8081", OperatorOrigin: "http://127.0.0.1:8080", AgentOrigin: "http://127.0.0.1:8081", AgentClientCAFile: write("fixture-ca.pem", []byte("fixture-public-ca"), 0644), OperatorAuthFile: authPath, StateDirectory: filepath.Join(dir, "state"), WebDirectory: dir, InsecureHTTPAcknowledged: true}
	raw, _ := json.Marshal(c)
	path := write("config.json", raw, 0600)
	m, err := Load(path)
	if err != nil || m.PasswordHash != "" || len(m.Operators) != 1 {
		t.Fatal("protected v2 load failed")
	}
	auth, err := operatorauth.New(operatorauth.Config{Operators: m.Operators})
	if err != nil || !auth.Named() {
		t.Fatal("loaded named auth not usable")
	}
	serialized, _ := json.Marshal(m)
	if strings.Contains(string(serialized), operatorConfigHash()) || strings.Contains(string(serialized), "reader") {
		t.Fatal("material diagnostics leaked named credentials")
	}
	if err := os.Chmod(authPath, 0644); err != nil {
		t.Fatal("fixture chmod failed")
	}
	if _, err := Load(path); err == nil {
		t.Fatal("publicly readable named config accepted")
	}
	if err := os.Chmod(authPath, 0600); err != nil {
		t.Fatal("fixture chmod failed")
	}
	link := filepath.Join(dir, "auth-link.json")
	if err := os.Symlink(authPath, link); err != nil {
		t.Fatal("fixture symlink failed")
	}
	c.OperatorAuthFile = link
	raw, _ = json.Marshal(c)
	write("config.json", raw, 0600)
	if _, err := Load(path); err == nil {
		t.Fatal("symlink named config accepted")
	}
}
