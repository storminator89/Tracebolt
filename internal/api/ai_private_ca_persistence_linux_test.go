//go:build linux

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"localrmm/internal/aiconfig"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateLANCAIsNeverPersisted(t *testing.T) {
	o := newOperatorFixture(t, 0)
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	settings, err := aiconfig.New(dir, "manager-fixture", "tls")
	if err != nil {
		t.Fatal(err)
	}
	if err = o.app.configurePersistentAI(settings, true); err != nil {
		t.Fatal(err)
	}
	ca, _, _, _ := operatorCertificates(t)
	block, _ := pem.Decode(ca)
	sum := sha256.Sum256(block.Bytes)
	hash := hex.EncodeToString(sum[:])
	body := lanBody(o.app.ai.config.Revision)
	body["caPem"] = string(ca)
	body["expectedCaSha256"] = hash
	body["acknowledgeCaFingerprint"] = true
	r, _ := o.call(t, "POST", "/api/ai/config/lan-private-ca", body, csrf, nil)
	if r.StatusCode != 200 {
		t.Fatal("pin import rejected", r.StatusCode)
	}
	snapshot, err := settings.Snapshot()
	if err != nil || snapshot.Configured || snapshot.Scope.Enabled {
		t.Fatal("saved provider or scope", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(content), string(ca)) || strings.Contains(string(content), hash) {
			t.Fatal("private CA pin leaked to persistent storage")
		}
	}
}
