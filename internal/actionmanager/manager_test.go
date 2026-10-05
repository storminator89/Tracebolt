package actionmanager

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentstore"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func signerFixture(t *testing.T) *Manager {
	t.Helper()
	d := t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32))
	kp := filepath.Join(d, "command.key")
	if e := os.WriteFile(kp, key, 0600); e != nil {
		t.Fatal(e)
	}
	cfg := Config{Version: ConfigVersion, Enabled: true, ManagerID: "manager_" + strings.Repeat("1", 32), TransportProfile: actionhelper.ProductionTLS, PrivateKeyFile: kp}
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(d, "actions.json")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return &Manager{store: &enrollmentstore.Store{}, config: cfg, path: path, raw: raw, key: &signingKey{bytes: key}, now: func() time.Time { return time.Now().UTC() }}
}
func permitFixture(m *Manager) actionpermit.Permit {
	d := actionpermit.Digest(nil)
	plan := actionpermit.Plan{Version: actionpermit.PlanVersion, Action: actionpermit.TryRestartService, Unit: "fixture.service", UnitPolicyDigest: d}
	pd, _ := actionpermit.PlanDigest(plan)
	return actionpermit.Permit{Version: actionpermit.Version, ManagerID: m.config.ManagerID, KeyID: actionpermit.Digest(m.keyPublic()), EndpointID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: d, JobID: "action_" + strings.Repeat("3", 32), Sequence: 1, Plan: plan, PlanDigest: pd, OperatorID: "operator_" + strings.Repeat("4", 32), ApprovalDigest: d, RootPolicyDigest: d, IssuedAt: 100, NotBefore: 100, StartDeadline: 160}
}
func TestSignerProtectedInputsRecheckedBeforeSigning(t *testing.T) {
	for _, change := range []string{"config-revoke", "config-permission", "key-replace", "key-remove", "key-symlink"} {
		t.Run(change, func(t *testing.T) {
			m := signerFixture(t)
			p := permitFixture(m)
			if _, e := m.sign(p); e != nil {
				t.Fatal(e)
			}
			switch change {
			case "config-revoke":
				os.WriteFile(m.path, []byte(`{"enabled":false}`), 0600)
			case "config-permission":
				os.Chmod(m.path, 0644)
			case "key-replace":
				os.WriteFile(m.config.PrivateKeyFile, bytes.Repeat([]byte{19}, 64), 0600)
			case "key-remove":
				os.Remove(m.config.PrivateKeyFile)
			case "key-symlink":
				os.Rename(m.config.PrivateKeyFile, m.config.PrivateKeyFile+".old")
				os.Symlink(m.config.PrivateKeyFile+".old", m.config.PrivateKeyFile)
			}
			if b, e := m.sign(p); e == nil || len(b) != 0 {
				t.Fatal("signer ignored revoked input")
			}
		})
	}
}
func TestSignerConfigurationIsExplicitAndProfileBound(t *testing.T) {
	m := signerFixture(t)
	if !validConfig(m.config) {
		t.Fatal("valid config")
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Enabled = false }, func(c *Config) { c.TransportProfile = "http-test" }, func(c *Config) { c.HTTPTestAcknowledged = true }, func(c *Config) { c.PrivateKeyFile = "relative.key" }, func(c *Config) { c.ManagerID = "host" }} {
		c := m.config
		mutate(&c)
		if validConfig(c) {
			t.Fatal("unsafe config")
		}
	}
	c := m.config
	c.TransportProfile = actionhelper.DisposableHTTPTest
	if validConfig(c) {
		t.Fatal("http without ack")
	}
	c.HTTPTestAcknowledged = true
	if !validConfig(c) {
		t.Fatal("explicit disposable profile rejected")
	}
}
func TestSignerFormattingAndCloseRedactKey(t *testing.T) {
	m := signerFixture(t)
	b, e := json.Marshal(m)
	if e != nil || strings.Contains(string(b), "privateKeyFile") || strings.Contains(fmt.Sprintf("%#v", *m), m.config.PrivateKeyFile) {
		t.Fatal("secret formatting")
	}
	m.Close()
	if _, e = m.sign(permitFixture(m)); e == nil {
		t.Fatal("closed signer active")
	}
}

func TestSignerCloseConcurrentWithSigningAndReads(t *testing.T) {
	m := signerFixture(t)
	p := permitFixture(m)
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 50; k++ {
				_, _ = m.sign(p)
				_ = m.keyPublic()
				_ = m.Available()
			}
		}()
	}
	m.Close()
	wg.Wait()
	if b, e := m.sign(p); e == nil || len(b) > 0 || len(m.keyPublic()) > 0 {
		t.Fatal("closed key usable")
	}
}
