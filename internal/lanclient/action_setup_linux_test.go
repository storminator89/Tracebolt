//go:build linux

package lanclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/inventorystate"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/systemstate"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
)

func setupIdentityFixture(t *testing.T, profile string) (string, Material, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	f := integrationFixture(t, profile, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); next.ServeHTTP(w, r) })
	})
	c := completeConfig(f.material.config)
	if InitializeGuidedState(c) != nil {
		t.Fatal("initialize complete fixture")
	}
	m, err := loadConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(c.PrivateKeyFile), "agent.json")
	raw, _ := json.Marshal(c)
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("config fixture")
	}
	hash := sha256.Sum256(raw)
	ready, _ := json.Marshal(map[string]any{"version": "tracebolt.enrollment-ready.v2", "configHash": hex.EncodeToString(hash[:]), "certificateHash": journalLeaf(m), "serverAuthenticated": profile == "tls"})
	if os.WriteFile(filepath.Join(filepath.Dir(path), "ready.json"), ready, 0600) != nil {
		t.Fatal("ready fixture")
	}
	return path, m, calls
}

func setupSnapshot(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	snapshot := map[string][]byte{}
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			snapshot[path] = b
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// The fixture reader and projection are useful to test under any ordinary test
// account. The public reader additionally requires the narrower service-process
// identity, which a developer or hosted runner may not have. Always exercise
// both paths; the dedicated CI gate requires the real public-reader evidence.
func readSetupFixtureIdentity(t *testing.T, path string) (ActionSetupIdentity, error) {
	t.Helper()
	m, err := loadActionSetupMaterial(path)
	got, publicErr := ReadActionSetupIdentity(path)
	uid, gid, serviceProcess := journalAgentIdentity()
	if !serviceProcess {
		if publicErr != errActionDenied || got != (ActionSetupIdentity{}) {
			t.Fatal("public reader accepted a non-service process")
		}
	} else if err != nil {
		if !errors.Is(publicErr, err) || got != (ActionSetupIdentity{}) {
			t.Fatal("public reader did not preserve fixture rejection")
		}
		if err == ErrState {
			t.Log("action setup identity: public_reader=state_rejected")
		}
	} else {
		if publicErr != nil || got != projectActionSetupIdentity(m, uid, gid) {
			t.Fatal("public reader rejected or changed the service identity")
		}
		t.Log("action setup identity: public_reader=accepted")
	}
	if err != nil {
		return ActionSetupIdentity{}, err
	}
	return projectActionSetupIdentity(m, uint32(os.Geteuid()), uint32(os.Getegid())), nil
}

func TestActionSetupIdentityLocalCompleteAndNoWrites(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			path, m, calls := setupIdentityFixture(t, profile)
			before := setupSnapshot(t, filepath.Dir(path))
			identity, err := readSetupFixtureIdentity(t, path)
			if err != nil {
				t.Fatal(err)
			}
			if identity.SenderBinding != m.binding || identity.IncarnationDigest != "sha256:"+journalLeaf(m) || identity.ManagerOrigin != m.config.ManagerOrigin || identity.EndpointID != m.config.AgentID || identity.AgentUID != uint32(os.Geteuid()) || identity.AgentGID != uint32(os.Getegid()) || identity.TransportProfile != actionProfile(m) {
				t.Fatal(identity)
			}
			raw, _ := json.Marshal(identity)
			for _, secret := range [][]byte{[]byte(m.config.PrivateKeyFile), []byte(m.config.StateDirectory), []byte("PRIVATE KEY"), []byte("certificateFile")} {
				if bytes.Contains(raw, secret) {
					t.Fatal("private projection")
				}
			}
			if !reflect.DeepEqual(before, setupSnapshot(t, filepath.Dir(path))) || calls.Load() != 0 {
				t.Fatal("identity probe wrote or contacted manager")
			}
		})
	}
}

func TestActionSetupIdentityRejectsMissingActivationOrLedgers(t *testing.T) {
	for _, missing := range []string{"ready.json", "state/state.json", "state/inventory", "state/system"} {
		t.Run(missing, func(t *testing.T) {
			path, m, calls := setupIdentityFixture(t, "http-test")
			remove := filepath.Join(filepath.Dir(path), "ready.json")
			switch missing {
			case "state/state.json":
				remove = filepath.Join(m.config.StateDirectory, "state.json")
			case "state/inventory":
				remove = inventoryStateDirectory(m.config)
			case "state/system":
				remove = systemStateDirectory(m.config)
			}
			if os.Rename(remove, remove+"-preserved") != nil {
				t.Fatal("fixture remove")
			}
			before := setupSnapshot(t, filepath.Dir(path))
			if _, err := readSetupFixtureIdentity(t, path); err != ErrState {
				t.Fatal("incomplete sender did not reach the state check")
			}
			if !reflect.DeepEqual(before, setupSnapshot(t, filepath.Dir(path))) || calls.Load() != 0 {
				t.Fatal("failure repaired state or contacted manager")
			}
		})
	}
}

func TestActionSetupIdentityWorksWhileSenderOwnsAllLedgers(t *testing.T) {
	path, m, calls := setupIdentityFixture(t, "http-test")
	metrics, err := lanclientstate.OpenExisting(m.config.StateDirectory, m.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer metrics.Close()
	inventory, err := inventorystate.OpenExisting(inventoryStateDirectory(m.config), m.binding, m.config.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	defer inventory.Close()
	system, err := systemstate.OpenExisting(systemStateDirectory(m.config), systemStateBinding(m))
	if err != nil {
		t.Fatal(err)
	}
	defer system.Close()
	before := setupSnapshot(t, filepath.Dir(path))
	got, err := readSetupFixtureIdentity(t, path)
	if err != nil || got.SenderBinding != m.binding {
		t.Fatal("active sender probe rejected", err)
	}
	if !reflect.DeepEqual(before, setupSnapshot(t, filepath.Dir(path))) || calls.Load() != 0 {
		t.Fatal("probe mutated sender or contacted manager")
	}
}
