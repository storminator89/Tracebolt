//go:build linux

package enrollmentconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMacOSInventoryDatabaseFragmentsRejectFreshOrManualAdoption(t *testing.T) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		t.Run("fragment"+suffix, func(t *testing.T) {
			c, lan, path, now := profileFixture(t)
			raw, _ := json.Marshal(c)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			m, err := Load(path, lan, now)
			if err != nil {
				t.Fatal(err)
			}
			fragment := filepath.Join(lan.Config.StateDirectory, MacOSInventoryDatabaseFile+suffix)
			if err = os.WriteFile(fragment, []byte("retained fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			if RejectEnrollmentMode(lan.Config.StateDirectory) == nil || m.PrepareMode(lan.Config.StateDirectory, 0) == nil {
				t.Fatal("Mac fragment adopted")
			}
			if _, err = os.Stat(filepath.Join(lan.Config.StateDirectory, ModeFile)); !os.IsNotExist(err) {
				t.Fatal("failed admission created marker")
			}
			after, err := os.ReadFile(fragment)
			if err != nil || string(after) != "retained fixture" {
				t.Fatal("rejection modified state")
			}
		})
	}
}

// These marker-interruption fixtures reuse an in-memory disposable issuer. The
// full protected TLS config loader is exercised by the closed manager tests.
func macOSInventoryModeFixture(t *testing.T) Material {
	t.Helper()
	c, lan, path, now := profileFixture(t)
	raw, _ := json.Marshal(c)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	m, err := Load(path, lan, now)
	if err != nil {
		t.Fatal(err)
	}
	m.value.config.Profile = lanconfig.TLS
	m.value.lan.Profile = lanconfig.TLS
	m.value.lan.OperatorOrigin = "https://127.0.0.1:8443"
	m.value.lan.AgentOrigin = "https://127.0.0.1:8444"
	m.value.lan.MacOSInventoryEnabled = true
	if err = m.PrepareMode(lan.Config.StateDirectory, 0); err != nil {
		t.Fatal(err)
	}
	return m
}
func macOSInventoryStateBytes(t *testing.T, dir string) map[string]string {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[file.Name()] = string(raw)
	}
	return out
}
func TestMacOSInventoryExistingPrimaryRejectsEveryOrphanFragment(t *testing.T) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		t.Run("fragment"+suffix, func(t *testing.T) {
			m := macOSInventoryModeFixture(t)
			dir := m.value.lan.StateDirectory
			fragment := filepath.Join(dir, MacOSInventoryDatabaseFile+suffix)
			if err := os.WriteFile(fragment, []byte("retained fragment"), 0600); err != nil {
				t.Fatal(err)
			}
			before := macOSInventoryStateBytes(t, dir)
			if m.PrepareMode(dir, 0) == nil {
				t.Fatal("existing primary adopted orphan Mac fragment")
			}
			if store, err := m.OpenMacOSInventoryStore(dir); err == nil {
				store.Close()
				t.Fatal("orphan Mac fragment initialized")
			}
			if !reflect.DeepEqual(before, macOSInventoryStateBytes(t, dir)) {
				t.Fatal("orphan rejection changed state")
			}
		})
	}
}
func TestMacOSInventoryReadyFenceReopensAndNeverRecreatesMissingLedger(t *testing.T) {
	m := macOSInventoryModeFixture(t)
	dir := m.value.lan.StateDirectory
	primary, _ := os.ReadFile(filepath.Join(dir, ModeFile))
	store, err := m.OpenMacOSInventoryStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateInvitation(context.Background(), enrollmentstate.CreateCommand{InvitationID: "invite_" + strings.Repeat("1", 32), RequestID: "request_" + strings.Repeat("2", 32), InvitationHash: strings.Repeat("3", 64), Platform: "darwin", Now: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	for n := 0; n < 2; n++ {
		if m.PrepareMode(dir, 0) != nil {
			t.Fatal("repeat mode rejected")
		}
		store, err = m.OpenMacOSInventoryStore(dir)
		if err != nil {
			t.Fatal("repeat ledger open", err)
		}
		got, err := store.Get(context.Background(), created.InvitationID)
		if err != nil || got != created {
			t.Fatal("reopen changed identity")
		}
		store.Close()
	}
	after, _ := os.ReadFile(filepath.Join(dir, ModeFile))
	if !bytes.Equal(primary, after) {
		t.Fatal("primary marker changed")
	}
	for _, name := range []string{MacOSInventoryInitializingFile, MacOSInventoryReadyFile} {
		if raw, err := os.ReadFile(filepath.Join(dir, name)); err != nil || len(raw) == 0 {
			t.Fatal("durable marker missing")
		}
	}
	if err = os.Remove(filepath.Join(dir, MacOSInventoryDatabaseFile)); err != nil {
		t.Fatal(err)
	}
	before := macOSInventoryStateBytes(t, dir)
	if m.PrepareMode(dir, 0) == nil {
		t.Fatal("missing used ledger accepted")
	}
	if store, err = m.OpenMacOSInventoryStore(dir); err == nil {
		store.Close()
		t.Fatal("missing used ledger recreated")
	}
	if !reflect.DeepEqual(before, macOSInventoryStateBytes(t, dir)) {
		t.Fatal("missing-ledger failure wrote state")
	}
}
func TestMacOSInventoryInterruptedInitializationIsNeverFresh(t *testing.T) {
	for _, stage := range []string{"marker-only", "empty-ledger", "validated-ledger", "ready-only"} {
		t.Run(stage, func(t *testing.T) {
			m := macOSInventoryModeFixture(t)
			dir := m.value.lan.StateDirectory
			if stage == "ready-only" {
				if err := createMacOSMarker(dir, MacOSInventoryReadyFile, m.macOSInventoryMarker("ready")); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := createMacOSMarker(dir, MacOSInventoryInitializingFile, m.macOSInventoryMarker("initializing")); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "empty-ledger" {
				if err := os.WriteFile(filepath.Join(dir, MacOSInventoryDatabaseFile), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "validated-ledger" {
				cfg, _ := m.MacOSInventoryStoreConfig()
				store, err := enrollmentstore.Create(filepath.Join(dir, MacOSInventoryDatabaseFile), cfg, m.Issuer().IssuerDER())
				if err != nil {
					t.Fatal(err)
				}
				store.Close()
			}
			before := macOSInventoryStateBytes(t, dir)
			if m.PrepareMode(dir, 0) == nil {
				t.Fatal("interrupted state admitted")
			}
			if store, err := m.OpenMacOSInventoryStore(dir); err == nil {
				store.Close()
				t.Fatal("interrupted initialization retried")
			}
			if !reflect.DeepEqual(before, macOSInventoryStateBytes(t, dir)) {
				t.Fatal("interrupted state changed")
			}
		})
	}
}

func TestMacOSInventoryFencesCannotAdoptBasicOrChangePolicy(t *testing.T) {
	for _, change := range []string{"basic-marker", "profile", "platform", "issuer", "renewal", "missing-ledger-disabled"} {
		t.Run(change, func(t *testing.T) {
			m := macOSInventoryModeFixture(t)
			dir := m.value.lan.StateDirectory
			store, err := m.OpenMacOSInventoryStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			store.Close()
			switch change {
			case "basic-marker":
				if err := os.WriteFile(filepath.Join(dir, MacOSInventoryReadyFile), m.macOSMarker("ready"), 0600); err != nil {
					t.Fatal(err)
				}
			case "profile", "platform", "issuer":
				raw, err := os.ReadFile(filepath.Join(dir, MacOSInventoryReadyFile))
				if err != nil {
					t.Fatal(err)
				}
				switch change {
				case "profile":
					raw = bytes.ReplaceAll(raw, []byte("macos-read-inventory-v1"), []byte("basic-readonly-v1"))
				case "platform":
					raw = bytes.ReplaceAll(raw, []byte("darwin"), []byte("linux"))
				case "issuer":
					raw = bytes.ReplaceAll(raw, []byte(m.StoreConfig().Binding.IssuerFingerprint), []byte(strings.Repeat("f", 64)))
				}
				if err := os.WriteFile(filepath.Join(dir, MacOSInventoryReadyFile), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "renewal":
				m.value.config.AutomaticRenewal = true
			case "missing-ledger-disabled":
				m.value.lan.MacOSInventoryEnabled = false
				if err := os.Remove(filepath.Join(dir, MacOSInventoryDatabaseFile)); err != nil {
					t.Fatal(err)
				}
			}
			before := macOSInventoryStateBytes(t, dir)
			if m.PrepareMode(dir, 0) == nil {
				t.Fatal("changed inventory authority admitted")
			}
			if got, err := m.OpenMacOSInventoryStore(dir); err == nil {
				got.Close()
				t.Fatal("changed inventory authority reopened")
			}
			if !reflect.DeepEqual(before, macOSInventoryStateBytes(t, dir)) {
				t.Fatal("failed fence check changed state")
			}
		})
	}
}

func TestMacOSInventoryDisabledRetainedStoreNeverCreatesAndValidates(t *testing.T) {
	m := macOSInventoryModeFixture(t)
	dir := m.value.lan.StateDirectory
	m.value.lan.MacOSInventoryEnabled = false
	if s, e := m.OpenRetainedMacOSInventoryStore(dir); e != nil || s != nil {
		t.Fatal("disabled fresh domain created", e)
	}
	m.value.lan.MacOSInventoryEnabled = true
	s, e := m.OpenMacOSInventoryStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	m.value.lan.MacOSInventoryEnabled = false
	s, e = m.OpenRetainedMacOSInventoryStore(dir)
	if e != nil || s == nil {
		t.Fatal("disabled retained store unavailable", e)
	}
	s.Close()
	if e = os.WriteFile(filepath.Join(dir, MacOSInventoryDatabaseFile), []byte("nonempty corrupt SQLite fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if s, e = m.OpenRetainedMacOSInventoryStore(dir); e == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("disabled corrupted used database adopted")
	}
}
