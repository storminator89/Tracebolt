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

func TestMacOSDatabaseFragmentsRejectFreshOrManualAdoption(t *testing.T) {
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
			fragment := filepath.Join(lan.Config.StateDirectory, MacOSDatabaseFile+suffix)
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
func macOSModeFixture(t *testing.T) Material {
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
	m.value.lan.MacOSBasicEnabled = true
	if err = m.PrepareMode(lan.Config.StateDirectory, 0); err != nil {
		t.Fatal(err)
	}
	return m
}
func macOSStateBytes(t *testing.T, dir string) map[string]string {
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
func TestMacOSExistingPrimaryRejectsEveryOrphanFragment(t *testing.T) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		t.Run("fragment"+suffix, func(t *testing.T) {
			m := macOSModeFixture(t)
			dir := m.value.lan.StateDirectory
			fragment := filepath.Join(dir, MacOSDatabaseFile+suffix)
			if err := os.WriteFile(fragment, []byte("retained fragment"), 0600); err != nil {
				t.Fatal(err)
			}
			before := macOSStateBytes(t, dir)
			if m.PrepareMode(dir, 0) == nil {
				t.Fatal("existing primary adopted orphan Mac fragment")
			}
			if store, err := m.OpenMacOSStore(dir); err == nil {
				store.Close()
				t.Fatal("orphan Mac fragment initialized")
			}
			if !reflect.DeepEqual(before, macOSStateBytes(t, dir)) {
				t.Fatal("orphan rejection changed state")
			}
		})
	}
}
func TestMacOSReadyFenceReopensAndNeverRecreatesMissingLedger(t *testing.T) {
	m := macOSModeFixture(t)
	dir := m.value.lan.StateDirectory
	primary, _ := os.ReadFile(filepath.Join(dir, ModeFile))
	store, err := m.OpenMacOSStore(dir)
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
		store, err = m.OpenMacOSStore(dir)
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
	for _, name := range []string{MacOSInitializingFile, MacOSReadyFile} {
		if raw, err := os.ReadFile(filepath.Join(dir, name)); err != nil || len(raw) == 0 {
			t.Fatal("durable marker missing")
		}
	}
	if err = os.Remove(filepath.Join(dir, MacOSDatabaseFile)); err != nil {
		t.Fatal(err)
	}
	before := macOSStateBytes(t, dir)
	if m.PrepareMode(dir, 0) == nil {
		t.Fatal("missing used ledger accepted")
	}
	if store, err = m.OpenMacOSStore(dir); err == nil {
		store.Close()
		t.Fatal("missing used ledger recreated")
	}
	if !reflect.DeepEqual(before, macOSStateBytes(t, dir)) {
		t.Fatal("missing-ledger failure wrote state")
	}
}
func TestMacOSInterruptedInitializationIsNeverFresh(t *testing.T) {
	for _, stage := range []string{"marker-only", "empty-ledger", "validated-ledger", "ready-only"} {
		t.Run(stage, func(t *testing.T) {
			m := macOSModeFixture(t)
			dir := m.value.lan.StateDirectory
			if stage == "ready-only" {
				if err := createMacOSMarker(dir, MacOSReadyFile, m.macOSMarker("ready")); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := createMacOSMarker(dir, MacOSInitializingFile, m.macOSMarker("initializing")); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "empty-ledger" {
				if err := os.WriteFile(filepath.Join(dir, MacOSDatabaseFile), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "validated-ledger" {
				cfg, _ := m.MacOSStoreConfig()
				store, err := enrollmentstore.Create(filepath.Join(dir, MacOSDatabaseFile), cfg, m.Issuer().IssuerDER())
				if err != nil {
					t.Fatal(err)
				}
				store.Close()
			}
			before := macOSStateBytes(t, dir)
			if m.PrepareMode(dir, 0) == nil {
				t.Fatal("interrupted state admitted")
			}
			if store, err := m.OpenMacOSStore(dir); err == nil {
				store.Close()
				t.Fatal("interrupted initialization retried")
			}
			if !reflect.DeepEqual(before, macOSStateBytes(t, dir)) {
				t.Fatal("interrupted state changed")
			}
		})
	}
}
