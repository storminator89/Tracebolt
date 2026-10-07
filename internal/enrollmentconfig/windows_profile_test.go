//go:build linux

package enrollmentconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"localrmm/internal/enrollmentcrypto"
)

func TestWindowsSidecarNeedsExplicitOptInAndPreservesPrimaryBinding(t *testing.T) {
	c, lan, path, now := profileFixture(t)
	c.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	raw, _ := json.Marshal(c)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	disabled, err := Load(path, lan, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = disabled.WindowsStoreConfig(); err == nil {
		t.Fatal("Windows domain admitted without opt-in")
	}
	lan.Config.WindowsInventoryEnabled = true
	enabled, err := Load(path, lan, now)
	if err != nil {
		t.Fatal(err)
	}
	windows, err := enabled.WindowsStoreConfig()
	if err != nil {
		t.Fatal(err)
	}
	primary := enabled.StoreConfig()
	if primary.Binding.CollectionProfile != c.CollectionProfile || windows.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		t.Fatal("collection domain changed")
	}
	windows.Binding.CollectionProfile = primary.Binding.CollectionProfile
	if windows.Binding != primary.Binding {
		t.Fatal("Windows domain changed manager trust or origin")
	}
	if string(enabled.marker()) != string(disabled.marker()) {
		t.Fatal("opt-in changed original marker")
	}
	c.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
	raw, _ = json.Marshal(c)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(path, lan, now); err == nil {
		t.Fatal("Windows admitted as primary profile")
	}
}

func TestWindowsDatabaseFragmentsCannotBeAdoptedAsFreshOrManualState(t *testing.T) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		t.Run("fragment"+suffix, func(t *testing.T) {
			c, lan, path, now := profileFixture(t)
			raw, _ := json.Marshal(c)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			material, err := Load(path, lan, now)
			if err != nil {
				t.Fatal(err)
			}
			fragment := filepath.Join(lan.Config.StateDirectory, WindowsDatabaseFile+suffix)
			if err = os.WriteFile(fragment, []byte("retained fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			if RejectEnrollmentMode(lan.Config.StateDirectory) == nil || material.PrepareMode(lan.Config.StateDirectory, 0) == nil {
				t.Fatal("retained Windows fragment adopted")
			}
			if _, err = os.Stat(filepath.Join(lan.Config.StateDirectory, ModeFile)); !os.IsNotExist(err) {
				t.Fatal("failed admission created marker")
			}
			after, err := os.ReadFile(fragment)
			if err != nil || string(after) != "retained fixture" {
				t.Fatal("rejected admission changed retained bytes")
			}
		})
	}
}
