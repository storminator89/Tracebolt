//go:build linux

package main

import (
	"bytes"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/lanconfig"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMacOSInventoryManagerRejectsUsedLedgerDisappearance(t *testing.T) {
	m, _, path := guidedFixture(t, lanconfig.TLS)
	m.Config.MacOSInventoryEnabled = true
	material, err := enrollmentconfig.Load(path, m, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	p, err := prepareWithEnrollment(m, &material)
	if err != nil {
		t.Fatal(err)
	}
	p.close()
	dir := m.Config.StateDirectory
	before, _ := os.ReadFile(filepath.Join(dir, enrollmentconfig.ModeFile))
	if err = os.Remove(filepath.Join(dir, enrollmentconfig.MacOSInventoryDatabaseFile)); err != nil {
		t.Fatal(err)
	}
	m.Config.MacOSInventoryEnabled = false
	material, err = enrollmentconfig.Load(path, m, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if p, err = prepareWithEnrollment(m, &material); err == nil {
		p.close()
		t.Fatal("manager recreated used Mac ledger")
	}
	if _, err = os.Stat(filepath.Join(dir, enrollmentconfig.MacOSInventoryDatabaseFile)); !os.IsNotExist(err) {
		t.Fatal("missing Mac ledger was replaced")
	}
	after, _ := os.ReadFile(filepath.Join(dir, enrollmentconfig.ModeFile))
	if !bytes.Equal(before, after) {
		t.Fatal("primary marker changed")
	}
}
func TestMacOSInventoryManagerExistingPrimaryRejectsOrphanFragments(t *testing.T) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		t.Run("fragment"+suffix, func(t *testing.T) {
			m, material, path := guidedFixture(t, lanconfig.TLS)
			p, err := prepareWithEnrollment(m, &material)
			if err != nil {
				t.Fatal(err)
			}
			p.close()
			dir := m.Config.StateDirectory
			fragment := filepath.Join(dir, enrollmentconfig.MacOSInventoryDatabaseFile+suffix)
			if err = os.WriteFile(fragment, []byte("retained orphan"), 0600); err != nil {
				t.Fatal(err)
			}
			m.Config.MacOSInventoryEnabled = true
			material, err = enrollmentconfig.Load(path, m, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if p, err = prepareWithEnrollment(m, &material); err == nil {
				p.close()
				t.Fatal("existing primary adopted Mac fragment")
			}
			after, err := os.ReadFile(fragment)
			if err != nil || string(after) != "retained orphan" {
				t.Fatal("failed startup changed orphan")
			}
			if _, err = os.Stat(filepath.Join(dir, enrollmentconfig.MacOSInventoryInitializingFile)); !os.IsNotExist(err) {
				t.Fatal("rejected orphan staged new authority")
			}
		})
	}
}
