//go:build linux

package inventorystate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectExistingWithLiveInventoryPackDoesNotMutate(t *testing.T) {
	s, dir := newFixture(t)
	stageFixture(t, s, 20)
	ledger, _ := os.ReadFile(filepath.Join(dir, stateName))
	pack, _ := os.ReadFile(filepath.Join(dir, packName))
	if err := InspectExisting(dir, fixtureBinding, fixtureAgent); err != nil {
		t.Fatal("inspection blocked by live sender", err)
	}
	ledgerAfter, _ := os.ReadFile(filepath.Join(dir, stateName))
	packAfter, _ := os.ReadFile(filepath.Join(dir, packName))
	if !bytes.Equal(ledger, ledgerAfter) || !bytes.Equal(pack, packAfter) {
		t.Fatal("inspection changed ledger or pack")
	}
	if _, err := OpenExisting(dir, fixtureBinding, fixtureAgent); err != ErrLocked {
		t.Fatal("inspection released writer lock", err)
	}
	if err := InspectExisting(dir, strings.Repeat("a", 64), fixtureAgent); err == nil {
		t.Fatal("wrong binding accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, tempName), []byte("uncertain fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := InspectExisting(dir, fixtureBinding, fixtureAgent); err == nil {
		t.Fatal("uncertain state accepted")
	}
	if raw, err := os.ReadFile(filepath.Join(dir, tempName)); err != nil || string(raw) != "uncertain fixture" {
		t.Fatal("inspection cleaned temporary")
	}
}

func TestInspectExistingMissingInventoryNeverCreatesOrRepairs(t *testing.T) {
	_, dir := newFixture(t)
	if err := os.Rename(filepath.Join(dir, stateName), filepath.Join(dir, stateName+"-kept")); err != nil {
		t.Fatal(err)
	}
	if err := InspectExisting(dir, fixtureBinding, fixtureAgent); err == nil {
		t.Fatal("missing ledger accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, stateName)); !os.IsNotExist(err) {
		t.Fatal("missing ledger recreated")
	}
}
