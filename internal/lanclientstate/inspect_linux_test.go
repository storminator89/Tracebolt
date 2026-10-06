//go:build linux

package lanclientstate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectExistingWithLiveWriterDoesNotMutate(t *testing.T) {
	s, dir := openTestState(t)
	if _, err := s.Stage(1, []byte("{\"sequence\":1}")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, stateName))
	if err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(dir, tempName)
	if err := os.WriteFile(temp, []byte("retained temporary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := InspectExisting(dir, testBinding); err != nil {
		t.Fatal("read-only inspection blocked by live writer", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, stateName))
	left, err := os.ReadFile(temp)
	if !bytes.Equal(before, after) || err != nil || string(left) != "retained temporary" {
		t.Fatal("inspection changed state or cleaned temporary")
	}
	if _, err := OpenExisting(dir, testBinding); err != ErrLocked {
		t.Fatal("inspection released writer's lock", err)
	}
	if err := InspectExisting(dir, strings.Repeat("b", 64)); err == nil {
		t.Fatal("wrong binding accepted")
	}
	if p, err := s.Pending(); err != nil || p == nil || p.Sequence != 1 {
		t.Fatal("live sender affected", err)
	}
}

func TestInspectExistingMissingStateNeverCreatesOrRepairs(t *testing.T) {
	_, dir := openTestState(t)
	if err := os.Rename(filepath.Join(dir, stateName), filepath.Join(dir, stateName+"-kept")); err != nil {
		t.Fatal(err)
	}
	if err := InspectExisting(dir, testBinding); err == nil {
		t.Fatal("missing state accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, stateName)); !os.IsNotExist(err) {
		t.Fatal("missing state recreated")
	}
}
