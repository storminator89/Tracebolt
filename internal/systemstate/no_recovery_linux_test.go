//go:build linux

package systemstate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenExistingNoRecoveryPreservesTemporaryFloorAndBody(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	binding := strings.Repeat("a", 64)
	state, err := InitializeNew(dir, binding)
	if err != nil {
		t.Fatal(err)
	}
	p, err := state.Stage(1, []byte(`{"invented":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExistingNoRecovery(dir, binding); !errors.Is(err, ErrLocked) {
		t.Fatal("lock bypass", err)
	}
	state.Close()
	before, _ := os.ReadFile(filepath.Join(dir, stateName))
	temporary := []byte("incomplete synthetic state")
	if os.WriteFile(filepath.Join(dir, tempName), temporary, 0600) != nil {
		t.Fatal("fixture")
	}
	state, err = OpenExistingNoRecovery(dir, binding)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := state.Pending()
	if err != nil || pending == nil || pending.Digest != p.Digest || !bytes.Equal(pending.Body(), p.Body()) {
		t.Fatal("pending changed")
	}
	n, err := state.NextSequence()
	if err != nil || n != 2 {
		t.Fatal("floor")
	}
	if err = state.Discard(p.Digest); err == nil {
		t.Fatal("discard overwrote exclusive temporary")
	}
	state.Close()
	after, _ := os.ReadFile(filepath.Join(dir, stateName))
	retained, _ := os.ReadFile(filepath.Join(dir, tempName))
	if !bytes.Equal(before, after) || !bytes.Equal(temporary, retained) {
		t.Fatal("recovered/adopted temporary")
	}
}
func TestOpenExistingNoRecoveryRejectsMissingWithoutCreating(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	if s, err := OpenExistingNoRecovery(dir, strings.Repeat("a", 64)); err == nil {
		s.Close()
		t.Fatal("missing adopted")
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("missing recreated")
	}
}
