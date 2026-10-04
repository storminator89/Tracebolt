//go:build linux

package lanclientstate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectionLeasePreservesExistingLedgerAndTemporary(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	binding := strings.Repeat("a", 64)
	state, e := InitializeNew(dir, binding)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = AcquireInspection(dir, binding); !errors.Is(e, ErrLocked) {
		t.Fatal("active owner bypassed", e)
	}
	if e = state.Close(); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(filepath.Join(dir, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	temp := []byte("inert pending crash temporary")
	if os.WriteFile(filepath.Join(dir, ".state.tmp"), temp, 0600) != nil {
		t.Fatal("fixture")
	}
	lease, e := AcquireInspection(dir, binding)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = OpenExisting(dir, binding); !errors.Is(e, ErrLocked) {
		t.Fatal("inspection failed to retain owner")
	}
	if e = lease.Close(); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	retained, _ := os.ReadFile(filepath.Join(dir, ".state.tmp"))
	if !bytes.Equal(before, after) || !bytes.Equal(temp, retained) {
		t.Fatal("inspection mutated existing state")
	}
}
func TestInspectionLeaseMissingStateDoesNotCreate(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "missing")
	if _, e := AcquireInspection(dir, strings.Repeat("a", 64)); e == nil {
		t.Fatal("missing state adopted")
	}
	if _, e := os.Lstat(dir); !os.IsNotExist(e) {
		t.Fatal("inspection created missing path")
	}
	entries, e := os.ReadDir(root)
	if e != nil || len(entries) != 0 {
		t.Fatal("inspection wrote files")
	}
}
