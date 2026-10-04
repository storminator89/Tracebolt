//go:build linux

package lanclientstate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitializeNewRejectsExistingWithoutCleanup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	binding := strings.Repeat("a", 64)
	state, e := InitializeNew(dir, binding)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = state.Stage(1, []byte(`{"invented":true}`)); e != nil {
		t.Fatal(e)
	}
	state.Close()
	before, e := os.ReadFile(filepath.Join(dir, stateName))
	if e != nil {
		t.Fatal(e)
	}
	if os.WriteFile(filepath.Join(dir, tempName), []byte("preserved fixture"), 0600) != nil {
		t.Fatal("fixture")
	}
	if s, e := InitializeNew(dir, binding); e == nil {
		s.Close()
		t.Fatal("existing domain adopted")
	}
	after, e := os.ReadFile(filepath.Join(dir, stateName))
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("existing ledger changed")
	}
	tmp, e := os.ReadFile(filepath.Join(dir, tempName))
	if e != nil || string(tmp) != "preserved fixture" {
		t.Fatal("rejected initialization cleaned temporary")
	}
}
