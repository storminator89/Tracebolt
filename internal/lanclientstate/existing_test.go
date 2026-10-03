//go:build linux

package lanclientstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenExistingNeverCreatesLostDomain(t *testing.T) {
	binding := strings.Repeat("1", 64)
	root := t.TempDir()
	missing := filepath.Join(root, "missing", "sender")
	if s, e := OpenExisting(missing, binding); e == nil {
		s.Close()
		t.Fatal("missing domain initialized")
	}
	if _, e := os.Lstat(filepath.Join(root, "missing")); !os.IsNotExist(e) {
		t.Fatal("missing path modified")
	}
	empty := filepath.Join(root, "empty")
	if os.Mkdir(empty, 0700) != nil {
		t.Fatal("fixture directory")
	}
	if s, e := OpenExisting(empty, binding); e == nil {
		s.Close()
		t.Fatal("empty replacement adopted")
	}
	entries, _ := os.ReadDir(empty)
	if len(entries) != 0 {
		t.Fatal("rejected empty directory changed")
	}
	original := filepath.Join(root, "original")
	s, e := Open(original, binding)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = OpenExisting(original, binding)
	if e != nil {
		t.Fatal("existing domain rejected", e)
	}
	s.Close()
	if os.Remove(filepath.Join(original, "state.json")) != nil {
		t.Fatal("fixture loss")
	}
	before, _ := os.ReadDir(original)
	if s, e := OpenExisting(original, binding); e == nil {
		s.Close()
		t.Fatal("missing sequence ledger recreated")
	}
	after, _ := os.ReadDir(original)
	if len(after) != len(before) {
		t.Fatal("rejected lost state modified")
	}
}
func TestValidateExistingPreservesSenderTemporary(t *testing.T) {
	binding := strings.Repeat("4", 64)
	dir := filepath.Join(t.TempDir(), "sender")
	state, e := Open(dir, binding)
	if e != nil {
		t.Fatal(e)
	}
	state.Close()
	sentinel := []byte("private uncommitted sender fixture, not enrollment-owned")
	path := filepath.Join(dir, ".state.tmp")
	if e = os.WriteFile(path, sentinel, 0600); e != nil {
		t.Fatal(e)
	}
	if e = ValidateExisting(dir, binding); e != nil {
		t.Fatal("valid ledger validation failed", e)
	}
	after, e := os.ReadFile(path)
	if e != nil || string(after) != string(sentinel) {
		t.Fatal("read-only validator changed sender temporary")
	}
}
