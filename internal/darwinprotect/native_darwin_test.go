//go:build darwin

package darwinprotect

import (
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// These tests touch only newly created temporary fixture files. Compilation
// elsewhere does not execute the syscall, ACL or durability acceptance gate.
func TestNativeDarwinACLAndDurabilityFixtures(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("fixture path")
	}
	path := filepath.Join(dir, "fixture")
	if os.WriteFile(path, []byte("synthetic fixture"), 0600) != nil {
		t.Fatal("fixture file")
	}
	// Remove only this fixture's added ACL before TempDir removes the file.
	// In particular, the deny-delete entry must not obstruct test cleanup.
	t.Cleanup(func() {
		if exec.Command("/bin/chmod", "-N", path).Run() != nil {
			t.Error("fixture ACL cleanup")
		}
	})
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal("fixture open")
	}
	defer f.Close()
	var st unix.Stat_t
	if err = Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal("plain local protected fixture rejected")
	}
	if err = Sync(int(f.Fd())); err != nil {
		t.Fatal("full file durability flush rejected")
	}
	if exec.Command("/bin/chmod", "+a", "everyone deny delete", path).Run() != nil {
		t.Fatal("deny ACL fixture setup")
	}
	if Fstat(int(f.Fd()), &st) != nil {
		t.Fatal("deny-only ACL rejected")
	}
	if exec.Command("/bin/chmod", "+a", "everyone allow read", path).Run() != nil {
		t.Fatal("allow ACL fixture setup")
	}
	if Fstat(int(f.Fd()), &st) == nil {
		t.Fatal("mode-0600 file with expanding ACL accepted")
	}
}
