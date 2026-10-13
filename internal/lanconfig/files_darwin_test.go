//go:build darwin

package lanconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDarwinReadProtectedUsesDescriptorAndACLPolicy(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("fixture path")
	}
	dir := filepath.Join(root, "private")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("fixture directory")
	}
	path := filepath.Join(dir, "material")
	if os.WriteFile(path, []byte("synthetic private fixture"), 0600) != nil {
		t.Fatal("fixture material")
	}
	raw, err := ReadProtected(path, true, 100)
	if err != nil || string(raw) != "synthetic private fixture" {
		t.Fatal("protected fixture rejected")
	}
	if _, err = ReadProtected(path, true, 3); err == nil {
		t.Fatal("oversize material accepted")
	}
	link := filepath.Join(dir, "alias")
	if os.Symlink(path, link) != nil {
		t.Fatal("fixture link")
	}
	if _, err = ReadProtected(link, true, 100); err == nil {
		t.Fatal("symlink material accepted")
	}
	if os.Remove(link) != nil || os.Link(path, link) != nil {
		t.Fatal("fixture hardlink")
	}
	if _, err = ReadProtected(path, true, 100); err == nil {
		t.Fatal("shared material accepted")
	}
	if os.Remove(link) != nil {
		t.Fatal("fixture unlink")
	}
	if exec.Command("/bin/chmod", "+a", "everyone allow read", path).Run() != nil {
		t.Fatal("file ACL fixture")
	}
	if _, err = ReadProtected(path, true, 100); err == nil {
		t.Fatal("mode-only policy accepted file ACL")
	}
	if exec.Command("/bin/chmod", "-N", path).Run() != nil {
		t.Fatal("fixture restore")
	}
	if exec.Command("/bin/chmod", "+a", "everyone allow add_file", dir).Run() != nil {
		t.Fatal("directory ACL fixture")
	}
	if _, err = ReadProtected(path, true, 100); err == nil {
		t.Fatal("replaceable ACL ancestor accepted")
	}
}
