//go:build linux

package actionhelper

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFullAdminRootControlledSymlinksAndWritableAuthority(t *testing.T) {
	root := t.TempDir()
	fs := authorityFS{root: root, owner: uint32(os.Geteuid())}
	for _, dir := range []string{"usr/lib/systemd/system", "usr/bin", "opt/tracebolt-agent", "etc/systemd/system"} {
		if e := os.MkdirAll(filepath.Join(root, dir), 0755); e != nil {
			t.Fatal(e)
		}
	}
	unit := filepath.Join(root, "usr/lib/systemd/system/example.service")
	if e := os.WriteFile(unit, []byte("[Service]\nExecStart=/usr/bin/daemon\n"), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("usr/lib", filepath.Join(root, "lib")); e != nil {
		t.Fatal(e)
	}
	got, e := readFullAdminFileFrom(fs, "/lib/systemd/system/example.service")
	if e != nil || got.Resolved != "/usr/lib/systemd/system/example.service" {
		t.Fatal(got, e)
	}
	if e := os.WriteFile(filepath.Join(root, "opt/tracebolt-agent/agent"), []byte("inert executable fixture"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("../../opt/tracebolt-agent/agent", filepath.Join(root, "usr/bin/alias")); e != nil {
		t.Fatal(e)
	}
	exe, e := readFullAdminExecutableFrom(fs, "/usr/bin/alias")
	if e != nil || !protectedFullAdminPath(exe.Resolved) {
		t.Fatal(exe, e)
	}
	if e := os.Link(filepath.Join(root, "opt/tracebolt-agent/agent"), filepath.Join(root, "usr/bin/hardalias")); e != nil {
		t.Fatal(e)
	}
	if _, e := readFullAdminExecutableFrom(fs, "/usr/bin/hardalias"); e == nil {
		t.Fatal("hardlink execution alias accepted")
	}
	if e := os.Chmod(unit, 0666); e != nil {
		t.Fatal(e)
	}
	if _, e := readFullAdminFileFrom(fs, "/lib/systemd/system/example.service"); e == nil {
		t.Fatal("writable fragment trusted")
	}
	if e := os.Chmod(unit, 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(filepath.Join(root, "usr/lib/systemd"), 0777); e != nil {
		t.Fatal(e)
	}
	if _, e := readFullAdminFileFrom(fs, "/lib/systemd/system/example.service"); e == nil {
		t.Fatal("writable ancestor trusted")
	}
	if e := os.Symlink("cycle-b", filepath.Join(root, "cycle-a")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("cycle-a", filepath.Join(root, "cycle-b")); e != nil {
		t.Fatal(e)
	}
	if _, _, e := resolveFullAdminPath(fs, "/cycle-a"); e == nil {
		t.Fatal("symlink loop accepted")
	}
}
