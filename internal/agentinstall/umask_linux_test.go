//go:build linux

package agentinstall

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Runs only an inert backend in a subprocess so the process-global umask cannot
// affect other tests. No real account, service or credential drop is performed.
func TestLinuxAdapterPublicDirectoriesIgnoreRestrictiveUmask(t *testing.T) {
	if os.Getenv("TRACEBOLT_INERT_UMASK_FIXTURE") == "1" {
		syscall.Umask(0077)
		r, b, _ := installerHostFixture(t)
		original := b.host.run
		b.host.run = func(ctx context.Context, path string, args []string, a *accountRecord, interactive bool) error {
			if filepath.Base(path) == "enroll-agent" {
				for _, dir := range []string{b.host.path(InstallDirectory), b.host.path(publicDirectory), filepath.Dir(path)} {
					i, e := os.Lstat(dir)
					if e != nil || i.Mode().Perm() != 0755 {
						return ErrPreflight
					}
				}
			}
			return original(ctx, path, args, a, interactive)
		}
		out, e := Execute(context.Background(), r, b)
		if e != nil || !out.Committed {
			t.Fatal("new public directories denied dedicated-account traversal under umask077")
		}
		return
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal("fixture executable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestLinuxAdapterPublicDirectoriesIgnoreRestrictiveUmask$")
	cmd.Env = append(os.Environ(), "TRACEBOLT_INERT_UMASK_FIXTURE=1")
	if cmd.Run() != nil {
		t.Fatal("inert restrictive-umask lifecycle failed")
	}
}

func TestNewPublicDirectoryNeverAdoptsExisting(t *testing.T) {
	h := &linuxHost{owner: os.Geteuid()}
	dir := filepath.Join(t.TempDir(), "existing")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("fixture directory")
	}
	if h.createPublicDirectory(dir) == nil {
		t.Fatal("existing directory adopted")
	}
	if info, e := os.Stat(dir); e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("existing permissions changed")
	}
	link := filepath.Join(t.TempDir(), "link")
	if os.Symlink(dir, link) != nil {
		t.Fatal("fixture link")
	}
	if h.createPublicDirectory(link) == nil {
		t.Fatal("linked directory adopted")
	}
	if info, e := os.Stat(dir); e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("link target permissions changed")
	}
}
