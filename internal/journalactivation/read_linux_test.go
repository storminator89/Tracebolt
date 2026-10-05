//go:build linux

package journalactivation

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestRootActivationMetadataAndAmbiguousStageDeny(t *testing.T) {
	st := unix.Stat_t{Uid: 0, Gid: 0, Mode: unix.S_IFREG | 0644, Nlink: 1, Size: 128}
	if !safeActivationFile(st) {
		t.Fatal("valid rejected")
	}
	for _, change := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Uid = 1001 }, func(s *unix.Stat_t) { s.Gid = 1001 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFLNK | 0644 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFREG | 0664 }, func(s *unix.Stat_t) { s.Nlink = 2 }, func(s *unix.Stat_t) { s.Size = 0 }, func(s *unix.Stat_t) { s.Size = MaxBytes + 1 }} {
		bad := st
		change(&bad)
		if safeActivationFile(bad) {
			t.Fatal("unsafe metadata accepted")
		}
	}
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			f, e := os.Open(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			if !noStage(int(f.Fd())) {
				t.Fatal("absence rejected")
			}
			p := filepath.Join(dir, TempName)
			switch kind {
			case "file":
				e = os.WriteFile(p, nil, 0600)
			case "directory":
				e = os.Mkdir(p, 0700)
			case "symlink":
				e = os.Symlink("missing", p)
			}
			if e != nil {
				t.Fatal(e)
			}
			if noStage(int(f.Fd())) {
				t.Fatal("stage ignored")
			}
			if noStage(-1) {
				t.Fatal("I/O error treated absent")
			}
		})
	}

}
