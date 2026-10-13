//go:build darwin

package macosservice

import (
	"golang.org/x/sys/unix"
	"testing"
)

// These synthetic policy tests never inspect or modify a native host path.
func TestDirectoryOwnershipPolicy(t *testing.T) {
	root := unix.Stat_t{Uid: 0, Gid: 0, Mode: unix.S_IFDIR | 0755, Nlink: 2}
	private := unix.Stat_t{Uid: 510, Gid: 510, Mode: unix.S_IFDIR | 0700, Nlink: 2}
	for _, name := range []string{"/", "/Library", InstallDirectory, "/Library/LaunchDaemons"} {
		if !safeDirectory(name, root, 510, 510) || safeDirectory(name, private, 510, 510) {
			t.Fatal("bad protected root policy")
		}
	}
	for _, name := range []string{StateDirectory, EnrollmentDirectory, EnrollmentDirectory + "/telemetry"} {
		if !safeDirectory(name, private, 510, 510) || safeDirectory(name, root, 510, 510) {
			t.Fatal("bad private state policy")
		}
	}
	for _, mode := range []uint16{unix.S_IFDIR | 0777, unix.S_IFDIR | 01777, unix.S_IFLNK | 0755, unix.S_IFDIR | 02755} {
		s := root
		s.Mode = mode
		if safeDirectory(InstallDirectory, s, 510, 510) {
			t.Fatal("unsafe mode")
		}
	}
	s := private
	s.Gid = 511
	if safeDirectory(StateDirectory, s, 510, 510) {
		t.Fatal("wrong private group")
	}
	s = private
	s.Mode = unix.S_IFDIR | 0750
	if safeDirectory(StateDirectory, s, 510, 510) {
		t.Fatal("shared private directory")
	}
}
func TestSnapshotDetectsIdentityAndMetadataChanges(t *testing.T) {
	base := unix.Stat_t{Dev: 1, Ino: 2, Uid: 0, Gid: 0, Mode: unix.S_IFREG | 0555, Nlink: 1, Size: 20}
	if !sameNode(base, base) {
		t.Fatal("same node")
	}
	for _, mutate := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Ino++ }, func(s *unix.Stat_t) { s.Uid++ }, func(s *unix.Stat_t) { s.Gid++ }, func(s *unix.Stat_t) { s.Mode++ }, func(s *unix.Stat_t) { s.Nlink++ }, func(s *unix.Stat_t) { s.Size++ }, func(s *unix.Stat_t) { s.Ctim.Sec++ }, func(s *unix.Stat_t) { s.Mtim.Sec++ }, func(s *unix.Stat_t) { s.Flags++ }} {
		s := base
		mutate(&s)
		if sameNode(base, s) {
			t.Fatal("changed snapshot")
		}
	}
}
