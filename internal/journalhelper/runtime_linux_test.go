//go:build linux

package journalhelper

import (
	"testing"

	"golang.org/x/sys/unix"
)

// These are inert stat facts only. No protected loader, socket activation,
// real process identity, peer-credential syscall or source runtime is invoked.
func TestProtectedMetadataPredicates(t *testing.T) {
	dir := unix.Stat_t{Uid: 0, Mode: unix.S_IFDIR | 0755}
	if !safeDirectory(dir) {
		t.Fatal("directory fixture")
	}
	for _, change := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Uid = 1200 }, func(s *unix.Stat_t) { s.Mode |= 0020 }, func(s *unix.Stat_t) { s.Mode |= 0002 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFLNK | 0755 }, func(s *unix.Stat_t) { s.Mode |= unix.S_ISGID }} {
		s := dir
		change(&s)
		if safeDirectory(s) {
			t.Fatal("unsafe directory")
		}
	}
	file := unix.Stat_t{Uid: 0, Gid: 1201, Mode: unix.S_IFREG | 0640, Nlink: 1, Size: 100}
	if !safeFile(file, 1024) {
		t.Fatal("file fixture")
	}
	for _, change := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Uid = 1200 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFLNK | 0640 }, func(s *unix.Stat_t) { s.Mode |= 0020 }, func(s *unix.Stat_t) { s.Mode |= 0004 }, func(s *unix.Stat_t) { s.Nlink = 2 }, func(s *unix.Stat_t) { s.Size = 0 }, func(s *unix.Stat_t) { s.Size = 1025 }, func(s *unix.Stat_t) { s.Mode |= unix.S_ISUID }} {
		s := file
		change(&s)
		if safeFile(s, 1024) {
			t.Fatal("unsafe file")
		}
	}
	socket := unix.Stat_t{Uid: 0, Gid: 1200, Mode: unix.S_IFSOCK | 0660, Nlink: 1}
	if !safeSocket(socket, fixtureState().Deployment) {
		t.Fatal("socket fixture")
	}
	for _, change := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Uid = 1200 }, func(s *unix.Stat_t) { s.Gid = 1201 }, func(s *unix.Stat_t) { s.Mode |= 0002 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFREG | 0660 }, func(s *unix.Stat_t) { s.Nlink = 2 }} {
		s := socket
		change(&s)
		if safeSocket(s, fixtureState().Deployment) {
			t.Fatal("unsafe socket")
		}
	}
	if !sameObject(file, file) {
		t.Fatal("same fixture")
	}
	for _, change := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Dev++ }, func(s *unix.Stat_t) { s.Ino++ }, func(s *unix.Stat_t) { s.Uid++ }, func(s *unix.Stat_t) { s.Gid++ }, func(s *unix.Stat_t) { s.Mode++ }, func(s *unix.Stat_t) { s.Nlink++ }, func(s *unix.Stat_t) { s.Size++ }, func(s *unix.Stat_t) { s.Mtim.Nsec++ }, func(s *unix.Stat_t) { s.Ctim.Nsec++ }} {
		s := file
		change(&s)
		if sameObject(s, file) {
			t.Fatal("changed metadata accepted")
		}
	}
}
