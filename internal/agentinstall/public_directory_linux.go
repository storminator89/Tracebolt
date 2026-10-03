//go:build linux

package agentinstall

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"syscall"
)

// createPublicDirectory first creates a private directory, then explicitly sets
// the public traversal mode through its checked descriptor. Caller umask must
// not prevent the genuinely dropped enrollment child from reaching its binary
// and public bootstrap. Existing paths are never adopted or chmodded.
func (h *linuxHost) createPublicDirectory(path string) error {
	if os.Mkdir(path, 0700) != nil {
		return ErrState
	}
	before, e := os.Lstat(path)
	if e != nil {
		return ErrState
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrState
	}
	f := os.NewFile(uintptr(fd), "installer-new-public-directory")
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) || !opened.IsDir() || opened.Mode().Perm() != 0700 {
		return ErrState
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != h.owner {
		return ErrState
	}
	if f.Chmod(0755) != nil || f.Sync() != nil {
		return ErrState
	}
	final, e := f.Stat()
	if e != nil || final.Mode().Perm() != 0755 {
		return ErrState
	}
	return syncDirectory(filepath.Dir(path))
}
