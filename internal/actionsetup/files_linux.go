//go:build linux

package actionsetup

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
)

// The held ancestor chain prevents symlinks; identity is rechecked by name
// after each durable create. Never repair modes/owners or replace an old leaf.
func protectedParent(path string) ([]int, []unix.Stat_t, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n\t") {
		return nil, nil, ErrSetup
	}
	var fds []int
	var stats []unix.Stat_t
	fail := func() ([]int, []unix.Stat_t, error) {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return nil, nil, ErrSetup
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return fail()
	}
	fds = append(fds, fd)
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/")
	for i := 0; ; i++ {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Mode&0022 != 0 || st.Mode&06000 != 0 {
			return fail()
		}
		stats = append(stats, st)
		if i == len(parts) || (len(parts) == 1 && parts[0] == "") {
			break
		}
		fd, e = unix.Openat(fd, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return fail()
		}
		fds = append(fds, fd)
	}
	return fds, stats, nil
}
func closeParents(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}
func sameParent(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode
}
func parentsUnchanged(path string, fds []int, stats []unix.Stat_t) bool {
	fresh, now, e := protectedParent(path)
	if e != nil {
		return false
	}
	defer closeParents(fresh)
	if len(fds) != len(fresh) {
		return false
	}
	for i, fd := range fds {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || !sameParent(st, stats[i]) || !sameParent(st, now[i]) {
			return false
		}
	}
	return true
}
func createProtected(path string, b []byte) error {
	fds, stats, e := protectedParent(path)
	if e != nil {
		return ErrSetup
	}
	defer closeParents(fds)
	parent := fds[len(fds)-1]
	fd, e := unix.Openat(parent, filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrSetup
	}
	f := os.NewFile(uintptr(fd), "action-setup-private-output")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(os.Getegid()) || st.Mode&07777 != 0600 || st.Nlink != 1 {
		return ErrSetup
	}
	n, e := f.Write(b)
	if e != nil || n != len(b) || f.Sync() != nil || unix.Fsync(parent) != nil || !parentsUnchanged(path, fds, stats) {
		return ErrSetup
	}
	return nil
}
func createDirectory(path string) error {
	fds, stats, e := protectedParent(path)
	if e != nil {
		return ErrSetup
	}
	defer closeParents(fds)
	parent := fds[len(fds)-1]
	if unix.Mkdirat(parent, filepath.Base(path), 0700) != nil || unix.Fsync(parent) != nil || !parentsUnchanged(path, fds, stats) {
		return ErrSetup
	}
	return nil
}
