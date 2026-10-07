//go:build linux

package mutationfence

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"syscall"
)

func checkDirectory(dir string) (os.FileInfo, uint32, error) {
	var direct os.FileInfo
	owner := uint32(os.Geteuid())
	for p := dir; ; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return nil, 0, ErrInvalid
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || (s.Uid != 0 && s.Uid != owner) || i.Mode().Perm()&0022 != 0 && i.Mode()&os.ModeSticky == 0 {
			return nil, 0, ErrInvalid
		}
		if p == dir {
			if s.Uid != owner || i.Mode().Perm() != 0700 {
				return nil, 0, ErrInvalid
			}
			direct = i
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return direct, owner, nil
}
func openPrivate(path string, flags int, owner uint32) (*os.File, error) {
	fd, e := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, ErrInvalid
	}
	f := os.NewFile(uintptr(fd), "endpoint-mutation-fence")
	if e = checkNamedFile(f, path, owner); e != nil {
		_ = f.Close()
		return nil, e
	}
	return f, nil
}
func checkNamedFile(f *os.File, path string, owner uint32) error {
	a, e := f.Stat()
	if e != nil {
		return ErrInvalid
	}
	b, e := os.Lstat(path)
	if e != nil || !os.SameFile(a, b) || !a.Mode().IsRegular() || a.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || a.Mode().Perm() != 0600 || a.Size() > MaxBytes {
		return ErrInvalid
	}
	s, ok := a.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != owner || s.Nlink != 1 {
		return ErrInvalid
	}
	return nil
}
func lockFile(f *os.File) error {
	if e := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return ErrBusy
	}
	return nil
}
func unlockFile(f *os.File) { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }
func syncDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
