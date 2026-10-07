//go:build linux

package packageupdatestore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"localrmm/internal/packageupdate"
)

// As in enrollmentstore, the private direct directory and trusted ancestor
// chain exclude cross-account pathname replacement. Same-UID/root compromise
// and replacement with a complete older backup are outside this local boundary.
// No existing path is chmodded, followed through a symlink, or adopted as new.
type protectedFile struct {
	path        string
	file        *os.File
	info        os.FileInfo
	directories map[string]os.FileInfo
}

func privateDirectoryChain(dir string) (map[string]os.FileInfo, error) {
	chain := map[string]os.FileInfo{}
	for current, direct := dir, true; ; current, direct = filepath.Dir(current), false {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrStorage
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != uint32(os.Geteuid()) && st.Uid != 0) || st.Nlink == 0 {
			return nil, ErrStorage
		}
		if direct && (st.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0) {
			return nil, ErrStorage
		}
		if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return nil, ErrStorage
		}
		chain[current] = info
		if filepath.Dir(current) == current {
			break
		}
	}
	return chain, nil
}

func privateFile(path string, required bool) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if !required && os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() > databaseCap {
		return nil, ErrStorage
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return nil, ErrStorage
	}
	return info, nil
}

func openProtected(path string, create bool) (*protectedFile, error) {
	absolute, err := normalizedPath(path)
	if err != nil || strings.ContainsRune(absolute, 0) {
		return nil, ErrStorage
	}
	chain, err := privateDirectoryChain(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		info, err := privateFile(absolute+suffix, false)
		if err != nil || (create && info != nil) {
			return nil, ErrStorage
		}
		// This package never uses WAL. Foreign WAL state is not adopted or migrated.
		if info != nil && suffix != "-journal" {
			return nil, ErrStorage
		}
	}
	if !create {
		info, err := privateFile(absolute, true)
		if err != nil || info.Size() == 0 {
			return nil, ErrStorage
		}
	}
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Open(absolute, flags, 0600)
	if err != nil {
		return nil, ErrStorage
	}
	f := &protectedFile{path: absolute, file: os.NewFile(uintptr(fd), "package-update-state"), directories: chain}
	fail := func(err error) (*protectedFile, error) { _ = f.file.Close(); return nil, err }
	if f.info, err = f.file.Stat(); err != nil {
		return fail(ErrStorage)
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return fail(ErrLocked)
		}
		return fail(ErrStorage)
	}
	if err = f.check(); err != nil {
		return fail(err)
	}
	if !create {
		// No crash recovery is implicit in opening. Even a leftover rollback
		// journal requires explicit future reconciliation outside this package.
		if _, err := os.Lstat(absolute + "-journal"); err == nil {
			return fail(packageupdate.ErrUncertain)
		} else if !os.IsNotExist(err) {
			return fail(ErrStorage)
		}
		var header [20]byte
		if _, err := f.file.ReadAt(header[:], 0); err != nil || string(header[:16]) != "SQLite format 3\x00" || header[18] != 1 || header[19] != 1 {
			return fail(ErrStorage)
		}
	}
	return f, nil
}

func (f *protectedFile) check() error {
	chain, err := privateDirectoryChain(filepath.Dir(f.path))
	if err != nil {
		return err
	}
	if len(chain) != len(f.directories) {
		return ErrStorage
	}
	for path, original := range f.directories {
		current, ok := chain[path]
		if !ok || !os.SameFile(original, current) {
			return ErrStorage
		}
	}
	info, err := privateFile(f.path, true)
	if err != nil || !os.SameFile(f.info, info) {
		return ErrStorage
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		info, err := privateFile(f.path+suffix, false)
		if err != nil || (info != nil && suffix != "-journal") {
			return ErrStorage
		}
	}
	return nil
}

func (f *protectedFile) sync() error {
	if err := f.file.Sync(); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(f.path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (f *protectedFile) close() error { return f.file.Close() }
