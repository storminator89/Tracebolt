//go:build linux

package lanstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type managerWriterLease struct {
	file        *os.File
	path        string
	directories map[string]os.FileInfo
	once        sync.Once
	closeErr    error
}

// AcquireManagerWriter holds a nonblocking exclusive flock on the directory
// itself; it creates no lock file and never changes existing ownership/modes.
// Like PrepareProfileDirectory, fresh startup may create private directories.
// The caller must retain the lease until every manager worker/store is stopped
// and closed. Supported filesystem lock semantics need native qualification.
func AcquireManagerWriter(dir string) (ManagerWriterLease, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || strings.ContainsRune(dir, 0) {
		return nil, ErrStorage
	}
	if err := CheckRestoreQuarantine(dir); err != nil {
		return nil, err
	}
	if os.MkdirAll(dir, 0700) != nil || privateStateDirectory(dir) != nil {
		return nil, ErrStorage
	}
	chain := make(map[string]os.FileInfo)
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return nil, ErrStorage
		}
		chain[current] = info
		if filepath.Dir(current) == current {
			break
		}
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrStorage
	}
	lease := &managerWriterLease{file: os.NewFile(uintptr(fd), "manager-writer-directory"), path: dir, directories: chain}
	fail := func(err error) (ManagerWriterLease, error) { _ = lease.Close(); return nil, err }
	var filesystem unix.Statfs_t
	if err = unix.Fstatfs(fd, &filesystem); err != nil {
		if managerWriterUnsupported(err) {
			return fail(ErrManagerWriterUnavailable)
		}
		return fail(ErrStorage)
	}
	if !managerWriterFilesystem(int64(filesystem.Type)) {
		return fail(ErrManagerWriterUnavailable)
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return fail(ErrManagerWriterBusy)
		}
		if managerWriterUnsupported(err) {
			return fail(ErrManagerWriterUnavailable)
		}
		return fail(ErrStorage)
	}
	if err = lease.Check(); err != nil {
		return fail(err)
	}
	return lease, nil
}

func managerWriterUnsupported(err error) bool {
	return err == unix.EOPNOTSUPP || err == unix.ENOSYS || err == unix.EPERM
}

// Remote/FUSE/unknown filesystems have different, configurable or unqualified
// flock semantics. The lease API never returns a successful unheld lease. The
// manager may preserve its old startup behavior on ErrManagerWriterUnavailable,
// without claiming writer exclusion; a future backup must not use that fallback.
// This is a locking boundary, not filesystem durability/native acceptance.
func managerWriterFilesystem(kind int64) bool {
	switch kind {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC:
		return true
	default:
		return false
	}
}

func (*managerWriterLease) String() string   { return "manager-writer-directory-lease" }
func (*managerWriterLease) GoString() string { return "manager-writer-directory-lease" }

func (l *managerWriterLease) Check() error {
	if privateStateDirectory(l.path) != nil {
		return ErrStorage
	}
	for path, original := range l.directories {
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(original, current) {
			return ErrStorage
		}
	}
	opened, err := l.file.Stat()
	if err != nil || !os.SameFile(l.directories[l.path], opened) {
		return ErrStorage
	}
	return CheckRestoreQuarantine(l.path)
}

func (l *managerWriterLease) Close() error {
	l.once.Do(func() {
		if l.file.Close() != nil {
			l.closeErr = ErrStorage
		}
	})
	return l.closeErr
}
