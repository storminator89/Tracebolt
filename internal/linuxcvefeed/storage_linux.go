//go:build linux

package linuxcvefeed

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const lockName = ".security-data.lock"

type directory struct {
	file *os.File
	name string
	id   unix.Stat_t
}

type linuxStorage struct {
	chain  []directory
	lock   *os.File
	lockID unix.Stat_t
	sync   func(int) error
	rename func(int, string, int, string, uint) error
}

func openStorage(path string) (storage, error) {
	if !filepath.IsAbs(path) || path == "/" || strings.ContainsRune(path, 0) {
		return nil, ErrUnsafe
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." || part == "." {
			return nil, ErrUnsafe
		}
	}
	s := &linuxStorage{sync: unix.Fsync, rename: unix.Renameat2}
	fail := func(err error) (storage, error) { _ = s.close(); return nil, err }
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(ErrIO)
	}
	s.chain = append(s.chain, directory{file: os.NewFile(uintptr(fd), "cve-cache-root")})
	if unix.Fstat(fd, &s.chain[0].id) != nil || !trustedDirectory(s.chain[0].id, false) {
		return fail(ErrUnsafe)
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	for i, name := range parts {
		parent := s.dirFD()
		child, openErr := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && i == len(parts)-1 {
			// No recursive mkdir or permission repair: this cache is a child of
			// the manager's already protected StateDirectory.
			var parentID unix.Stat_t
			if unix.Fstat(parent, &parentID) != nil || !trustedDirectory(parentID, true) {
				return fail(ErrUnsafe)
			}
			if err = unix.Mkdirat(parent, name, 0700); err != nil {
				return fail(safeOpenError(err))
			}
			if s.sync(parent) != nil {
				return fail(ErrIO)
			}
			child, openErr = unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			return fail(safeOpenError(openErr))
		}
		d := directory{file: os.NewFile(uintptr(child), "cve-cache-directory"), name: name}
		s.chain = append(s.chain, d)
		if unix.Fstat(child, &s.chain[len(s.chain)-1].id) != nil || !trustedDirectory(s.chain[len(s.chain)-1].id, i == len(parts)-1) {
			return fail(ErrUnsafe)
		}
	}
	fd, err = unix.Openat(s.dirFD(), lockName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(s.dirFD(), lockName, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return fail(safeOpenError(err))
	}
	s.lock = os.NewFile(uintptr(fd), "cve-cache-lock")
	if unix.Fstat(fd, &s.lockID) != nil || !privateFile(s.lockID) || s.lockID.Size != 0 {
		return fail(ErrUnsafe)
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			return fail(ErrLocked)
		}
		return fail(ErrIO)
	}
	if err = s.verify(); err != nil {
		return fail(err)
	}
	if created && (s.sync(fd) != nil || s.sync(s.dirFD()) != nil) {
		return fail(ErrIO)
	}
	return s, nil
}

func (s *linuxStorage) dirFD() int { return int(s.chain[len(s.chain)-1].file.Fd()) }

func trustedDirectory(st unix.Stat_t, private bool) bool {
	uid := uint32(os.Geteuid())
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Nlink == 0 || (st.Uid != uid && st.Uid != 0) {
		return false
	}
	if private {
		return st.Uid == uid && st.Mode&07777 == 0700
	}
	return st.Mode&0022 == 0 || st.Mode&unix.S_ISVTX != 0
}

func privateFile(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}

func sameFile(a, b unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }

func safeOpenError(err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.EEXIST) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return ErrUnsafe
	}
	return ErrIO
}

func (s *linuxStorage) verify() error {
	if len(s.chain) == 0 || s.lock == nil {
		return ErrIO
	}
	for i, d := range s.chain {
		var current unix.Stat_t
		if unix.Fstat(int(d.file.Fd()), &current) != nil {
			return ErrIO
		}
		if !sameFile(d.id, current) || !trustedDirectory(current, i == len(s.chain)-1) {
			return ErrUnsafe
		}
		if i > 0 {
			var entry unix.Stat_t
			if unix.Fstatat(int(s.chain[i-1].file.Fd()), d.name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameFile(current, entry) {
				return ErrUnsafe
			}
		}
	}
	var current, entry unix.Stat_t
	if unix.Fstat(int(s.lock.Fd()), &current) != nil || unix.Fstatat(s.dirFD(), lockName, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return ErrUnsafe
	}
	if !privateFile(current) || current.Size != 0 || !sameFile(s.lockID, current) || !sameFile(current, entry) {
		return ErrUnsafe
	}
	return nil
}

func validFilename(name string) bool {
	return name == "debian-security-tracker.json" || name == "canonical-ubuntu-osv.json"
}

func (s *linuxStorage) read(name string) ([]byte, error) {
	if !validFilename(name) {
		return nil, ErrUnsafe
	}
	if err := s.verify(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(s.dirFD(), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, safeOpenError(err)
	}
	f := os.NewFile(uintptr(fd), "cve-cache-snapshot")
	defer f.Close()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil {
		return nil, ErrIO
	}
	if !privateFile(before) {
		return nil, ErrUnsafe
	}
	if before.Size < 1 || before.Size > MaxCacheBytes {
		return nil, ErrCache
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxCacheBytes+1))
	if err != nil {
		return nil, ErrIO
	}
	if int64(len(raw)) != before.Size || len(raw) > MaxCacheBytes {
		return nil, ErrCache
	}
	var after, entry unix.Stat_t
	if unix.Fstat(fd, &after) != nil || unix.Fstatat(s.dirFD(), name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return nil, ErrIO
	}
	if !privateFile(after) || !sameFile(before, after) || !sameFile(after, entry) || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, ErrUnsafe
	}
	if err = s.verify(); err != nil {
		return nil, err
	}
	return raw, nil
}

// entry accepts only private regular files, including interrupted empty stages.
func (s *linuxStorage) entry(name string) (unix.Stat_t, bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(s.dirFD(), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return st, false, nil
	}
	if err != nil {
		return st, false, ErrIO
	}
	if !privateFile(st) || st.Size < 0 || st.Size > MaxCacheBytes {
		return st, false, ErrUnsafe
	}
	return st, true, nil
}

func (s *linuxStorage) removeSame(name string, id unix.Stat_t) error {
	st, exists, err := s.entry(name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if !sameFile(st, id) {
		return ErrUnsafe
	}
	if unix.Unlinkat(s.dirFD(), name, 0) != nil {
		return ErrIO
	}
	return nil
}

func (s *linuxStorage) replace(name string, raw []byte) error {
	if !validFilename(name) || len(raw) == 0 || len(raw) > MaxCacheBytes {
		return ErrCache
	}
	if err := s.verify(); err != nil {
		return err
	}
	prior, exists, err := s.entry(name)
	if err != nil {
		return err
	}
	stage := "." + name + ".tmp"
	if stale, present, e := s.entry(stage); e != nil {
		return e
	} else if present {
		// Stages are never recovered as snapshots. Remove only our fixed private
		// stage after acquiring the directory's exclusive lifetime lock.
		if e = s.removeSame(stage, stale); e != nil {
			return e
		}
		if s.sync(s.dirFD()) != nil {
			return ErrIO
		}
	}
	fd, err := unix.Openat(s.dirFD(), stage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return safeOpenError(err)
	}
	f := os.NewFile(uintptr(fd), "cve-cache-stage")
	defer f.Close()
	var id unix.Stat_t
	if unix.Fstat(fd, &id) != nil || !privateFile(id) {
		return ErrUnsafe
	}
	// On a failed pre-commit write, remove only the exact stage inode we made.
	cleanupID := id
	cleanup := true
	defer func() {
		if cleanup {
			_ = s.removeSame(stage, cleanupID)
		}
	}()
	if n, e := f.Write(raw); e != nil || n != len(raw) {
		return ErrIO
	}
	if s.sync(fd) != nil {
		return ErrIO
	}
	if err = s.verify(); err != nil {
		return err
	}
	current, present, err := s.entry(stage)
	if err != nil || !present || !sameFile(id, current) || current.Size != int64(len(raw)) {
		return ErrUnsafe
	}
	old, stillExists, err := s.entry(name)
	if err != nil || exists != stillExists || exists && !sameFile(old, prior) {
		return ErrUnsafe
	}
	flags := uint(unix.RENAME_NOREPLACE)
	if exists {
		flags = unix.RENAME_EXCHANGE
	}
	if s.rename(s.dirFD(), stage, s.dirFD(), name, flags) != nil {
		return ErrIO
	}
	if exists {
		cleanupID = prior
	}
	if s.sync(s.dirFD()) != nil {
		// Keep the previous file in the stage slot until the directory commit is
		// durable. Restore it if durability fails; no new in-memory snapshot is
		// published. A second I/O failure is explicitly reported as uncertain.
		if exists {
			if s.rename(s.dirFD(), stage, s.dirFD(), name, unix.RENAME_EXCHANGE) != nil {
				cleanup = false // retain the old file for recovery after uncertain I/O
				return ErrUncertain
			}
			cleanupID = id
		} else if err = s.removeSame(name, id); err != nil {
			return ErrUncertain
		}
		if s.sync(s.dirFD()) != nil {
			return ErrUncertain
		}
		return ErrIO
	}
	// Durable commit point. Removing an old, private stage is housekeeping; a
	// cleanup failure cannot turn a committed snapshot into a reported failure.
	if exists {
		_ = s.removeSame(stage, prior)
		_ = s.sync(s.dirFD())
	}
	return nil
}

func (s *linuxStorage) close() error {
	var result error
	if s.lock != nil {
		if s.lock.Close() != nil {
			result = ErrIO
		}
		s.lock = nil
	}
	for i := len(s.chain) - 1; i >= 0; i-- {
		if s.chain[i].file.Close() != nil {
			result = ErrIO
		}
	}
	s.chain = nil
	return result
}
