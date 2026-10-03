//go:build linux

package lanclientstate

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	stateName = "state.json"
	lockName  = "state.lock"
	tempName  = ".state.tmp"
)

type directory struct {
	file *os.File
	name string
	id   unix.Stat_t
}
type fileOps struct {
	sync   func(int) error
	rename func(int, string, int, string) error
}
type linuxStorage struct {
	chain   []directory
	lock    *os.File
	lockID  unix.Stat_t
	stateID *unix.Stat_t
	hash    [sha256.Size]byte
	ops     fileOps
}

func newStorage(path string) (storage, []byte, bool, error) { return newStorageMode(path, true) }
func newStorageMode(path string, allowCreate bool) (storage, []byte, bool, error) {
	if path == "" || strings.ContainsRune(path, 0) {
		return nil, nil, false, ErrUnsafe
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, false, ErrIO
	}
	s := &linuxStorage{ops: fileOps{sync: unix.Fsync, rename: unix.Renameat}}
	fail := func(err error) (storage, []byte, bool, error) { _ = s.close(); return nil, nil, false, err }
	if err = s.openDirectoryMode(abs, allowCreate); err != nil {
		return fail(err)
	}
	dfd := s.dirFD()
	var existingLock unix.Stat_t
	if err = unix.Fstatat(dfd, lockName, &existingLock, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		if !allowCreate {
			return fail(ErrCorrupt)
		}
		// Do not turn an arbitrary configured directory into a sender store,
		// or create a new lock domain beside an existing sequence ledger.
		if err = s.requireDedicatedDirectory(false); err != nil {
			return fail(err)
		}
	} else if err != nil {
		return fail(ErrIO)
	}
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if allowCreate {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(dfd, lockName, flags, 0600)
	newLock := allowCreate && err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(dfd, lockName, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return fail(safeOpenError(err))
	}
	s.lock = os.NewFile(uintptr(fd), "native-sender-lock")
	if unix.Fstat(fd, &s.lockID) != nil {
		return fail(ErrIO)
	}
	if !privateFile(s.lockID) || s.lockID.Size != 0 {
		return fail(ErrUnsafe)
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return fail(ErrLocked)
		}
		return fail(ErrIO)
	}
	if err = s.verifyPaths(); err != nil {
		return fail(err)
	}
	if newLock {
		if s.ops.sync(fd) != nil || s.ops.sync(dfd) != nil {
			return fail(ErrIO)
		}
	}
	raw, id, err := s.readState()
	fresh := errors.Is(err, os.ErrNotExist)
	if fresh {
		// A missing state beside a preexisting lock might be a deleted sequence
		// ledger. Never silently create a fresh sequence domain in its place.
		if !newLock {
			return fail(ErrCorrupt)
		}
		if err = s.requireDedicatedDirectory(true); err != nil {
			return fail(err)
		}
	} else if err != nil {
		return fail(err)
	} else {
		// A removed/replaced lock must not create a second lock domain for an
		// existing state. A runtime-owned actor/root can still delete all files;
		// this package is not a defense against same-UID or root compromise.
		if newLock {
			return fail(ErrUnsafe)
		}
		s.stateID, s.hash = &id, sha256.Sum256(raw)
	}
	return s, raw, fresh, nil
}

func (s *linuxStorage) requireDedicatedDirectory(allowLock bool) error {
	fd, err := unix.Openat(s.dirFD(), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrIO
	}
	f := os.NewFile(uintptr(fd), "native-sender-directory-entries")
	defer f.Close()
	entries, err := f.ReadDir(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return ErrIO
	}
	if len(entries) == 0 && !allowLock {
		return nil
	}
	if allowLock && len(entries) == 1 && entries[0].Name() == lockName {
		return nil
	}
	return ErrUnsafe
}

func (s *linuxStorage) dirFD() int { return int(s.chain[len(s.chain)-1].file.Fd()) }

// Walk from / with anchored descriptors, never following a symlink. Trusted
// sticky directories (such as /tmp) are acceptable ancestors: other users cannot
// replace a root/runtime-owned child. Every other writable ancestor is rejected.
func (s *linuxStorage) openDirectory(abs string) error { return s.openDirectoryMode(abs, true) }
func (s *linuxStorage) openDirectoryMode(abs string, allowCreate bool) error {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrIO
	}
	root := directory{file: os.NewFile(uintptr(fd), "native-sender-root")}
	s.chain = append(s.chain, root)
	if unix.Fstat(fd, &s.chain[0].id) != nil {
		return ErrIO
	}
	parts := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	if len(parts) == 1 && parts[0] == "" {
		parts = nil
	}
	if !trustedDirectory(s.chain[0].id, len(parts) == 0) {
		return ErrUnsafe
	}
	for i, name := range parts {
		parent := s.dirFD()
		child, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) {
			if !allowCreate {
				return ErrCorrupt
			}
			if err = unix.Mkdirat(parent, name, 0700); err != nil {
				return safeOpenError(err)
			}
			if s.ops.sync(parent) != nil {
				return ErrIO
			}
			child, err = unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			return safeOpenError(err)
		}
		d := directory{file: os.NewFile(uintptr(child), "native-sender-directory"), name: name}
		s.chain = append(s.chain, d)
		d = s.chain[len(s.chain)-1]
		if unix.Fstat(child, &d.id) != nil {
			return ErrIO
		}
		s.chain[len(s.chain)-1].id = d.id
		if !trustedDirectory(d.id, i == len(parts)-1) {
			return ErrUnsafe
		}
	}
	return s.verifyDirectories()
}

func trustedDirectory(st unix.Stat_t, direct bool) bool {
	uid := uint32(os.Geteuid())
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Nlink == 0 || (st.Uid != uid && st.Uid != 0) {
		return false
	}
	if direct {
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

func (s *linuxStorage) verifyDirectories() error {
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
	return nil
}
func (s *linuxStorage) verifyPaths() error {
	if err := s.verifyDirectories(); err != nil {
		return err
	}
	var fd, entry unix.Stat_t
	if unix.Fstat(int(s.lock.Fd()), &fd) != nil {
		return ErrIO
	}
	if unix.Fstatat(s.dirFD(), lockName, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return ErrUnsafe
	}
	if !privateFile(fd) || fd.Size != 0 || !sameFile(fd, s.lockID) || !sameFile(fd, entry) {
		return ErrUnsafe
	}
	return nil
}

func (s *linuxStorage) readState() ([]byte, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := unix.Openat(s.dirFD(), stateName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, st, os.ErrNotExist
	}
	if err != nil {
		return nil, st, safeOpenError(err)
	}
	f := os.NewFile(uintptr(fd), "native-sender-state")
	defer f.Close()
	if unix.Fstat(fd, &st) != nil {
		return nil, st, ErrIO
	}
	if !privateFile(st) {
		return nil, st, ErrUnsafe
	}
	if st.Size < 1 || st.Size > MaxStateBytes {
		return nil, st, ErrCorrupt
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxStateBytes+1))
	if err != nil {
		return nil, st, ErrIO
	}
	if len(raw) > MaxStateBytes || int64(len(raw)) != st.Size {
		return nil, st, ErrCorrupt
	}
	var after, entry unix.Stat_t
	if unix.Fstat(fd, &after) != nil {
		return nil, st, ErrIO
	}
	if unix.Fstatat(s.dirFD(), stateName, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return nil, st, ErrUnsafe
	}
	if !privateFile(after) || !sameFile(st, after) || !sameFile(st, entry) || st.Size != after.Size || st.Mtim != after.Mtim || st.Ctim != after.Ctim {
		return nil, st, ErrUnsafe
	}
	return raw, after, nil
}
func (s *linuxStorage) verify() error {
	if err := s.verifyPaths(); err != nil {
		return err
	}
	raw, st, err := s.readState()
	if s.stateID == nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return ErrUnsafe
	}
	if errors.Is(err, os.ErrNotExist) {
		return ErrUnsafe
	}
	if err != nil {
		return err
	}
	if !sameFile(*s.stateID, st) {
		return ErrUnsafe
	}
	if sha256.Sum256(raw) != s.hash {
		return ErrCorrupt
	}
	return nil
}

func (s *linuxStorage) cleanup() error {
	if err := s.verify(); err != nil {
		return err
	}
	var st unix.Stat_t
	err := unix.Fstatat(s.dirFD(), tempName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return ErrIO
	}
	if !privateFile(st) || st.Size < 0 || st.Size > MaxStateBytes {
		return ErrUnsafe
	}
	// This file is uncommitted work. Only the already validated state.json is
	// authoritative; no recovery flow promotes a temporary file into it.
	if unix.Unlinkat(s.dirFD(), tempName, 0) != nil || s.ops.sync(s.dirFD()) != nil {
		return ErrIO
	}
	return nil
}

// replace writes all bytes, fsyncs the private file, atomically renames it over
// the validated prior state, and fsyncs the containing directory. A caller must
// treat any failure as uncertain and never transmit a failed Stage result.
func (s *linuxStorage) replace(raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxStateBytes {
		return ErrCorrupt
	}
	if err := s.verify(); err != nil {
		return err
	}
	dfd := s.dirFD()
	fd, err := unix.Openat(dfd, tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return safeOpenError(err)
	}
	f := os.NewFile(uintptr(fd), "native-sender-temporary")
	defer f.Close()
	var tempID unix.Stat_t
	if unix.Fstat(fd, &tempID) != nil {
		return ErrIO
	}
	if !privateFile(tempID) {
		return ErrUnsafe
	}
	// Failure leaves the private uncommitted temporary for safe removal on
	// reopen. Never unlink an entry that may have been substituted in place.
	if n, err := f.Write(raw); err != nil || n != len(raw) {
		return ErrIO
	}
	if s.ops.sync(fd) != nil {
		return ErrIO
	}
	if err = s.verify(); err != nil {
		return err
	}
	var current, entry unix.Stat_t
	if unix.Fstat(fd, &current) != nil {
		return ErrIO
	}
	if unix.Fstatat(dfd, tempName, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return ErrUnsafe
	}
	if !privateFile(current) || !sameFile(tempID, current) || !sameFile(tempID, entry) || current.Size != int64(len(raw)) {
		return ErrUnsafe
	}
	if s.ops.rename(dfd, tempName, dfd, stateName) != nil {
		return ErrIO
	}
	s.stateID, s.hash = &current, sha256.Sum256(raw)
	if s.ops.sync(dfd) != nil {
		return ErrIO
	}
	return s.verify()
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
