//go:build linux

package journalgenerationstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	stateName = "journal-generation.json"
	lockName  = "journal-generation.lock"
	tempName  = ".journal-generation.tmp"
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

func newStorage(ctx context.Context, path string, initialize bool) (storage, []byte, error) {
	if canceled(ctx) {
		return nil, nil, ErrCanceled
	}
	if path == "" || strings.ContainsRune(path, 0) {
		return nil, nil, ErrUnsafe
	}
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, nil, ErrIO
	}
	s := &linuxStorage{ops: fileOps{sync: unix.Fsync, rename: unix.Renameat}}
	fail := func(e error) (storage, []byte, error) { _ = s.close(); return nil, nil, e }
	if e = s.openDirectory(ctx, abs, initialize); e != nil {
		return fail(e)
	}
	dfd := s.dirFD()
	if initialize {
		if e = s.requireDedicatedDirectory(false); e != nil {
			return fail(e)
		}
	}
	if canceled(ctx) {
		return fail(ErrCanceled)
	}
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if initialize {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, e := unix.Openat(dfd, lockName, flags, 0600)
	if errors.Is(e, unix.ENOENT) {
		return fail(ErrCorrupt)
	}
	if e != nil {
		return fail(safeOpenError(e))
	}
	s.lock = os.NewFile(uintptr(fd), "journal-generation-lock")
	if unix.Fstat(fd, &s.lockID) != nil {
		return fail(ErrIO)
	}
	if !privateFile(s.lockID) || s.lockID.Size != 0 {
		return fail(ErrUnsafe)
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		if errors.Is(e, unix.EWOULDBLOCK) || errors.Is(e, unix.EAGAIN) {
			return fail(ErrLocked)
		}
		return fail(ErrIO)
	}
	if e = s.verifyPaths(); e != nil {
		return fail(e)
	}
	if initialize {
		if s.ops.sync(fd) != nil || s.ops.sync(dfd) != nil {
			return fail(ErrUncertain)
		}
		if e = s.requireDedicatedDirectory(true); e != nil {
			return fail(e)
		}
		return s, nil, nil
	}
	raw, id, e := s.readState()
	if errors.Is(e, os.ErrNotExist) {
		return fail(ErrCorrupt)
	}
	if e != nil {
		return fail(e)
	}
	s.stateID, s.hash = &id, sha256.Sum256(raw)
	if e = s.inspect(); e != nil {
		return fail(e)
	}
	return s, raw, nil
}

func (s *linuxStorage) requireDedicatedDirectory(allowLock bool) error {
	fd, err := unix.Openat(s.dirFD(), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrIO
	}
	f := os.NewFile(uintptr(fd), "journal-generation-directory-entries")
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
func (s *linuxStorage) openDirectory(ctx context.Context, abs string, allowCreate bool) error {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrIO
	}
	root := directory{file: os.NewFile(uintptr(fd), "journal-generation-root")}
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
			if !allowCreate || i != len(parts)-1 {
				return ErrCorrupt
			}
			if canceled(ctx) {
				return ErrCanceled
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
		d := directory{file: os.NewFile(uintptr(child), "journal-generation-directory"), name: name}
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
	f := os.NewFile(uintptr(fd), "journal-generation-state")
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
func (s *linuxStorage) verifyBase() error {
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

// inspect never removes or promotes a crash temporary. Unknown entries are
// unsafe; a recognized temporary is uncertain even if it looks well-formed.
func (s *linuxStorage) inspect() error {
	fd, e := unix.Openat(s.dirFD(), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrIO
	}
	f := os.NewFile(uintptr(fd), "journal-generation-entries")
	defer f.Close()
	entries, e := f.ReadDir(4)
	if e != nil && !errors.Is(e, io.EOF) {
		return ErrIO
	}
	for _, entry := range entries {
		switch entry.Name() {
		case lockName, stateName:
		case tempName:
			return ErrUncertain
		default:
			return ErrUnsafe
		}
	}
	if len(entries) > 2 {
		return ErrUnsafe
	}
	return nil
}
func (s *linuxStorage) verify() error {
	if e := s.verifyBase(); e != nil {
		return e
	}
	return s.inspect()
}

// replace fsyncs complete bytes, atomically replaces the checked record, then
// fsyncs the directory. All errors after temporary creation are uncertain. No
// failure removes a temporary or returns collection permission.
func (s *linuxStorage) replace(ctx context.Context, raw []byte) error {
	if canceled(ctx) {
		return ErrCanceled
	}
	if len(raw) == 0 || len(raw) > MaxStateBytes {
		return ErrCorrupt
	}
	if e := s.verify(); e != nil {
		return e
	}
	if canceled(ctx) {
		return ErrCanceled
	}
	dfd := s.dirFD()
	fd, e := unix.Openat(dfd, tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if e != nil {
		return safeOpenError(e)
	}
	f := os.NewFile(uintptr(fd), "journal-generation-temporary")
	defer f.Close()
	var tempID unix.Stat_t
	if unix.Fstat(fd, &tempID) != nil || !privateFile(tempID) {
		return ErrUncertain
	}
	if canceled(ctx) {
		return ErrUncertain
	}
	if n, e := f.Write(raw); e != nil || n != len(raw) {
		return ErrUncertain
	}
	if s.ops.sync(fd) != nil {
		return ErrUncertain
	}
	if e = s.verifyBase(); e != nil {
		return ErrUncertain
	}
	var current, entry unix.Stat_t
	if unix.Fstat(fd, &current) != nil || unix.Fstatat(dfd, tempName, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return ErrUncertain
	}
	if !privateFile(current) || !sameFile(tempID, current) || !sameFile(tempID, entry) || current.Size != int64(len(raw)) {
		return ErrUncertain
	}
	if canceled(ctx) {
		return ErrUncertain
	}
	if s.ops.rename(dfd, tempName, dfd, stateName) != nil {
		return ErrUncertain
	}
	s.stateID, s.hash = &current, sha256.Sum256(raw)
	if s.ops.sync(dfd) != nil {
		return ErrUncertain
	}
	if s.verify() != nil {
		return ErrUncertain
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
