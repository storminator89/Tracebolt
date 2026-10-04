//go:build linux

package enrollmentclient

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	storeLockName = "enrollment.lock"
	storeTempName = ".enrollment.tmp"
	storeMaxBytes = 1 << 20
)

type storeDirectory struct {
	file *os.File
	name string
	id   unix.Stat_t
}

type storeFile struct {
	id   unix.Stat_t
	hash [sha256.Size]byte
}

type storeOperations struct {
	sync   func(int) error
	rename func(int, string, int, string, uint) error
}

// localStore holds the lock for the entire enrollment attempt. All operations
// are relative to verified directory descriptors. A storage failure poisons the
// handle: callers must close it and resolve the state rather than retry writes.
// This does not protect against a compromised runtime UID or root.
type localStore struct {
	storeRedaction
	*localStoreData
}

type localStoreData struct {
	mu        sync.Mutex
	chain     []storeDirectory
	lock      *os.File
	lockID    unix.Stat_t
	files     map[string]storeFile
	telemetry *storeDirectory
	ops       storeOperations
	closed    bool
	failed    bool
}

func storeDataName(name string) bool {
	switch name {
	case "ledger.json", "agent-key.pem", "agent-cert.pem", "server-ca.pem", "agent.json", "ready.json", "service-enrollment.json":
		return true
	}
	return false
}

func openStore(absPath string) (*localStore, error)         { return openStoreMode(absPath, false) }
func openExistingStore(absPath string) (*localStore, error) { return openStoreMode(absPath, true) }
func openStoreMode(absPath string, existingOnly bool) (*localStore, error) {
	// Do not normalize away a symlink-bearing component or accept a relative
	// location whose meaning could change during the workflow.
	if !filepath.IsAbs(absPath) || filepath.Clean(absPath) != absPath || absPath == "/" || strings.ContainsRune(absPath, 0) {
		return nil, ErrState
	}
	s := &localStore{localStoreData: &localStoreData{
		files: make(map[string]storeFile),
		ops:   storeOperations{sync: unix.Fsync, rename: unix.Renameat2},
	}}
	fail := func(err error) (*localStore, error) { _ = s.Close(); return nil, err }
	if err := s.openDirectoryMode(absPath, existingOnly); err != nil {
		return fail(err)
	}
	entries, err := s.entries()
	if err != nil {
		return fail(err)
	}
	newLock := len(entries) == 0
	if existingOnly && (newLock || !entries["ledger.json"]) {
		return fail(ErrState)
	}
	if !newLock && !entries[storeLockName] {
		return fail(ErrState)
	}
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if newLock {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(s.dirFD(), storeLockName, flags, 0600)
	if err != nil {
		return fail(ErrState)
	}
	s.lock = os.NewFile(uintptr(fd), "enrollment-lock")
	if unix.Fstat(fd, &s.lockID) != nil || !storePrivateFile(s.lockID) || s.lockID.Size != 0 {
		return fail(ErrState)
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return fail(ErrLocked)
		}
		return fail(ErrState)
	}
	if err = s.verifyPaths(); err != nil {
		return fail(err)
	}
	entries, err = s.entries()
	if err != nil {
		return fail(err)
	}
	if newLock {
		if len(entries) != 1 || !entries[storeLockName] {
			return fail(ErrState)
		}
		if s.ops.sync(fd) != nil || s.ops.sync(s.dirFD()) != nil {
			return fail(ErrState)
		}
	} else {
		// A leftover lock without its ledger can be an interrupted creation or
		// a deleted identity. Neither case permits creating a new identity.
		if !entries["ledger.json"] {
			return fail(ErrState)
		}
		for name := range entries {
			switch {
			case name == storeLockName:
			case name == "telemetry":
				if err = s.openTelemetry(); err != nil {
					return fail(err)
				}
			case storeDataName(name):
				raw, id, readErr := s.readFile(name)
				if readErr != nil {
					return fail(ErrState)
				}
				s.files[name] = storeFile{id: id, hash: sha256.Sum256(raw)}
			default:
				// Unknown files, including interrupted write temporaries, are
				// never adopted, promoted, removed, or repaired.
				return fail(ErrState)
			}
		}
	}
	if err = s.verify(""); err != nil {
		return fail(err)
	}
	return s, nil
}

func (s *localStore) dirFD() int { return int(s.chain[len(s.chain)-1].file.Fd()) }

func storeTrustedDirectory(st unix.Stat_t, direct bool) bool {
	uid := uint32(os.Geteuid())
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Nlink == 0 || (st.Uid != uid && st.Uid != 0) {
		return false
	}
	if direct {
		return st.Uid == uid && st.Mode&07777 == 0700
	}
	// Root/runtime-owned sticky ancestors such as /tmp cannot have their
	// root/runtime-owned children replaced by a different UID.
	return st.Mode&0022 == 0 || st.Mode&unix.S_ISVTX != 0
}

func storePrivateFile(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}

func storeSameFile(a, b unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }

func storeUnchanged(a, b unix.Stat_t) bool {
	return storeSameFile(a, b) && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func (s *localStore) openDirectory(abs string) error { return s.openDirectoryMode(abs, false) }
func (s *localStore) openDirectoryMode(abs string, existingOnly bool) error {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrState
	}
	s.chain = append(s.chain, storeDirectory{file: os.NewFile(uintptr(fd), "enrollment-root")})
	if unix.Fstat(fd, &s.chain[0].id) != nil || !storeTrustedDirectory(s.chain[0].id, false) {
		return ErrState
	}
	parts := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	for i, name := range parts {
		parent := s.dirFD()
		child, openErr := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && i == len(parts)-1 && !existingOnly {
			if unix.Mkdirat(parent, name, 0700) != nil || s.ops.sync(parent) != nil {
				return ErrState
			}
			child, openErr = unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			return ErrState
		}
		s.chain = append(s.chain, storeDirectory{file: os.NewFile(uintptr(child), "enrollment-directory"), name: name})
		d := &s.chain[len(s.chain)-1]
		if unix.Fstat(child, &d.id) != nil || !storeTrustedDirectory(d.id, i == len(parts)-1) {
			return ErrState
		}
	}
	return s.verifyDirectories()
}

func (s *localStore) verifyDirectories() error {
	for i, d := range s.chain {
		var current unix.Stat_t
		if unix.Fstat(int(d.file.Fd()), &current) != nil || !storeSameFile(d.id, current) || !storeTrustedDirectory(current, i == len(s.chain)-1) {
			return ErrState
		}
		if i > 0 {
			var entry unix.Stat_t
			if unix.Fstatat(int(s.chain[i-1].file.Fd()), d.name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !storeSameFile(current, entry) {
				return ErrState
			}
		}
	}
	return nil
}

func (s *localStore) verifyPaths() error {
	if err := s.verifyDirectories(); err != nil {
		return err
	}
	var current, entry unix.Stat_t
	if s.lock == nil || unix.Fstat(int(s.lock.Fd()), &current) != nil || unix.Fstatat(s.dirFD(), storeLockName, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return ErrState
	}
	if !storePrivateFile(current) || !storePrivateFile(entry) || current.Size != 0 || !storeUnchanged(s.lockID, current) || !storeUnchanged(current, entry) {
		return ErrState
	}
	if s.telemetry != nil {
		if unix.Fstat(int(s.telemetry.file.Fd()), &current) != nil || unix.Fstatat(s.dirFD(), "telemetry", &entry, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return ErrState
		}
		if !storeTrustedDirectory(current, true) || !storeTrustedDirectory(entry, true) || !storeSameFile(s.telemetry.id, current) || !storeSameFile(current, entry) {
			return ErrState
		}
	}
	return nil
}

// entries only reads the enrollment directory. In particular, it never walks
// telemetry or reads the independent sender's lock, ledger, or pending state.
func (s *localStore) entries() (map[string]bool, error) {
	fd, err := unix.Openat(s.dirFD(), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrState
	}
	f := os.NewFile(uintptr(fd), "enrollment-directory-entries")
	defer f.Close()
	entries, err := f.ReadDir(11)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > 10 {
		return nil, ErrState
	}
	names := make(map[string]bool, len(entries))
	for _, entry := range entries {
		names[entry.Name()] = true
	}
	return names, nil
}

func (s *localStore) readFile(name string) ([]byte, unix.Stat_t, error) {
	var id unix.Stat_t
	fd, err := unix.Openat(s.dirFD(), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, id, os.ErrNotExist
	}
	if err != nil {
		return nil, id, ErrState
	}
	f := os.NewFile(uintptr(fd), "enrollment-private-file")
	defer f.Close()
	if unix.Fstat(fd, &id) != nil || !storePrivateFile(id) || id.Size < 1 || id.Size > storeMaxBytes {
		return nil, id, ErrState
	}
	raw, err := io.ReadAll(io.LimitReader(f, storeMaxBytes+1))
	if err != nil || int64(len(raw)) != id.Size || len(raw) > storeMaxBytes {
		return nil, id, ErrState
	}
	var after, entry unix.Stat_t
	if unix.Fstat(fd, &after) != nil || unix.Fstatat(s.dirFD(), name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return nil, id, ErrState
	}
	if !storePrivateFile(after) || !storePrivateFile(entry) || !storeUnchanged(id, after) || !storeUnchanged(after, entry) {
		return nil, id, ErrState
	}
	return raw, after, nil
}

func (s *localStore) verify(ownedTemp string) error {
	if s.closed || s.failed || len(s.chain) == 0 {
		return ErrState
	}
	if err := s.verifyPaths(); err != nil {
		return err
	}
	entries, err := s.entries()
	if err != nil || !entries[storeLockName] {
		return ErrState
	}
	for name := range entries {
		if name == storeLockName || (name == "telemetry" && s.telemetry != nil) || (name == ownedTemp && ownedTemp != "") {
			continue
		}
		if _, ok := s.files[name]; !ok {
			return ErrState
		}
	}
	for name, saved := range s.files {
		raw, current, readErr := s.readFile(name)
		if readErr != nil || !storeUnchanged(saved.id, current) || saved.hash != sha256.Sum256(raw) {
			return ErrState
		}
	}
	return s.verifyPaths()
}

func (s *localStore) Read(name string) ([]byte, error) {
	if s == nil || !storeDataName(name) {
		return nil, ErrState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.verify(""); err != nil {
		s.failed = true
		return nil, err
	}
	saved, ok := s.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	raw, id, err := s.readFile(name)
	if err != nil || !storeUnchanged(saved.id, id) || sha256.Sum256(raw) != saved.hash || s.verifyPaths() != nil {
		s.failed = true
		return nil, ErrState
	}
	return raw, nil
}

// Write durably creates a private temporary, then atomically publishes it.
// First writes use RENAME_NOREPLACE. Replacements require the previous file to
// match its validated snapshot immediately before rename. Any uncertain result
// fails closed; no path ever unlinks a leftover temporary or unrelated file.
func (s *localStore) Write(name string, raw []byte) (result error) {
	if s == nil || !storeDataName(name) || len(raw) == 0 || len(raw) > storeMaxBytes {
		return ErrState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if result != nil {
			s.failed = true
		}
	}()
	if err := s.verify(""); err != nil {
		return err
	}
	dfd := s.dirFD()
	fd, err := unix.Openat(dfd, storeTempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrState
	}
	f := os.NewFile(uintptr(fd), "enrollment-private-temporary")
	defer f.Close()
	var initial unix.Stat_t
	if unix.Fstat(fd, &initial) != nil || !storePrivateFile(initial) {
		return ErrState
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) || s.ops.sync(fd) != nil {
		return ErrState
	}
	if err = s.verify(storeTempName); err != nil {
		return err
	}
	stored, current, err := s.readFile(storeTempName)
	wantHash := sha256.Sum256(raw)
	if err != nil || !storeSameFile(initial, current) || sha256.Sum256(stored) != wantHash {
		return ErrState
	}
	flags := uint(unix.RENAME_NOREPLACE)
	if _, exists := s.files[name]; exists {
		flags = 0
	}
	if s.ops.rename(dfd, storeTempName, dfd, name, flags) != nil {
		return ErrState
	}
	// A successful rename can update ctime. Take its post-rename snapshot only
	// after checking that it is still the exact inode and bytes we wrote.
	stored, current, err = s.readFile(name)
	if err != nil || !storeSameFile(initial, current) || sha256.Sum256(stored) != wantHash {
		return ErrState
	}
	s.files[name] = storeFile{id: current, hash: wantHash}
	if s.ops.sync(dfd) != nil {
		return ErrState
	}
	return s.verify("")
}

func (s *localStore) openTelemetry() error {
	fd, err := unix.Openat(s.dirFD(), "telemetry", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrState
	}
	s.telemetry = &storeDirectory{file: os.NewFile(uintptr(fd), "enrollment-telemetry-directory"), name: "telemetry"}
	if unix.Fstat(fd, &s.telemetry.id) != nil || !storeTrustedDirectory(s.telemetry.id, true) {
		return ErrState
	}
	return nil
}

// TelemetryExists checks the already validated directory entry without creating
// anything or inspecting the independent sender's files. A missing directory on
// reopen is reported distinctly so a published handoff cannot reset sender state.
func (s *localStore) TelemetryExists() (bool, error) {
	if s == nil {
		return false, ErrState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.verify(""); err != nil {
		s.failed = true
		return false, err
	}
	return s.telemetry != nil, nil
}

func (s *localStore) EnsureTelemetry() (result error) {
	if s == nil {
		return ErrState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if result != nil {
			s.failed = true
		}
	}()
	if err := s.verify(""); err != nil {
		return err
	}
	if s.telemetry != nil {
		return nil
	}
	if unix.Mkdirat(s.dirFD(), "telemetry", 0700) != nil {
		return ErrState
	}
	if err := s.openTelemetry(); err != nil {
		return err
	}
	if s.ops.sync(int(s.telemetry.file.Fd())) != nil || s.ops.sync(s.dirFD()) != nil {
		return ErrState
	}
	return s.verify("")
}

func (s *localStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var result error
	if s.telemetry != nil {
		if s.telemetry.file.Close() != nil {
			result = ErrState
		}
		s.telemetry = nil
	}
	if s.lock != nil {
		if s.lock.Close() != nil {
			result = ErrState
		}
		s.lock = nil
	}
	for i := len(s.chain) - 1; i >= 0; i-- {
		if s.chain[i].file.Close() != nil {
			result = ErrState
		}
	}
	s.chain = nil
	return result
}
