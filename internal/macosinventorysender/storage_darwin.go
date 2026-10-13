//go:build darwin

package macosinventorysender

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"localrmm/internal/darwinprotect"
	state "localrmm/internal/macosinventorystate"
)

type storageDirectory struct {
	file *os.File
	name string
	id   unix.Stat_t
}
type storageFile struct {
	id  unix.Stat_t
	raw []byte
}
type storageFileOps struct {
	sync   func(int) error
	rename func(int, string, int, string, uint32) error
}
type darwinInventoryStorage struct {
	chain  []storageDirectory
	lock   *os.File
	lockID unix.Stat_t
	files  map[string]storageFile
	ops    storageFileOps
	closed bool
}

func openStorageBackend(path string, fresh bool) (storageBackend, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) {
		return nil, ErrStorage
	}
	b := &darwinInventoryStorage{files: make(map[string]storageFile), ops: storageFileOps{sync: darwinprotect.Sync, rename: unix.RenameatxNp}}
	accepted := false
	defer func() {
		if !accepted {
			_ = b.close()
		}
	}()
	if b.openDirectory(path, fresh) != nil {
		return nil, ErrStorage
	}
	entries, err := b.entries()
	if err != nil {
		return nil, ErrStorage
	}
	// A surviving lock alone is interrupted initialization, not a fresh domain.
	if fresh {
		if len(entries) != 0 {
			return nil, ErrStorage
		}
	} else if len(entries) != 4 || !entries[storageLockName] || !entries[storageUsedName] || !entries[storageReadyName] || !entries[storageCheckpointName] {
		return nil, ErrStorage
	}
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if fresh {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(b.dirFD(), storageLockName, flags, 0600)
	if err != nil {
		return nil, ErrStorage
	}
	b.lock = os.NewFile(uintptr(fd), "inventory-storage-lock")
	if darwinprotect.Fstat(fd, &b.lockID) != nil || !storagePrivateFile(b.lockID) || b.lockID.Size != 0 {
		return nil, ErrStorage
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrStorageLocked
		}
		return nil, ErrStorage
	}
	if b.verifyPaths() != nil {
		return nil, ErrStorage
	}
	if fresh {
		if b.ops.sync(fd) != nil || b.ops.sync(b.dirFD()) != nil || b.ops.sync(fd) != nil {
			return nil, ErrStorage
		}
	} else {
		for _, name := range []string{storageUsedName, storageReadyName, storageCheckpointName} {
			raw, id, err := b.readFile(name)
			if err != nil {
				return nil, ErrStorage
			}
			b.files[name] = storageFile{id: id, raw: raw}
		}
	}
	if b.verify("") != nil {
		return nil, ErrStorage
	}
	accepted = true
	return b, nil
}

func storageTrustedDirectory(st unix.Stat_t, direct bool) bool {
	uid := uint32(os.Geteuid())
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Nlink == 0 || st.Uid != uid && st.Uid != 0 {
		return false
	}
	if direct {
		return st.Uid == uid && st.Mode&07777 == 0700
	}
	// A trusted root/runtime-owned sticky ancestor cannot have these owned child
	// entries replaced by a different UID. Expanding ACLs are still rejected.
	return st.Mode&0022 == 0 || st.Mode&unix.S_ISVTX != 0
}
func storagePrivateFile(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}
func storageSameFile(a, b unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }
func storageUnchanged(a, b unix.Stat_t) bool {
	return storageSameFile(a, b) && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Flags == b.Flags
}
func (b *darwinInventoryStorage) dirFD() int { return int(b.chain[len(b.chain)-1].file.Fd()) }

// Only the final dedicated directory may be created; missing ancestors fail.
// Paths are never cleaned, made absolute or symlink-normalized on the caller's behalf.
func (b *darwinInventoryStorage) openDirectory(path string, fresh bool) error {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrStorage
	}
	b.chain = append(b.chain, storageDirectory{file: os.NewFile(uintptr(fd), "inventory-storage-root")})
	if darwinprotect.Fstat(fd, &b.chain[0].id) != nil || !storageTrustedDirectory(b.chain[0].id, false) {
		return ErrStorage
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, name := range parts {
		parent := b.dirFD()
		child, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && fresh && i == len(parts)-1 {
			if unix.Mkdirat(parent, name, 0700) != nil || b.ops.sync(parent) != nil {
				return ErrStorage
			}
			child, err = unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			return ErrStorage
		}
		b.chain = append(b.chain, storageDirectory{file: os.NewFile(uintptr(child), "inventory-storage-directory"), name: name})
		d := &b.chain[len(b.chain)-1]
		if darwinprotect.Fstat(child, &d.id) != nil || !storageTrustedDirectory(d.id, i == len(parts)-1) {
			return ErrStorage
		}
	}
	return b.verifyDirectories()
}
func (b *darwinInventoryStorage) verifyDirectories() error {
	if len(b.chain) == 0 {
		return ErrStorage
	}
	for i, d := range b.chain {
		var current unix.Stat_t
		if darwinprotect.Fstat(int(d.file.Fd()), &current) != nil || !storageSameFile(d.id, current) || !storageTrustedDirectory(current, i == len(b.chain)-1) {
			return ErrStorage
		}
		if i > 0 {
			var entry unix.Stat_t
			if unix.Fstatat(int(b.chain[i-1].file.Fd()), d.name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !storageSameFile(current, entry) || !storageTrustedDirectory(entry, i == len(b.chain)-1) {
				return ErrStorage
			}
		}
	}
	return nil
}
func (b *darwinInventoryStorage) verifyPaths() error {
	if b.closed || b.lock == nil || b.verifyDirectories() != nil {
		return ErrStorage
	}
	var current, entry unix.Stat_t
	if darwinprotect.Fstat(int(b.lock.Fd()), &current) != nil || unix.Fstatat(b.dirFD(), storageLockName, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !storagePrivateFile(current) || current.Size != 0 || !storageUnchanged(b.lockID, current) || !storageUnchanged(current, entry) {
		return ErrStorage
	}
	return nil
}
func (b *darwinInventoryStorage) entries() (map[string]bool, error) {
	fd, err := unix.Openat(b.dirFD(), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrStorage
	}
	f := os.NewFile(uintptr(fd), "inventory-storage-entries")
	defer f.Close()
	entries, err := f.ReadDir(6)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 5 {
		return nil, ErrStorage
	}
	names := make(map[string]bool, len(entries))
	for _, entry := range entries {
		names[entry.Name()] = true
	}
	return names, nil
}
func storageFileLimit(name string) int {
	switch name {
	case storageCheckpointName, storageTempName:
		return state.MaxCheckpointBytes
	case storageUsedName, storageReadyName:
		return storageMarkerMax
	default:
		return 0
	}
}
func (b *darwinInventoryStorage) readFile(name string) ([]byte, unix.Stat_t, error) {
	var id unix.Stat_t
	limit := storageFileLimit(name)
	if limit == 0 {
		return nil, id, ErrStorage
	}
	fd, err := unix.Openat(b.dirFD(), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, id, ErrStorage
	}
	f := os.NewFile(uintptr(fd), "inventory-storage-private-file")
	defer f.Close()
	if darwinprotect.Fstat(fd, &id) != nil || !storagePrivateFile(id) || id.Size < 1 || id.Size > int64(limit) {
		return nil, id, ErrStorage
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || int64(len(raw)) != id.Size || len(raw) > limit {
		return nil, id, ErrStorage
	}
	var after, entry unix.Stat_t
	if darwinprotect.Fstat(fd, &after) != nil || unix.Fstatat(b.dirFD(), name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !storageUnchanged(id, after) || !storageUnchanged(after, entry) {
		return nil, id, ErrStorage
	}
	return raw, after, nil
}
func (b *darwinInventoryStorage) verify(ownedTemp string) error {
	if b.verifyPaths() != nil {
		return ErrStorage
	}
	entries, err := b.entries()
	expected := 1 + len(b.files)
	if ownedTemp != "" {
		expected++
	}
	if err != nil || len(entries) != expected || !entries[storageLockName] {
		return ErrStorage
	}
	if ownedTemp != "" && !entries[ownedTemp] {
		return ErrStorage
	}
	for name, saved := range b.files {
		if !entries[name] {
			return ErrStorage
		}
		raw, id, err := b.readFile(name)
		if err != nil || !storageUnchanged(saved.id, id) || !bytes.Equal(saved.raw, raw) {
			return ErrStorage
		}
	}
	return b.verifyPaths()
}
func (b *darwinInventoryStorage) snapshot() (map[string][]byte, error) {
	if b.verify("") != nil {
		return nil, ErrStorage
	}
	files := make(map[string][]byte, len(b.files))
	for name, saved := range b.files {
		files[name] = bytes.Clone(saved.raw)
	}
	return files, nil
}

// Publication is no-replace for both immutable markers and fresh checkpoints.
// Replacement checks exact prior bytes/inode immediately before rename. All
// callbacks run while Storage is poisoned; uncertainty never unlinks/retries.
func (b *darwinInventoryStorage) publish(name string, expected, next []byte) (result error) {
	limit := storageFileLimit(name)
	if name == storageTempName || limit == 0 || len(next) == 0 || len(next) > limit || b.verify("") != nil {
		return ErrStorage
	}
	saved, exists := b.files[name]
	if exists {
		if name != storageCheckpointName || !bytes.Equal(saved.raw, expected) {
			return ErrStorage
		}
	} else if len(expected) != 0 {
		return ErrStorage
	}
	dfd := b.dirFD()
	fd, err := unix.Openat(dfd, storageTempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrStorage
	}
	f := os.NewFile(uintptr(fd), "inventory-storage-temporary")
	defer func() {
		if f.Close() != nil {
			result = ErrStorage
		}
	}()
	var initial unix.Stat_t
	if darwinprotect.Fstat(fd, &initial) != nil || !storagePrivateFile(initial) {
		return ErrStorage
	}
	if n, err := f.Write(next); err != nil || n != len(next) || b.ops.sync(fd) != nil {
		return ErrStorage
	}
	if b.verify(storageTempName) != nil {
		return ErrStorage
	}
	raw, id, err := b.readFile(storageTempName)
	if err != nil || !storageSameFile(initial, id) || !bytes.Equal(raw, next) {
		return ErrStorage
	}
	// Recheck all expected files, including checkpoint inode and exact bytes,
	// after the temporary is read and immediately before namespace publication.
	if b.verify(storageTempName) != nil {
		return ErrStorage
	}
	flags := uint32(unix.RENAME_EXCL)
	if exists {
		flags = 0
	}
	if b.ops.rename(dfd, storageTempName, dfd, name, flags) != nil {
		return ErrStorage
	}
	raw, id, err = b.readFile(name)
	if err != nil || !storageSameFile(initial, id) || !bytes.Equal(raw, next) {
		return ErrStorage
	}
	b.files[name] = storageFile{id: id, raw: bytes.Clone(next)}
	// Full flush before rename, directory sync afterwards, and a second full
	// flush on the retained same-volume regular descriptor order publication.
	if b.ops.sync(dfd) != nil || b.ops.sync(fd) != nil {
		return ErrStorage
	}
	return b.verify("")
}
func (b *darwinInventoryStorage) close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	var result error
	if b.lock != nil {
		if b.lock.Close() != nil {
			result = ErrStorage
		}
		b.lock = nil
	}
	for i := len(b.chain) - 1; i >= 0; i-- {
		if b.chain[i].file.Close() != nil {
			result = ErrStorage
		}
	}
	b.chain = nil
	return result
}
