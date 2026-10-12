//go:build linux

package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"golang.org/x/sys/unix"
	"io"
	msi "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowssoftwarejob"
	"os"
	"path/filepath"
)

type artifactCache struct {
	stat   unix.Stat_t
	sha    string
	chunks []string
}

func sameArtifact(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func (s *Spool) check() error {
	fds, stats, e := protectedParent(filepath.Join(s.directory, artifactName))
	if e != nil {
		return ErrSpool
	}
	defer closeParents(fds)
	st := stats[len(stats)-1]
	if st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(os.Getegid()) || st.Mode&07777 != 0700 {
		return ErrSpool
	}
	dup, e := unix.Openat(fds[len(fds)-1], ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrSpool
	}
	f := os.NewFile(uintptr(dup), "managed-msi-spool")
	defer f.Close()
	names, e := f.Readdirnames(3)
	if e != nil && e != io.EOF {
		return ErrSpool
	}
	if len(names) > 1 || len(names) == 1 && names[0] != artifactName {
		return ErrSpool
	}
	return nil
}

type uploadCache struct {
	stat      unix.Stat_t
	offset    int64
	prefix    string
	hashState []byte
}

func (s *Spool) appendChunk(ctx context.Context, a msi.Artifact, data []byte, final func() error) (string, error) {
	path := filepath.Join(s.directory, artifactName)
	fds, parents, e := protectedParent(path)
	if e != nil {
		return "", ErrSpool
	}
	defer closeParents(fds)
	dir := fds[len(fds)-1]
	fd, e := unix.Openat(dir, artifactName, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e == unix.ENOENT && a.Offset == 0 {
		fd, e = unix.Openat(dir, artifactName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
		if e == nil && unix.Fsync(dir) != nil {
			unix.Close(fd)
			return "", ErrSpool
		}
	}
	if e != nil {
		return "", ErrSpool
	}
	f := os.NewFile(uintptr(fd), "managed-msi-artifact")
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Size < a.Offset || before.Size > a.Offset+int64(len(data)) || before.Size > a.Package.Size || !validArtifact(before, before.Size) {
		return "", ErrSpool
	}
	h := sha256.New()
	if cached := s.uploadCache; cached != nil && cached.offset == a.Offset && cached.prefix == a.PrefixDigest && sameArtifact(cached.stat, before) {
		if h.(encoding.BinaryUnmarshaler).UnmarshalBinary(cached.hashState) != nil {
			return "", ErrSpool
		}
	} else {
		if _, e = io.Copy(h, io.NewSectionReader(f, 0, a.Offset)); e != nil || "sha256:"+hex.EncodeToString(h.Sum(nil)) != a.PrefixDigest {
			return "", ErrSpool
		}
	}
	// Crash after append but before metadata checkpoint: only the identical
	// pending chunk's prefix can already exist. Never truncate or replace bytes.
	tail := before.Size - a.Offset
	if tail > 0 {
		stored := make([]byte, tail)
		if _, e = f.ReadAt(stored, a.Offset); e != nil || !bytes.Equal(stored, data[:tail]) {
			return "", ErrSpool
		}
	}
	if a.Offset == 0 && !bytes.Equal(data[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}) {
		return "", ErrSpool
	}
	if ctx.Err() != nil {
		return "", ErrSpool
	}
	if tail < int64(len(data)) {
		n, e := f.WriteAt(data[tail:], a.Offset+tail)
		if e != nil || n != len(data)-int(tail) {
			return "", ErrSpool
		}
	}
	h.Write(data)
	prefix := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if a.Offset+int64(len(data)) == a.Package.Size && prefix != a.Package.SHA256 {
		return "", ErrSpool
	}
	if f.Sync() != nil || unix.Fsync(dir) != nil || unix.Fstat(fd, &after) != nil || !validArtifact(after, a.Offset+int64(len(data))) || before.Dev != after.Dev || before.Ino != after.Ino || unix.Fstatat(dir, artifactName, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameArtifact(named, after) || !parentsUnchanged(path, fds, parents) || ctx.Err() != nil || final() != nil {
		return "", ErrSpool
	}
	state, e := h.(encoding.BinaryMarshaler).MarshalBinary()
	if e != nil {
		return "", ErrSpool
	}
	s.uploadCache = &uploadCache{after, after.Size, prefix, state}
	s.cache = nil
	return prefix, nil
}
func validArtifact(st unix.Stat_t, size int64) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Gid == uint32(os.Getegid()) && st.Nlink == 1 && st.Size == size
}
func (s *Spool) readChunk(ctx context.Context, sel windowssoftwarejob.Selection, index uint32) ([]byte, error) {
	path := filepath.Join(s.directory, artifactName)
	fds, parents, e := protectedParent(path)
	if e != nil {
		return nil, ErrSpool
	}
	defer closeParents(fds)
	fd, e := unix.Openat(fds[len(fds)-1], artifactName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrSpool
	}
	f := os.NewFile(uintptr(fd), "managed-msi-artifact")
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !validArtifact(before, sel.Size) {
		return nil, ErrSpool
	}
	// On first open (including restart), hash the exact complete file once and
	// retain bounded chunk digests. Later chunks verify identity/timestamps plus
	// their digest, avoiding 4096 complete 128 MiB scans while preserving bytes.
	if s.cache == nil {
		h := sha256.New()
		chunks := make([]string, 0, (sel.Size+ChunkBytes-1)/ChunkBytes)
		buf := make([]byte, ChunkBytes)
		var total int64
		for total < sel.Size {
			if e := ctx.Err(); e != nil {
				return nil, e
			}
			count := int(min(int64(ChunkBytes), sel.Size-total))
			if _, e = io.ReadFull(f, buf[:count]); e != nil {
				return nil, ErrSpool
			}
			h.Write(buf[:count])
			chunks = append(chunks, byteDigest(buf[:count]))
			total += int64(count)
		}
		if "sha256:"+hex.EncodeToString(h.Sum(nil)) != sel.SHA256 {
			return nil, ErrSpool
		}
		if unix.Fstat(fd, &after) != nil || !sameArtifact(before, after) {
			return nil, ErrSpool
		}
		s.cache = &artifactCache{before, sel.SHA256, chunks}
	}
	if s.cache.sha != sel.SHA256 || !sameArtifact(before, s.cache.stat) {
		return nil, ErrSpool
	}
	offset := int64(index) * ChunkBytes
	data := make([]byte, min(int64(ChunkBytes), sel.Size-offset))
	if _, e = f.ReadAt(data, offset); e != nil {
		return nil, ErrSpool
	}
	if byteDigest(data) != s.cache.chunks[index] || unix.Fstat(fd, &after) != nil || !sameArtifact(before, after) || unix.Fstatat(fds[len(fds)-1], artifactName, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameArtifact(named, after) || !parentsUnchanged(path, fds, parents) {
		return nil, ErrSpool
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	return data, nil
}

func (s *Spool) validateRecord(hasIntent, complete bool, size int64) error {
	path := filepath.Join(s.directory, artifactName)
	fds, parents, e := protectedParent(path)
	if e != nil {
		return ErrSpool
	}
	defer closeParents(fds)
	var st unix.Stat_t
	e = unix.Fstatat(fds[len(fds)-1], artifactName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if e == unix.ENOENT {
		if complete {
			return ErrSpool
		}
		return nil
	}
	if e != nil || !hasIntent || st.Size < 0 || st.Size > size || !validArtifact(st, st.Size) || complete && st.Size != size || !parentsUnchanged(path, fds, parents) {
		return ErrSpool
	}
	return nil
}
