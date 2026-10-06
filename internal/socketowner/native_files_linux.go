//go:build linux

package socketowner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const nativeDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
const nativeFileFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK

var fixedPaths = [objectCount]string{
	"/etc/tracebolt/socket-owner-policy.json",
	"/etc/tracebolt/socket-owner-deployment.json",
	"/opt/tracebolt-agent/socket-owner-reader",
	"/opt/tracebolt-agent/lan-agent",
	"/etc/systemd/system/tracebolt-socket-owner-reader.service",
	"/etc/systemd/system/tracebolt-agent.service",
	"/etc/systemd/system/tracebolt-socket-owner-reader.socket",
}

type nativeProtectedReader struct {
	mu        sync.Mutex
	artifacts map[fixedObject]protectedObject
}

func safeNativeDir(st unix.Stat_t) bool {
	return st.Uid == 0 && st.Gid == 0 && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&07777 == 0755
}
func sameNativeObject(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func objectRevision(st unix.Stat_t) string {
	b, _ := json.Marshal(struct {
		Dev, Ino       uint64
		UID, GID, Mode uint32
		Links          uint64
		Size           int64
		MTime, CTime   unix.Timespec
	}{uint64(st.Dev), st.Ino, st.Uid, st.Gid, st.Mode, uint64(st.Nlink), st.Size, st.Mtim, st.Ctim})
	return digest(b)
}

// Only fixed internal paths reach this helper. Each component is held while its
// child is opened, and every named object is rewalked after bounded reading.
func openProtectedDirectory(name string) (int, error) {
	fd, e := unix.Open("/", nativeDirFlags, 0)
	if e != nil {
		return -1, ErrRejected
	}
	check := func(fd int) bool { var st unix.Stat_t; return unix.Fstat(fd, &st) == nil && safeNativeDir(st) }
	if !check(fd) {
		unix.Close(fd)
		return -1, ErrRejected
	}
	for _, part := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		if part == "" {
			continue
		}
		if part == "." || part == ".." {
			unix.Close(fd)
			return -1, ErrRejected
		}
		next, e := unix.Openat(fd, part, nativeDirFlags, 0)
		unix.Close(fd)
		if e != nil {
			return -1, ErrRejected
		}
		fd = next
		if !check(fd) {
			unix.Close(fd)
			return -1, ErrRejected
		}
	}
	return fd, nil
}
func fixedSpec(id fixedObject) (string, uint32, int64, bool) {
	if id >= objectCount {
		return "", 0, 0, false
	}
	mode := uint32(0640)
	max := int64(maxRecordBytes)
	if id == policyObject {
		max = MaxPolicyBytes
	}
	if id >= helperObject {
		mode = 0644
		max = 64 << 10
	}
	if id == helperObject || id == agentObject {
		mode = 0755
		if id == agentObject {
			// The existing native installer publishes its agent as read-only 0555.
			mode = 0555
		}
		max = 128 << 20
	}
	return fixedPaths[id], mode, max, true
}
func safeNativeFile(st unix.Stat_t, mode uint32, max int64) bool {
	return st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == mode && st.Nlink == 1 && st.Size > 0 && st.Size <= max
}
func (r *nativeProtectedReader) Read(id fixedObject) (protectedObject, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if obj, ok := r.artifacts[id]; ok {
		if r.Recheck(id, obj) != nil {
			return protectedObject{}, ErrChanged
		}
		return obj, nil
	}
	obj, e := readProtectedObject(id)
	if e != nil {
		return protectedObject{}, e
	}
	if id >= helperObject {
		if r.artifacts == nil {
			r.artifacts = make(map[fixedObject]protectedObject)
		}
		r.artifacts[id] = obj
	}
	return obj, nil
}
func readProtectedObject(id fixedObject) (protectedObject, error) {
	name, mode, max, ok := fixedSpec(id)
	if !ok {
		return protectedObject{}, ErrRejected
	}
	dir, e := openProtectedDirectory(path.Dir(name))
	if e != nil {
		return protectedObject{}, e
	}
	defer unix.Close(dir)
	fd, e := unix.Openat(dir, path.Base(name), nativeFileFlags, 0)
	if e != nil {
		return protectedObject{}, ErrRejected
	}
	f := os.NewFile(uintptr(fd), "socket-owner-protected-object")
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !safeNativeFile(before, mode, max) {
		return protectedObject{}, ErrRejected
	}
	// Hash artifacts as streams; never allocate executable-sized buffers.
	h := sha256.New()
	var body []byte
	if id <= deploymentObject {
		body, e = io.ReadAll(io.LimitReader(f, max+1))
		if e == nil {
			_, e = h.Write(body)
		}
	} else {
		var n int64
		n, e = io.Copy(h, io.LimitReader(f, max+1))
		if n != before.Size {
			e = ErrRejected
		}
	}
	if e != nil || id <= deploymentObject && int64(len(body)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Fstatat(dir, path.Base(name), &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameNativeObject(before, after) || !sameNativeObject(after, named) {
		return protectedObject{}, ErrRejected
	}
	result := protectedObject{Body: body, Digest: hex.EncodeToString(h.Sum(nil)), Revision: objectRevision(after), GID: after.Gid}
	if (&nativeProtectedReader{}).Recheck(id, result) != nil {
		return protectedObject{}, ErrChanged
	}
	return result, nil
}
func (*nativeProtectedReader) Recheck(id fixedObject, obj protectedObject) error {
	name, mode, max, ok := fixedSpec(id)
	if !ok {
		return ErrRejected
	}
	dir, e := openProtectedDirectory(path.Dir(name))
	if e != nil {
		return e
	}
	defer unix.Close(dir)
	var st unix.Stat_t
	if unix.Fstatat(dir, path.Base(name), &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !safeNativeFile(st, mode, max) || objectRevision(st) != obj.Revision {
		return ErrChanged
	}
	return nil
}

// Installed files are not proof of systemd's loaded configuration. Conservatively
// reject override locations in the supported fixed profile; generated/transient
// or alternate fragment paths still require the independent running-unit proof.
func (*nativeProtectedReader) NoOverrides() error {
	roots := []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/run/systemd/transient", "/run/systemd/generator", "/run/systemd/generator.early", "/run/systemd/generator.late"}
	names := []string{"tracebolt-socket-owner-reader.service", "tracebolt-agent.service", "tracebolt-socket-owner-reader.socket"}
	for _, root := range roots {
		for _, name := range names {
			if root != "/etc/systemd/system" {
				if e := mustNotExist(root + "/" + name); e != nil {
					return e
				}
			}
			if e := mustNotExist(root + "/" + name + ".d"); e != nil {
				return e
			}
		}
		for _, name := range []string{"service.d", "socket.d", "tracebolt-.service.d", "tracebolt-.socket.d", "tracebolt-socket-.service.d", "tracebolt-socket-.socket.d", "tracebolt-socket-owner-.service.d", "tracebolt-socket-owner-.socket.d"} {
			if e := mustNotExist(root + "/" + name); e != nil {
				return e
			}
		}
	}
	return nil
}
func mustNotExist(name string) error {
	_, e := os.Lstat(name)
	if os.IsNotExist(e) {
		return nil
	}
	return ErrRejected
}
