//go:build linux

package journalactivation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

const directoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK

func protectedDir() (*os.File, error) {
	fd, e := unix.Open("/", directoryFlags, 0)
	if e != nil {
		return nil, ErrInvalid
	}
	for _, part := range []string{"", "etc", "tracebolt"} {
		if part != "" {
			n, err := unix.Openat(fd, part, directoryFlags, 0)
			unix.Close(fd)
			if err != nil {
				return nil, ErrInvalid
			}
			fd = n
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&06022 != 0 {
			unix.Close(fd)
			return nil, ErrInvalid
		}
	}
	return os.NewFile(uintptr(fd), "journal-activation-directory"), nil
}
func same(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func safeActivationFile(st unix.Stat_t) bool {
	return st.Uid == 0 && st.Gid == 0 && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0644 && st.Nlink == 1 && st.Size >= 1 && st.Size <= MaxBytes
}
func noStage(fd int) bool {
	var st unix.Stat_t
	return errors.Is(unix.Fstatat(fd, TempName, &st, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT)
}

// Read distinguishes proven absence from every unsafe/ambiguous result. A v2
// deployment may never interpret absence as permission to use legacy policy.
func Read() (Record, bool, string, error) {
	dir, e := protectedDir()
	if e != nil {
		return Record{}, false, "", ErrInvalid
	}
	defer dir.Close()
	dfd := int(dir.Fd())
	var parent unix.Stat_t
	if unix.Fstat(dfd, &parent) != nil || !noStage(dfd) {
		return Record{}, false, "", ErrInvalid
	}
	fd, e := unix.Openat(dfd, "journal-activation.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(e, unix.ENOENT) {
		var check unix.Stat_t
		if unix.Fstat(dfd, &check) != nil || !same(parent, check) || !noStage(dfd) {
			return Record{}, false, "", ErrInvalid
		}
		return Record{}, false, "", nil
	}
	if e != nil {
		return Record{}, false, "", ErrInvalid
	}
	f := os.NewFile(uintptr(fd), "journal-activation")
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !safeActivationFile(before) {
		return Record{}, true, "", ErrInvalid
	}
	raw, e := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if e != nil || int64(len(raw)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Fstatat(dfd, "journal-activation.json", &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(before, after) || !same(after, named) || !noStage(dfd) {
		return Record{}, true, "", ErrInvalid
	}
	fresh, e := protectedDir()
	if e != nil {
		return Record{}, true, "", ErrInvalid
	}
	defer fresh.Close()
	var freshParent unix.Stat_t
	if unix.Fstat(int(fresh.Fd()), &freshParent) != nil || !same(parent, freshParent) {
		return Record{}, true, "", ErrInvalid
	}
	r, e := Decode(raw)
	if e != nil {
		return Record{}, true, "", ErrInvalid
	}
	metadata, _ := json.Marshal(before)
	h := sha256.New()
	h.Write(raw)
	h.Write(metadata)
	return r, true, hex.EncodeToString(h.Sum(nil)), nil
}
