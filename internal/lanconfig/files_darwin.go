//go:build darwin

package lanconfig

import (
	"golang.org/x/sys/unix"
	"io"
	"localrmm/internal/darwinprotect"
	"os"
	"path/filepath"
	"strings"
)

// ReadProtected anchors every component to an open directory descriptor and
// checks both mode ownership and native ACLs. It never follows a symlink,
// normalizes a /var alias, grants permissions, or adopts unsafe material.
func ReadProtected(path string, private bool, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) || limit < 1 || limit > 16<<20 {
		return nil, ErrConfiguration
	}
	type directory struct {
		fd   int
		name string
		id   unix.Stat_t
	}
	var chain []directory
	defer func() {
		for i := len(chain) - 1; i >= 0; i-- {
			_ = unix.Close(chain[i].fd)
		}
	}()
	trusted := func(st unix.Stat_t) bool {
		return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Nlink > 0 && (st.Uid == 0 || st.Uid == uint32(os.Geteuid())) && (st.Mode&0022 == 0 || st.Mode&unix.S_ISVTX != 0)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrConfiguration
	}
	chain = append(chain, directory{fd: fd})
	if darwinprotect.Fstat(fd, &chain[0].id) != nil || !trusted(chain[0].id) {
		return nil, ErrConfiguration
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, ErrConfiguration
		}
		chain = append(chain, directory{fd: next, name: part})
		current := &chain[len(chain)-1]
		if darwinprotect.Fstat(next, &current.id) != nil || !trusted(current.id) {
			return nil, ErrConfiguration
		}
		fd = next
	}
	name := parts[len(parts)-1]
	fileFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrConfiguration
	}
	file := os.NewFile(uintptr(fileFD), "macOS-protected-material")
	defer file.Close()
	var before, after, entry unix.Stat_t
	fileSafe := func(st unix.Stat_t) bool {
		uid := uint32(os.Geteuid())
		return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && (st.Uid == uid || st.Uid == 0) && st.Mode&07022 == 0 && (!private || st.Uid == uid && st.Mode&0077 == 0)
	}
	if darwinprotect.Fstat(fileFD, &before) != nil || !fileSafe(before) || before.Size < 1 || before.Size > limit {
		return nil, ErrConfiguration
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != before.Size || int64(len(raw)) > limit {
		return nil, ErrConfiguration
	}
	if darwinprotect.Fstat(fileFD, &after) != nil || unix.Fstatat(fd, name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !fileSafe(after) || !fileSafe(entry) || before.Dev != after.Dev || before.Ino != after.Ino || after.Dev != entry.Dev || after.Ino != entry.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || after.Ctim != entry.Ctim {
		return nil, ErrConfiguration
	}
	for i, d := range chain {
		var now unix.Stat_t
		if darwinprotect.Fstat(d.fd, &now) != nil || !trusted(now) || d.id.Dev != now.Dev || d.id.Ino != now.Ino {
			return nil, ErrConfiguration
		}
		if i > 0 {
			var entry unix.Stat_t
			if unix.Fstatat(chain[i-1].fd, d.name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || now.Dev != entry.Dev || now.Ino != entry.Ino {
				return nil, ErrConfiguration
			}
		}
	}
	return raw, nil
}
