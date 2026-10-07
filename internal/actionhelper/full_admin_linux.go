//go:build linux

package actionhelper

import (
	"context"
	"encoding/json"
	"path"
	"strings"

	"golang.org/x/sys/unix"
	"localrmm/internal/actionpermit"
)

// Resolve every symlink through held, root-protected parent descriptors. No
// writable directory or non-root symlink is trusted, including /lib -> /usr/lib
// and executable aliases. The second resolution must have identical identities.
func resolveFullAdminPath(fs authorityFS, name string) (string, string, error) {
	if _, err := authorityPathPartsPortable(name); err != nil {
		return "", "", err
	}
	original := name
	links := 0
	metadata := [][]byte{}
	for {
		parts, _ := authorityPathPartsPortable(name)
		prefix := "/"
		changed := false
		for i, part := range parts {
			d, err := fs.openDirectories(prefix)
			if err != nil {
				return "", "", err
			}
			var st unix.Stat_t
			if unix.Fstatat(d.fd(), part, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
				d.close()
				return "", "", ErrRejected
			}
			if st.Uid != fs.owner {
				d.close()
				return "", "", ErrRejected
			}
			for _, ancestor := range d.dirs {
				metadata = append(metadata, authorityMetadata(ancestor.stat))
			}
			metadata = append(metadata, authorityMetadata(st))
			if st.Mode&unix.S_IFMT == unix.S_IFLNK {
				links++
				if links > 40 {
					d.close()
					return "", "", ErrRejected
				}
				raw := make([]byte, 1024)
				n, err := unix.Readlinkat(d.fd(), part, raw)
				var after unix.Stat_t
				stable := err == nil && n > 0 && n < len(raw) && unix.Fstatat(d.fd(), part, &after, unix.AT_SYMLINK_NOFOLLOW) == nil && sameAuthorityObject(st, after) && d.unchanged()
				d.close()
				if !stable {
					return "", "", ErrRejected
				}
				target := string(raw[:n])
				metadata = append(metadata, []byte(target))
				if !strings.HasPrefix(target, "/") {
					target = path.Join(prefix, target)
				}
				name = path.Join(append([]string{target}, parts[i+1:]...)...)
				if _, err := authorityPathPartsPortable(name); err != nil {
					return "", "", err
				}
				changed = true
				break
			}
			stable := d.unchanged()
			d.close()
			if !stable || st.Mode&0022 != 0 {
				return "", "", ErrRejected
			}
			if i < len(parts)-1 && st.Mode&unix.S_IFMT != unix.S_IFDIR {
				return "", "", ErrRejected
			}
			prefix = path.Join(prefix, part)
		}
		if !changed {
			raw, _ := json.Marshal(struct {
				Original, Resolved string
				Metadata           [][]byte
			}{original, name, metadata})
			return name, actionpermit.Digest(raw), nil
		}
	}
}
func readFullAdminFileFrom(fs authorityFS, name string) (fullAdminFile, error) {
	resolved, revision, err := resolveFullAdminPath(fs, name)
	if err != nil {
		return fullAdminFile{}, err
	}
	d, err := fs.openDirectories(path.Dir(resolved))
	if err != nil {
		return fullAdminFile{}, err
	}
	defer d.close()
	f, err := d.readFile(path.Base(resolved), maxPinnedInputBytes, false)
	if err != nil {
		return fullAdminFile{}, err
	}
	defer f.close()
	current, currentRevision, err := resolveFullAdminPath(fs, name)
	if err != nil || current != resolved || currentRevision != revision || !d.unchanged() || !f.unchanged() {
		return fullAdminFile{}, ErrRejected
	}
	return fullAdminFile{name, resolved, actionpermit.Digest(f.raw), revision}, nil
}
func readFullAdminFile(name string) (fullAdminFile, error) {
	if rootIdentity() != nil {
		return fullAdminFile{}, ErrRejected
	}
	return readFullAdminFileFrom(authorityFS{root: "/", owner: 0}, name)
}
func newFullAdminBackend() Backend {
	return &fullAdminSystemdBackend{source: fullAdminSource{run: runSystemctl, file: readFullAdminFile, executable: readFullAdminExecutable}}
}

// InspectFullAdminService is an explicitly invoked read-only production adapter;
// setup itself does not need a per-service file or retained target manifest.
func InspectFullAdminService(ctx context.Context, unit string) (ServiceInspection, error) {
	if rootIdentity() != nil {
		return ServiceInspection{}, ErrRejected
	}
	return inspectServiceV2(ctx, fullAdminSource{run: runSystemctl, file: readFullAdminFile, executable: readFullAdminExecutable}, unit)
}

// Executables are existing host authority, not sandbox inputs. Resolve and
// bind protected path/file identity without requiring a static ELF or hashing
// arbitrarily large package binaries. Dynamic libraries/scripts remain the
// existing administrator's trust decision and are explicitly disclosed.
func readFullAdminExecutable(name string) (fullAdminFile, error) {
	if rootIdentity() != nil {
		return fullAdminFile{}, ErrRejected
	}
	return readFullAdminExecutableFrom(authorityFS{root: "/", owner: 0}, name)
}
func readFullAdminExecutableFrom(fs authorityFS, name string) (fullAdminFile, error) {
	resolved, revision, err := resolveFullAdminPath(fs, name)
	if err != nil {
		return fullAdminFile{}, err
	}
	d, err := fs.openDirectories(path.Dir(resolved))
	if err != nil {
		return fullAdminFile{}, err
	}
	defer d.close()
	fd, err := unix.Openat(d.fd(), path.Base(resolved), authorityFileFlags, 0)
	if err != nil {
		return fullAdminFile{}, ErrRejected
	}
	defer unix.Close(fd)
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Uid != fs.owner || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Mode&0022 != 0 || before.Mode&0111 == 0 {
		return fullAdminFile{}, ErrRejected
	}
	current, currentRevision, err := resolveFullAdminPath(fs, name)
	if err != nil || current != resolved || currentRevision != revision || unix.Fstat(fd, &after) != nil || unix.Fstatat(d.fd(), path.Base(resolved), &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameAuthorityObject(before, after) || !sameAuthorityObject(after, named) || !d.unchanged() {
		return fullAdminFile{}, ErrRejected
	}
	return fullAdminFile{name, resolved, "", revision}, nil
}
