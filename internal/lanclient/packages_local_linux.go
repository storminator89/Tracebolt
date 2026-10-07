//go:build linux

package lanclient

import (
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"localrmm/internal/actionpermit"
	"os"
)

func loadPackageLocal(m Material) (packageLocal, error) {
	uid, gid, ok := journalAgentIdentity()
	if !ok {
		return packageLocal{}, errPackageDenied
	}
	dir, e := journalRootDirectory([]string{"etc", "tracebolt"})
	if e != nil {
		if errors.Is(e, errJournalDisabled) {
			return packageLocal{}, errPackageDisabled
		}
		return packageLocal{}, errPackageDenied
	}
	defer dir.Close()
	local, e := readPackageLocalFile(dir, m, uid, gid, 0)
	if e != nil {
		return packageLocal{}, e
	}
	fresh, e := journalRootDirectory([]string{"etc", "tracebolt"})
	if e != nil {
		return packageLocal{}, errPackageDenied
	}
	defer fresh.Close()
	var first, current unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &first) != nil || unix.Fstat(int(fresh.Fd()), &current) != nil || !journalSame(first, current) {
		return packageLocal{}, errPackageDenied
	}
	return local, nil
}

// Fixture owner/root parameters remain private. Production never accepts a
// path, grant body or numeric identity from the manager/helper response.
func readPackageLocalFile(dir *os.File, m Material, uid, gid, owner uint32) (packageLocal, error) {
	var directory unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &directory) != nil || directory.Uid != owner || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Mode&0022 != 0 {
		return packageLocal{}, errPackageDenied
	}
	fd, e := unix.Openat(int(dir.Fd()), "package-client.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(e, unix.ENOENT) {
		return packageLocal{}, errPackageDisabled
	}
	if e != nil {
		return packageLocal{}, errPackageDenied
	}
	f := os.NewFile(uintptr(fd), "service-action-client-policy")
	defer f.Close()
	var before, after, named, afterDir unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Uid != owner || before.Gid != gid || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0640 || before.Nlink != 1 || before.Size <= 0 || before.Size > maxPackageClientPolicyBytes {
		return packageLocal{}, errPackageDenied
	}
	raw, e := io.ReadAll(io.LimitReader(f, maxPackageClientPolicyBytes+1))
	if e != nil || int64(len(raw)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Fstatat(int(dir.Fd()), "package-client.json", &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !journalSame(before, after) || !journalSame(after, named) || unix.Fstat(int(dir.Fd()), &afterDir) != nil || !journalSame(directory, afterDir) {
		return packageLocal{}, errPackageDenied
	}
	p, e := decodePackageLocal(raw, m, uid, gid)
	if e != nil {
		return packageLocal{}, e
	}
	after.Atim, afterDir.Atim = unix.Timespec{}, unix.Timespec{}
	metadata, _ := json.Marshal(struct {
		Raw             []byte
		File, Directory unix.Stat_t
	}{raw, after, afterDir})
	return packageLocal{policy: p, revision: actionpermit.Digest(metadata)}, nil
}
