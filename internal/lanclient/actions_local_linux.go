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

func loadActionLocal(m Material) (actionLocal, error) {
	uid, gid, ok := journalAgentIdentity()
	if !ok {
		return actionLocal{}, errActionDenied
	}
	dir, e := journalRootDirectory([]string{"etc", "tracebolt"})
	if e != nil {
		if errors.Is(e, errJournalDisabled) {
			return actionLocal{}, errActionDisabled
		}
		return actionLocal{}, errActionDenied
	}
	defer dir.Close()
	local, e := readActionLocalFile(dir, m, uid, gid, 0)
	if e != nil {
		return actionLocal{}, e
	}
	fresh, e := journalRootDirectory([]string{"etc", "tracebolt"})
	if e != nil {
		return actionLocal{}, errActionDenied
	}
	defer fresh.Close()
	var first, current unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &first) != nil || unix.Fstat(int(fresh.Fd()), &current) != nil || !journalSame(first, current) {
		return actionLocal{}, errActionDenied
	}
	return local, nil
}

// Fixture owner/root parameters remain private. Production never accepts a
// path, grant body or numeric identity from the manager/helper response.
func readActionLocalFile(dir *os.File, m Material, uid, gid, owner uint32) (actionLocal, error) {
	var directory unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &directory) != nil || directory.Uid != owner || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Mode&0022 != 0 {
		return actionLocal{}, errActionDenied
	}
	fd, e := unix.Openat(int(dir.Fd()), "action-client.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(e, unix.ENOENT) {
		return actionLocal{}, errActionDisabled
	}
	if e != nil {
		return actionLocal{}, errActionDenied
	}
	f := os.NewFile(uintptr(fd), "service-action-client-policy")
	defer f.Close()
	var before, after, named, afterDir unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Uid != owner || before.Gid != gid || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0640 || before.Nlink != 1 || before.Size <= 0 || before.Size > maxActionClientPolicyBytes {
		return actionLocal{}, errActionDenied
	}
	raw, e := io.ReadAll(io.LimitReader(f, maxActionClientPolicyBytes+1))
	if e != nil || int64(len(raw)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Fstatat(int(dir.Fd()), "action-client.json", &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !journalSame(before, after) || !journalSame(after, named) || unix.Fstat(int(dir.Fd()), &afterDir) != nil || !journalSame(directory, afterDir) {
		return actionLocal{}, errActionDenied
	}
	p, e := decodeActionLocal(raw, m, uid, gid)
	if e != nil {
		return actionLocal{}, e
	}
	after.Atim, afterDir.Atim = unix.Timespec{}, unix.Timespec{}
	metadata, _ := json.Marshal(struct {
		Raw             []byte
		File, Directory unix.Stat_t
	}{raw, after, afterDir})
	return actionLocal{policy: p, revision: actionpermit.Digest(metadata)}, nil
}
