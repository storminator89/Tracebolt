//go:build linux

package socketowner

import (
	"bytes"
	"context"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const maxNativeThreads = 4096

type nativeIdentity struct {
	UIDs, GIDs               [3]uint32
	Groups                   []uint32
	Caps                     [5]uint64
	PID                      int32
	NoNewPrivileges, Seccomp bool
}

func parseNativeStatus(raw []byte) (nativeIdentity, error) {
	var v nativeIdentity
	if len(raw) == 0 || len(raw) > 64<<10 {
		return v, ErrRejected
	}
	seen := map[string]bool{}
	required := []string{"Pid", "Uid", "Gid", "Groups", "CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd", "NoNewPrivs", "Seccomp"}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		relevant := false
		for _, k := range required {
			if key == k {
				relevant = true
				break
			}
		}
		if !relevant {
			continue
		}
		if seen[key] {
			return v, ErrRejected
		}
		seen[key] = true
		fields := strings.Fields(value)
		switch key {
		case "Uid", "Gid":
			if len(fields) != 4 {
				return v, ErrRejected
			}
			var ids [4]uint32
			for i, s := range fields {
				n, e := strconv.ParseUint(s, 10, 32)
				if e != nil {
					return v, ErrRejected
				}
				ids[i] = uint32(n)
			}
			if ids[3] != ids[1] {
				return v, ErrRejected
			}
			if key == "Uid" {
				copy(v.UIDs[:], ids[:3])
			} else {
				copy(v.GIDs[:], ids[:3])
			}
		case "Groups":
			// Parse at most one group, then compare it to the actual primary
			// GID after all fields are read. Never normalize/deduplicate input.
			if len(fields) > 1 {
				return v, ErrRejected
			}
			if len(fields) == 1 {
				n, err := strconv.ParseUint(fields[0], 10, 32)
				if err != nil {
					return v, ErrRejected
				}
				v.Groups = []uint32{uint32(n)}
			}
		case "Pid":
			if len(fields) != 1 {
				return v, ErrRejected
			}
			n, e := strconv.ParseInt(fields[0], 10, 32)
			if e != nil || n <= 0 {
				return v, ErrRejected
			}
			v.PID = int32(n)
		case "NoNewPrivs", "Seccomp":
			if len(fields) != 1 {
				return v, ErrRejected
			}
			if key == "NoNewPrivs" {
				v.NoNewPrivileges = fields[0] == "1"
			} else {
				v.Seccomp = fields[0] == "2"
			}
		default:
			if len(fields) != 1 || len(fields[0]) != 16 {
				return v, ErrRejected
			}
			n, e := strconv.ParseUint(fields[0], 16, 64)
			if e != nil {
				return v, ErrRejected
			}
			index := map[string]int{"CapEff": 0, "CapPrm": 1, "CapInh": 2, "CapAmb": 3, "CapBnd": 4}[key]
			v.Caps[index] = n
		}
	}
	for _, k := range required {
		if !seen[k] {
			return v, ErrRejected
		}
	}
	if !v.NoNewPrivileges || !v.Seccomp || !primaryOnlyGroups(v.Groups, v.GIDs[1]) {
		return v, ErrRejected
	}
	return v, nil
}
func validateNativeIdentity(i nativeIdentity, uid, gid uint32, cap uint64) error {
	if !validID(uid) || !validID(gid) || i.UIDs != [3]uint32{uid, uid, uid} || i.GIDs != [3]uint32{gid, gid, gid} || !primaryOnlyGroups(i.Groups, gid) || !i.NoNewPrivileges || !i.Seccomp {
		return ErrRejected
	}
	for _, c := range i.Caps {
		if c != cap {
			return ErrRejected
		}
	}
	return nil
}
func readProcFile(dir int, name string, max int) ([]byte, error) {
	fd, e := unix.Openat(dir, name, nativeFileFlags, 0)
	if e != nil {
		return nil, ErrRejected
	}
	f := os.NewFile(uintptr(fd), "socket-owner-proc-metadata")
	defer f.Close()
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, ErrRejected
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if e != nil || len(b) > max {
		return nil, ErrRejected
	}
	return b, nil
}
func procDirectory(dir int, name string) (int, error) {
	fd, e := unix.Openat(dir, name, nativeDirFlags, 0)
	if e != nil {
		return -1, ErrRejected
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		unix.Close(fd)
		return -1, ErrRejected
	}
	return fd, nil
}
func nativeAlive(fd int) bool { return nativeAliveUsing(fd, unix.Poll) }
func nativeAliveUsing(fd int, poll func([]unix.PollFd, int) (int, error)) bool {
	if fd < 0 {
		return false
	}
	p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, e := poll(p, 0)
	return e == nil && n == 0 && p[0].Revents == 0
}

type pinnedNamespaces struct {
	FDs [3]int
	IDs NamespaceSet
}

func (n *pinnedNamespaces) close() {
	for i, fd := range n.FDs {
		if fd >= 0 {
			unix.Close(fd)
			n.FDs[i] = -1
		}
	}
}
func pinNamespaces(dir int) (pinnedNamespaces, error) {
	n := pinnedNamespaces{FDs: [3]int{-1, -1, -1}}
	nsdir, e := procDirectory(dir, "ns")
	if e != nil {
		return n, e
	}
	defer unix.Close(nsdir)
	names := []string{"pid", "net", "user"}
	types := []int{unix.CLONE_NEWPID, unix.CLONE_NEWNET, unix.CLONE_NEWUSER}
	ids := []*NamespaceID{&n.IDs.PID, &n.IDs.Net, &n.IDs.User}
	for i, name := range names {
		// Only these kernel nsfs magic links are followed, relative to a pinned proc
		// directory. Ordinary metadata paths always use O_NOFOLLOW.
		fd, e := unix.Openat(nsdir, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if e != nil {
			n.close()
			return n, ErrRejected
		}
		n.FDs[i] = fd
		id, e := inspectNamespace(fd, types[i], namespaceProbe{unix.IoctlRetInt, unix.Fstatfs, unix.Fstat})
		if e != nil {
			n.close()
			return n, e
		}
		*ids[i] = id
	}
	return n, nil
}

type namespaceProbe struct {
	kind func(int, uint) (int, error)
	fs   func(int, *unix.Statfs_t) error
	stat func(int, *unix.Stat_t) error
}

func inspectNamespace(fd, expected int, p namespaceProbe) (NamespaceID, error) {
	if expected != unix.CLONE_NEWPID && expected != unix.CLONE_NEWNET && expected != unix.CLONE_NEWUSER {
		return NamespaceID{}, ErrRejected
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	kind, e := p.kind(fd, unix.NS_GET_NSTYPE)
	if e != nil || kind != expected || p.fs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC || p.stat(fd, &st) != nil || st.Ino == 0 || st.Dev == 0 {
		return NamespaceID{}, ErrRejected
	}
	return NamespaceID{Device: uint64(st.Dev), Inode: st.Ino}, nil
}
func sameNamespaceView(dir int, expected NamespaceSet) bool {
	n, e := pinNamespaces(dir)
	if e != nil {
		return false
	}
	defer n.close()
	return n.IDs == expected
}

type processPin struct {
	dir, pidfd int
	pid        int32
	namespaces pinnedNamespaces
}

func (p *processPin) close() {
	p.namespaces.close()
	if p.dir >= 0 {
		unix.Close(p.dir)
		p.dir = -1
	}
	if p.pidfd >= 0 {
		unix.Close(p.pidfd)
		p.pidfd = -1
	}
}

// pid is kernel-derived SO_PEERCRED or fixed local PID1/self, never request data.
// Caller transfers pidfd ownership even when this fails.
func pinProcess(proc int, pid int32, pidfd int) (*processPin, error) {
	p := &processPin{dir: -1, pidfd: pidfd, pid: pid, namespaces: pinnedNamespaces{FDs: [3]int{-1, -1, -1}}}
	fail := func() (*processPin, error) { p.close(); return nil, ErrRejected }
	if pid <= 0 || !nativeAlive(pidfd) {
		return fail()
	}
	dir, e := procDirectory(proc, strconv.Itoa(int(pid)))
	if e != nil {
		return fail()
	}
	p.dir = dir
	n, e := pinNamespaces(dir)
	if e != nil {
		return fail()
	}
	p.namespaces = n
	if !nativeAlive(pidfd) {
		return fail()
	}
	return p, nil
}
func (p *processPin) identity() (nativeIdentity, error) {
	b, e := readProcFile(p.dir, "status", 64<<10)
	if e != nil {
		return nativeIdentity{}, e
	}
	i, e := parseNativeStatus(b)
	if e != nil || i.PID != p.pid {
		return nativeIdentity{}, ErrRejected
	}
	return i, nil
}
func taskIDs(dir int) ([]string, error) {
	fd, e := procDirectory(dir, "task")
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "socket-owner-tasks")
	defer f.Close()
	names, e := f.Readdirnames(maxNativeThreads + 1)
	if e != nil && e != io.EOF || len(names) == 0 || len(names) > maxNativeThreads {
		return nil, ErrRejected
	}
	for _, name := range names {
		n, e := strconv.ParseInt(name, 10, 32)
		if e != nil || n <= 0 || strconv.FormatInt(n, 10) != name {
			return nil, ErrRejected
		}
	}
	sort.Strings(names)
	return names, nil
}

// Stable task snapshots detect observed heterogeneous threads. They do NOT
// prove atomic process-wide confinement: SCM_CREDENTIALS identifies TGID, not
// the sending TID. These are checkpoint evidence for trusted fixed binaries,
// not attestation of seccomp filter contents or malicious-thread confinement.
func (p *processPin) checkThreads(ctx context.Context, uid, gid uint32, cap uint64) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrChanged
	}
	before, e := taskIDs(p.dir)
	if e != nil {
		return e
	}
	task, e := procDirectory(p.dir, "task")
	if e != nil {
		return e
	}
	defer unix.Close(task)
	for _, tid := range before {
		if ctx.Err() != nil {
			return ErrChanged
		}
		fd, e := procDirectory(task, tid)
		if e != nil {
			return e
		}
		b, e := readProcFile(fd, "status", 64<<10)
		identity, parseErr := parseNativeStatus(b)
		same := sameNamespaceView(fd, p.namespaces.IDs)
		unix.Close(fd)
		if e != nil || parseErr != nil || validateNativeIdentity(identity, uid, gid, cap) != nil || !same {
			return ErrRejected
		}
	}
	after, e := taskIDs(p.dir)
	if e != nil || strings.Join(before, ",") != strings.Join(after, ",") || !nativeAlive(p.pidfd) {
		return ErrChanged
	}
	return nil
}
func (p *processPin) checkArtifact(id fixedObject, expected protectedObject) error {
	fd, e := unix.Openat(p.dir, "exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrRejected
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	_, mode, max, ok := fixedSpec(id)
	if !ok || unix.Fstat(fd, &st) != nil || !safeNativeFile(st, mode, max) || objectRevision(st) != expected.Revision {
		return ErrChanged
	}
	return nil
}
func (p *processPin) checkCgroup(helper bool) error {
	b, e := readProcFile(p.dir, "cgroup", 4096)
	expected := "0::/system.slice/tracebolt-agent.service\n"
	if helper {
		expected = "0::/system.slice/tracebolt-socket-owner-reader.service\n"
	}
	if e != nil || string(b) != expected {
		return ErrRejected
	}
	return nil
}
func (p *processPin) check(ctx context.Context, uid, gid uint32, cap uint64, id fixedObject, obj protectedObject) (nativeIdentity, error) {
	if !nativeAlive(p.pidfd) || !sameNamespaceView(p.dir, p.namespaces.IDs) || p.checkThreads(ctx, uid, gid, cap) != nil || p.checkArtifact(id, obj) != nil || p.checkCgroup(id == helperObject) != nil {
		return nativeIdentity{}, ErrChanged
	}
	i, e := p.identity()
	if e != nil || validateNativeIdentity(i, uid, gid, cap) != nil || !nativeAlive(p.pidfd) {
		return nativeIdentity{}, ErrChanged
	}
	return i, nil
}
func systemdPID1(p *processPin) bool {
	if p.pid != 1 || !nativeAlive(p.pidfd) {
		return false
	}
	b, e := readProcFile(p.dir, "comm", 64)
	if e != nil || !bytes.Equal(b, []byte("systemd\n")) {
		return false
	}
	dir, e := openProtectedDirectory("/usr/lib/systemd")
	if e != nil {
		return false
	}
	defer unix.Close(dir)
	installed, e := unix.Openat(dir, "systemd", nativeFileFlags, 0)
	if e != nil {
		return false
	}
	defer unix.Close(installed)
	running, e := unix.Openat(p.dir, "exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if e != nil {
		return false
	}
	defer unix.Close(running)
	var a, bstat unix.Stat_t
	return unix.Fstat(installed, &a) == nil && unix.Fstat(running, &bstat) == nil && safeNativeFile(a, 0755, 128<<20) && a.Gid == 0 && sameNativeObject(a, bstat) && nativeAlive(p.pidfd)
}
