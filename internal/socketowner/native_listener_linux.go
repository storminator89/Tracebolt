//go:build linux

package socketowner

import (
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

type listenerEvidence struct {
	Socket       unix.Stat_t
	PathRevision string
	Mount, Inode uint64
}

func fixedSocketMetadata(p Policy) (string, error) {
	dir, e := openProtectedDirectory("/run/tracebolt-socket-owner-reader")
	if e != nil {
		return "", e
	}
	defer unix.Close(dir)
	var st unix.Stat_t
	if unix.Fstatat(dir, "reader.sock", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Uid != 0 || st.Gid != p.AgentGID || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Mode&07777 != 0660 || st.Nlink != 1 {
		return "", ErrRejected
	}
	// Rewalk the protected parent so a detached directory is never authoritative.
	fresh, e := openProtectedDirectory("/run/tracebolt-socket-owner-reader")
	if e != nil {
		return "", e
	}
	defer unix.Close(fresh)
	var before, after, named unix.Stat_t
	if unix.Fstat(dir, &before) != nil || unix.Fstat(fresh, &after) != nil || !sameNativeObject(before, after) || unix.Fstatat(fresh, "reader.sock", &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameNativeObject(st, named) {
		return "", ErrChanged
	}
	return objectRevision(st), nil
}

type listenerProbe struct {
	stat     func(int, *unix.Stat_t) error
	fs       func(int, *unix.Statfs_t) error
	option   func(int, int, int) (int, error)
	name     func(int) (unix.Sockaddr, error)
	statx    func(int, string, int, int, *unix.Statx_t) error
	pathname func(Policy) (string, error)
}

func inspectListener(fd int, p Policy) (listenerEvidence, error) {
	return inspectListenerUsing(fd, p, listenerProbe{unix.Fstat, unix.Fstatfs, unix.GetsockoptInt, unix.Getsockname, unix.Statx, fixedSocketMetadata})
}
func inspectListenerUsing(fd int, p Policy, probe listenerProbe) (listenerEvidence, error) {
	var out listenerEvidence
	var fs unix.Statfs_t
	var sx unix.Statx_t
	if probe.stat(fd, &out.Socket) != nil || out.Socket.Uid != 0 || out.Socket.Mode&unix.S_IFMT != unix.S_IFSOCK || probe.fs(fd, &fs) != nil || fs.Type != unix.SOCKFS_MAGIC {
		return out, ErrRejected
	}
	for _, pair := range [][2]int{{unix.SO_DOMAIN, unix.AF_UNIX}, {unix.SO_TYPE, unix.SOCK_STREAM}, {unix.SO_ACCEPTCONN, 1}, {unix.SO_PASSPIDFD, 0}} {
		v, e := probe.option(fd, unix.SOL_SOCKET, pair[0])
		if e != nil || v != pair[1] {
			return out, ErrRejected
		}
	}
	a, e := probe.name(fd)
	u, ok := a.(*unix.SockaddrUnix)
	if e != nil || !ok || u.Name != SocketPath {
		return out, ErrRejected
	}
	mask := uint32(unix.STATX_INO | unix.STATX_MNT_ID | unix.STATX_TYPE)
	if probe.statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, int(mask), &sx) != nil || sx.Mask&mask != mask || sx.Ino == 0 || sx.Mnt_id == 0 || sx.Mnt_id > 1<<31-1 || sx.Ino != out.Socket.Ino || sx.Mode&unix.S_IFMT != unix.S_IFSOCK || unix.Mkdev(sx.Dev_major, sx.Dev_minor) != uint64(out.Socket.Dev) {
		return out, ErrRejected
	}
	out.Mount = sx.Mnt_id
	out.Inode = sx.Ino
	out.PathRevision, e = probe.pathname(p)
	if e != nil {
		return out, e
	}
	return out, nil
}
func inheritedNativeListener(p Policy) (*net.UnixListener, *os.File, listenerEvidence, error) {
	var empty listenerEvidence
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" || os.Getenv("LISTEN_FDNAMES") != "socket-owner-reader" {
		return nil, nil, empty, ErrRejected
	}
	const fd = 3
	evidence, e := inspectListener(fd, p)
	if e != nil {
		return nil, nil, empty, e
	}
	// Before accept or data reads, require credentials on all subsequently accepted
	// sockets too. Pre-option queued data without matching credentials is rejected.
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1) != nil {
		return nil, nil, empty, ErrRejected
	}
	unix.CloseOnExec(fd)
	f := os.NewFile(fd, "socket-owner-inherited-listener")
	l, e := net.FileListener(f)
	if e != nil {
		f.Close()
		return nil, nil, empty, ErrRejected
	}
	u, ok := l.(*net.UnixListener)
	if !ok {
		l.Close()
		f.Close()
		return nil, nil, empty, ErrRejected
	}
	u.SetUnlinkOnClose(false)
	return u, f, evidence, nil
}
func listenerUnchanged(f *os.File, p Policy, expected listenerEvidence) bool {
	raw, e := f.SyscallConn()
	if e != nil {
		return false
	}
	var actual listenerEvidence
	var inner error
	e = raw.Control(func(fd uintptr) { actual, inner = inspectListener(int(fd), p) })
	return e == nil && inner == nil && actual.Mount == expected.Mount && actual.Inode == expected.Inode && actual.PathRevision == expected.PathRevision && sameNativeObject(actual.Socket, expected.Socket)
}
