//go:build linux

package actionclient

import (
	"context"
	"io"
	"net"

	"golang.org/x/sys/unix"
	"localrmm/internal/actionhelper"
)

const directoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK

var socketDirectories = [...]string{"run", "tracebolt-action-helper"}

type protectedPath struct {
	fds    []int
	stats  []unix.Stat_t
	socket unix.Stat_t
	group  uint32
}

func safeDirectory(s unix.Stat_t) bool {
	return s.Uid == 0 && s.Mode&unix.S_IFMT == unix.S_IFDIR && s.Mode&0022 == 0 && s.Mode&(unix.S_ISUID|unix.S_ISGID) == 0
}
func safeSocket(s unix.Stat_t, group uint32) bool {
	return group != 0 && group != ^uint32(0) && s.Uid == 0 && s.Gid == group && s.Mode&unix.S_IFMT == unix.S_IFSOCK && s.Mode&07777 == 0660 && s.Nlink == 1
}
func sameObject(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func (p *protectedPath) close() {
	for _, fd := range p.fds {
		unix.Close(fd)
	}
	p.fds = nil
}
func openPath(group uint32) (*protectedPath, error) {
	p := &protectedPath{group: group}
	fd, err := unix.Open("/", directoryFlags, 0)
	if err != nil {
		return nil, ErrRejected
	}
	for n := 0; ; n++ {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || !safeDirectory(st) {
			unix.Close(fd)
			p.close()
			return nil, ErrRejected
		}
		p.fds = append(p.fds, fd)
		p.stats = append(p.stats, st)
		if n == len(socketDirectories) {
			break
		}
		fd, err = unix.Openat(fd, socketDirectories[n], directoryFlags, 0)
		if err != nil {
			p.close()
			return nil, ErrRejected
		}
	}
	if unix.Fstatat(fd, "action.sock", &p.socket, unix.AT_SYMLINK_NOFOLLOW) != nil || !safeSocket(p.socket, group) {
		p.close()
		return nil, ErrRejected
	}
	return p, nil
}
func (p *protectedPath) recheck() error {
	fresh, err := openPath(p.group)
	if err != nil {
		return ErrRejected
	}
	defer fresh.close()
	if len(fresh.fds) != len(p.fds) || !sameObject(p.socket, fresh.socket) {
		return ErrRejected
	}
	for i, fd := range p.fds {
		var held unix.Stat_t
		if unix.Fstat(fd, &held) != nil || !sameObject(p.stats[i], held) || !sameObject(held, fresh.stats[i]) {
			return ErrRejected
		}
	}
	var held unix.Stat_t
	if unix.Fstatat(p.fds[len(p.fds)-1], "action.sock", &held, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameObject(p.socket, held) {
		return ErrRejected
	}
	return nil
}

func rootPeer(cred *unix.Ucred) bool {
	return cred != nil && cred.Uid == 0 && cred.Gid == 0 && cred.Pid > 0
}

func connectProtected(ctx context.Context) (connection, error) {
	u, e, s := unix.Getresuid()
	g, eg, sg := unix.Getresgid()
	if u <= 0 || u != e || u != s || g <= 0 || g != eg || g != sg {
		return connection{}, ErrRejected
	}
	p, err := openPath(uint32(g))
	if err != nil {
		return connection{}, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", actionhelper.SocketPath)
	if err != nil {
		p.close()
		return connection{}, ErrUnavailable
	}
	fail := func() (connection, error) { conn.Close(); p.close(); return connection{}, ErrRejected }
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return fail()
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return fail()
	}
	var cred *unix.Ucred
	var inner error
	if raw.Control(func(fd uintptr) {
		cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if inner == nil {
			inner = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
		}
	}) != nil || inner != nil || !rootPeer(cred) || p.recheck() != nil {
		return fail()
	}
	// SO_PEERCRED may identify systemd, the listening socket's creator. Per-
	// chunk credentials below authenticate the actual root response writer.
	return connection{Conn: c, reader: &credentialReader{conn: c}, recheck: p.recheck, close: p.close}, nil
}

type credentialReader struct {
	conn *net.UnixConn
	pid  int32
}

func (r *credentialReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(4*16))
	n, on, flags, _, err := r.conn.ReadMsgUnix(p, oob)
	return r.validateMessage(n, oob[:on], flags, err)
}
func (r *credentialReader) validateMessage(n int, oob []byte, flags int, readErr error) (int, error) {
	if n == 0 && len(oob) == 0 && flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) == 0 && (readErr == io.EOF || readErr == nil) {
		return 0, io.EOF
	}
	messages, err := unix.ParseSocketControlMessage(oob)
	valid := err == nil && flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) == 0
	credentials := 0
	eof := n == 0 && readErr == io.EOF
	for _, m := range messages {
		if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_RIGHTS {
			fds, e := unix.ParseUnixRights(&m)
			if e == nil {
				for _, fd := range fds {
					unix.Close(fd)
				}
			}
			valid = false
			continue
		}
		if m.Header.Level != unix.SOL_SOCKET || m.Header.Type != unix.SCM_CREDENTIALS {
			valid = false
			continue
		}
		cred, e := unix.ParseUnixCredentials(&m)
		credentials++
		if eof && e == nil && cred != nil {
			continue
		}
		if e != nil || !rootPeer(cred) {
			valid = false
			continue
		}
		if r.pid == 0 {
			r.pid = cred.Pid
		} else if r.pid != cred.Pid {
			valid = false
		}
	}
	// A zero-byte Linux EOF sentinel cannot authorize response bytes.
	if eof && valid && credentials <= 1 {
		return 0, io.EOF
	}
	if !valid || credentials != 1 || n <= 0 || readErr != nil {
		return 0, ErrRejected
	}
	return n, nil
}
