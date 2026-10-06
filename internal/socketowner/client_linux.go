//go:build linux

package socketowner

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type clientSocket interface {
	nativeMessageSocket
	CloseWrite() error
}

type clientSocketProbe struct {
	set func(int, int, int, int) error
	get func(int, int, int) (int, error)
}

// Set both options before connect, so even immediately queued helper bytes must
// carry the actual writer's kernel-supplied pidfd and credentials. No connect-time
// SO_PEERCRED/SO_PEERPIDFD or numeric pidfd_open fallback identifies the writer.
func prepareClientSocket(fd int, probe clientSocketProbe) error {
	for _, opt := range []int{unix.SO_PASSCRED, unix.SO_PASSPIDFD} {
		if probe.set(fd, unix.SOL_SOCKET, opt, 1) != nil {
			return ErrRejected
		}
	}
	for _, pair := range [][2]int{{unix.SO_DOMAIN, unix.AF_UNIX}, {unix.SO_TYPE, unix.SOCK_STREAM}, {unix.SO_ACCEPTCONN, 0}, {unix.SO_PASSCRED, 1}, {unix.SO_PASSPIDFD, 1}} {
		got, err := probe.get(fd, unix.SOL_SOCKET, pair[0])
		if err != nil || got != pair[1] {
			return ErrRejected
		}
	}
	return nil
}

func connectNativeClient(ctx context.Context, p Policy) (clientConnection, error) {
	revision, err := fixedSocketMetadata(p)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Control: func(network, address string, raw syscall.RawConn) error {
		if network != "unix" || address != SocketPath {
			return ErrRejected
		}
		var inner error
		err := raw.Control(func(fd uintptr) {
			inner = prepareClientSocket(int(fd), clientSocketProbe{unix.SetsockoptInt, unix.GetsockoptInt})
		})
		if err != nil || inner != nil {
			return ErrRejected
		}
		return nil
	}}
	conn, err := dialer.DialContext(ctx, "unix", SocketPath)
	if err != nil {
		return nil, ErrRejected
	}
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, ErrRejected
	}
	checkPath := func() error {
		current, err := fixedSocketMetadata(p)
		if err != nil || current != revision {
			return ErrChanged
		}
		return nil
	}
	if checkPath() != nil {
		socket.Close()
		return nil, ErrChanged
	}
	return &nativeClientConnection{socket: socket, uid: p.HelperUID, gid: p.HelperGID, pin: -1, alive: nativeAlive, closeFD: unix.Close, checkPath: checkPath}, nil
}

// responseAncillary owns all received descriptors until returning a single
// validated pidfd. Complete rights/pidfd words are closed even on malformed
// lengths or later controls. Truncation never yields authenticated data.
func responseAncillary(oob []byte, flags, n int, uid, gid uint32, closeFD func(int) error) (unix.Ucred, int, error) {
	valid := flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) == 0
	var cred unix.Ucred
	credentials, pidfds := 0, 0
	fds := []int{}
	for len(oob) > 0 {
		if len(oob) < unix.CmsgLen(0) {
			valid = false
			break
		}
		hdr, data, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			valid = false
			break
		}
		switch {
		case hdr.Level == unix.SOL_SOCKET && hdr.Type == unix.SCM_CREDENTIALS:
			credentials++
			if len(data) != unix.SizeofUcred {
				valid = false
				break
			}
			got, err := unix.ParseUnixCredentials(&unix.SocketControlMessage{Header: hdr, Data: data})
			if err != nil || got == nil {
				valid = false
				break
			}
			cred = *got
			if n > 0 && (cred.Pid <= 0 || cred.Uid != uid || cred.Gid != gid) {
				valid = false
			}
		case hdr.Level == unix.SOL_SOCKET && (hdr.Type == unix.SCM_PIDFD || hdr.Type == unix.SCM_RIGHTS):
			if hdr.Type == unix.SCM_PIDFD {
				pidfds++
				if len(data) != 4 {
					valid = false
				}
			} else {
				valid = false
			}
			for len(data) >= 4 {
				fd := int32(binary.NativeEndian.Uint32(data[:4]))
				data = data[4:]
				if fd < 0 {
					valid = false
				} else {
					fds = append(fds, int(fd))
				}
			}
		default:
			valid = false
		}
		oob = rest
	}
	if n > 0 {
		valid = valid && credentials == 1 && pidfds == 1 && len(fds) == 1
	} else {
		// Linux EOF may include the all-zero credential sentinel, never a data pin.
		valid = valid && credentials <= 1 && (credentials == 0 || cred == (unix.Ucred{})) && pidfds == 0 && len(fds) == 0
	}
	if !valid {
		for _, fd := range fds {
			_ = closeFD(fd)
		}
		return unix.Ucred{}, -1, ErrRejected
	}
	if n == 0 {
		return unix.Ucred{}, -1, nil
	}
	return cred, fds[0], nil
}

type nativeClientConnection struct {
	socket           clientSocket
	uid, gid         uint32
	mu               sync.Mutex
	pin              int
	writer           unix.Ucred
	closed, poisoned bool
	alive            func(int) bool
	closeFD          func(int) error
	checkPath        func() error
}

func (c *nativeClientConnection) closePin() {
	if c.pin >= 0 {
		_ = c.closeFD(c.pin)
		c.pin = -1
	}
}
func (c *nativeClientConnection) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	reject := func() (int, error) { c.poisoned = true; c.closePin(); clear(p); return 0, ErrRejected }
	if c.closed || c.poisoned || c.pin >= 0 && !c.alive(c.pin) {
		return reject()
	}
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(4)+unix.CmsgSpace(4*253))
	n, on, flags, _, err := c.socket.ReadMsgUnix(p, oob)
	if n < 0 || n > len(p) || on < 0 || on > len(oob) {
		return reject()
	}
	cred, fd, controlErr := responseAncillary(oob[:on], flags, n, c.uid, c.gid, c.closeFD)
	if controlErr != nil {
		return reject()
	}
	if fd >= 0 {
		// The candidate pin and the first pin must both be alive. While the first
		// process is pinned and alive, its numeric PID cannot be reused by a writer.
		good := c.alive(fd) && (c.pin < 0 || cred == c.writer && c.alive(c.pin))
		if good && c.pin < 0 {
			c.pin, c.writer = fd, cred
		} else {
			_ = c.closeFD(fd)
		}
		if !good {
			return reject()
		}
	}
	if n > 0 && err != nil || n == 0 && err != nil && err != io.EOF {
		return reject()
	}
	if c.pin < 0 || !c.alive(c.pin) {
		return reject()
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}
func (c *nativeClientConnection) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.poisoned {
		return 0, ErrRejected
	}
	if len(p) == 0 {
		return 0, nil
	}
	n, on, err := c.socket.WriteMsgUnix(p, nil, nil)
	if err != nil || n <= 0 || n > len(p) || on != 0 {
		c.poisoned = true
		return 0, ErrRejected
	}
	return n, nil
}
func (c *nativeClientConnection) CloseWrite() error             { return c.socket.CloseWrite() }
func (c *nativeClientConnection) SetDeadline(t time.Time) error { return c.socket.SetDeadline(t) }
func (c *nativeClientConnection) Check() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.poisoned || c.pin < 0 || !c.alive(c.pin) || c.checkPath() != nil || !c.alive(c.pin) {
		return ErrChanged
	}
	return nil
}
func (c *nativeClientConnection) Close() error {
	// Interrupt blocking I/O before waiting for the lock protecting the pidfd.
	err := c.socket.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.closePin()
	}
	return err
}
