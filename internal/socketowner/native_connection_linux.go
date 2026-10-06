//go:build linux

package socketowner

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type nativeMessageSocket interface {
	ReadMsgUnix([]byte, []byte) (int, int, int, *net.UnixAddr, error)
	WriteMsgUnix([]byte, []byte, *net.UnixAddr) (int, int, error)
	SetDeadline(time.Time) error
	Close() error
}

// recvCredentials also closes every well-formed SCM_RIGHTS already received,
// including rights preceding a malformed tail. It never exposes payload bytes
// until the entire ancillary buffer is validated. Linux/Go recvmsg uses
// MSG_CMSG_CLOEXEC; truncated excess rights are closed by the kernel.
func recvCredentials(oob []byte, flags, n int, expected unix.Ucred, closeFD func(int) error) (bool, error) {
	valid := flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) == 0
	credentials := 0
	for len(oob) > 0 {
		if len(oob) < unix.CmsgLen(0) {
			valid = false
			break
		}
		hdr, data, rest, e := unix.ParseOneSocketControlMessage(oob)
		if e != nil {
			valid = false
			break
		}
		msg := unix.SocketControlMessage{Header: hdr, Data: data}
		switch {
		case hdr.Level == unix.SOL_SOCKET && hdr.Type == unix.SCM_RIGHTS:
			// Parse only complete descriptor words; x/sys assumes this shape.
			complete := len(data) / 4 * 4
			if complete > 0 {
				msg.Data = data[:complete]
				fds, e := unix.ParseUnixRights(&msg)
				if e == nil {
					for _, fd := range fds {
						_ = closeFD(fd)
					}
				}
			}
			valid = false
		case hdr.Level == unix.SOL_SOCKET && hdr.Type == unix.SCM_PIDFD:
			// Unexpected kernel-supplied pidfds are owned by this receiver too.
			// Negative errno sentinels are not descriptors.
			if len(data) == 4 {
				fd := int32(binary.NativeEndian.Uint32(data))
				if fd >= 0 {
					_ = closeFD(int(fd))
				}
			}
			valid = false
		case hdr.Level == unix.SOL_SOCKET && hdr.Type == unix.SCM_CREDENTIALS:
			credentials++
			if len(data) != unix.SizeofUcred {
				valid = false
				break
			}
			cred, e := unix.ParseUnixCredentials(&msg)
			if e != nil || cred == nil || n > 0 && *cred != expected {
				valid = false
			}
		default:
			valid = false
		}
		oob = rest
	}
	if !valid || credentials > 1 || n > 0 && credentials != 1 {
		return false, ErrRejected
	}
	return n > 0 && credentials == 1, nil
}

type nativeConnection struct {
	socket                   nativeMessageSocket
	expected, source         unix.Ucred
	facts                    func(context.Context) (Facts, error)
	closePins                func()
	closeFD                  func(int) error
	mu                       sync.Mutex
	closed, poisoned, writer bool
}

func (c *nativeConnection) reject() { c.mu.Lock(); c.poisoned = true; c.mu.Unlock() }
func (c *nativeConnection) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	invalid := c.closed || c.poisoned
	c.mu.Unlock()
	if invalid {
		return 0, ErrRejected
	}
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(4*253))
	n, on, flags, _, e := c.socket.ReadMsgUnix(p, oob)
	if n < 0 || n > len(p) || on < 0 || on > len(oob) {
		c.reject()
		return 0, ErrRejected
	}
	verified, controlErr := recvCredentials(oob[:on], flags, n, c.expected, c.closeFD)
	if controlErr != nil || n > 0 && e != nil || n == 0 && e != nil && e != io.EOF {
		c.reject()
		return 0, ErrRejected
	}
	if n == 0 {
		return 0, io.EOF
	}
	if !verified {
		c.reject()
		return 0, ErrRejected
	}
	c.mu.Lock()
	c.writer = true
	c.mu.Unlock()
	return n, nil
}
func (c *nativeConnection) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	invalid := c.closed || c.poisoned
	c.mu.Unlock()
	if invalid {
		return 0, ErrRejected
	}
	// Explicit credentials identify this response writer even when systemd created
	// the listener. The client must enable SO_PASSCRED and verify every receive.
	oob := unix.UnixCredentials(&c.source)
	n, on, e := c.socket.WriteMsgUnix(p, oob, nil)
	if e != nil || n <= 0 || n > len(p) || on != len(oob) {
		c.reject()
		return 0, ErrRejected
	}
	return n, nil
}
func (c *nativeConnection) SetDeadline(t time.Time) error { return c.socket.SetDeadline(t) }
func (c *nativeConnection) Facts(ctx context.Context) (Facts, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.poisoned || !c.writer || ctx == nil || ctx.Err() != nil {
		return Facts{}, ErrChanged
	}
	f, e := c.facts(ctx)
	if e != nil || f.PeerPID != c.expected.Pid || f.PeerUID != c.expected.Uid || f.PeerGID != c.expected.Gid {
		return Facts{}, ErrChanged
	}
	f.WriterPID = c.expected.Pid
	f.WriterVerified = true
	return f, nil
}
func (c *nativeConnection) Close() error {
	// Close the socket first to interrupt a blocked read/write. Closing pins is
	// synchronized with Facts, preventing reused descriptors during cancellation.
	e := c.socket.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		if c.closePins != nil {
			c.closePins()
		}
	}
	return e
}
