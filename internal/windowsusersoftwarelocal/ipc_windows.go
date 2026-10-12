//go:build windows

package windowsusersoftwarelocal

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"
)

// FILE_APPEND_DATA also means FILE_CREATE_PIPE_INSTANCE and is excluded.
const pipeClientAccess uint32 = 0x00120183

func pipeSDDL(sid string) string {
	return "O:" + sid + "G:" + sid + "D:P(A;;FA;;;SY)(A;;FA;;;" + sid + ")(A;;0x00120183;;;IU)"
}

type pipeChannel struct {
	handle       windows.Handle
	peer, own    *heldPeer
	server       bool
	first        []byte
	failedRevert bool
}

func (c *pipeChannel) read(ctx context.Context) ([]byte, error) {
	if c.first != nil {
		b := c.first
		c.first = nil
		return b, nil
	}
	return readFrame(ctx, c.handle)
}
func (c *pipeChannel) fatal() bool                               { return c.failedRevert }
func (c *pipeChannel) write(ctx context.Context, b []byte) error { return writeFrame(ctx, c.handle, b) }
func (c *pipeChannel) check() error {
	var pid uint32
	var e error
	if c.server {
		e = windows.GetNamedPipeClientProcessId(c.handle, &pid)
	} else {
		e = windows.GetNamedPipeServerProcessId(c.handle, &pid)
	}
	if e != nil || pid != c.peer.pid {
		return ErrBinding
	}
	if e = c.peer.check(); e != nil {
		if errors.Is(e, ErrRevert) {
			c.failedRevert = true
		}
		return e
	}
	if e = c.own.check(); e != nil {
		return e
	}
	return nil
}

// Serve is called only by the separately enabled observation service. It keeps
// one non-inheritable, local-only first instance for its lifetime, preventing
// name replacement between captures. No action service grants are consulted.
func Serve(ctx context.Context, h Handler) error {
	if ctx == nil || h == nil {
		return ErrInvalid
	}
	own, e := openOwnPeer(true)
	if e != nil {
		return e
	}
	defer own.close()
	if e = awaitOwnServiceReady(ctx, own.pid, own.checkIdentity, own.ownStatus, waitReady); e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString(pipeSDDL(own.serviceSID))
	if e != nil {
		return ErrBinding
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd, InheritHandle: 0}
	pipe, e := windows.CreateNamedPipe(windows.StringToUTF16Ptr(PipeName), windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE|windows.FILE_FLAG_OVERLAPPED, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 64<<10, 64<<10, 5000, &sa)
	if e != nil {
		return ErrUnavailable
	}
	defer windows.CloseHandle(pipe)
	for ctx.Err() == nil {
		if own.check() != nil {
			return ErrBinding
		}
		_, e = overlapped(ctx, pipe, func(o *windows.Overlapped, n *uint32) error { return windows.ConnectNamedPipe(pipe, o) })
		if e != nil && !errors.Is(e, windows.ERROR_PIPE_CONNECTED) {
			return e
		}
		conversationErr := func() error {
			defer windows.DisconnectNamedPipe(pipe)
			req, cancel := context.WithTimeout(ctx, ConversationTimeout)
			defer cancel()
			// Identification is the security context of the last read. The
			// first frame is fixed and tightly bounded; no handler runs yet.
			hello, e := readFrameMax(req, pipe, 512)
			if e != nil {
				return e
			}
			m, e := decode(hello)
			if e != nil || m.Operation != "begin" || m.Nonce != "" || m.Challenge != nil || m.Capture != nil {
				return ErrInvalid
			}
			peer, e := openClientPeer(pipe)
			if e != nil {
				return e
			}
			defer peer.close()
			c := &pipeChannel{handle: pipe, peer: peer, own: own, server: true, first: hello}
			e = serveConversation(req, c, h, peer.peer)
			if c.failedRevert {
				return ErrRevert
			}
			return e
		}()
		if errors.Is(conversationErr, ErrRevert) {
			return ErrRevert
		}

	}
	return ctx.Err()
}

var foregroundUsed atomic.Bool

// RunForeground is one-shot and MUST be called only from the dedicated helper
// executable, whose main exits immediately on return. Capture timeout can leave
// a blocked native thread; process exit is the hard cleanup boundary. This is
// never invoked by the observation service, Setup or a periodic collector.
func RunForeground(ctx context.Context, consent func(context.Context, Challenge) bool) error {
	if ctx == nil || consent == nil || !foregroundUsed.CompareAndSwap(false, true) || !IsForegroundConsole() {
		return ErrBinding
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !noThreadImpersonation() {
		return ErrBinding
	}
	own, e := ownNormalPeer()
	if e != nil {
		return e
	}
	defer own.close()
	ctx, cancel := context.WithTimeout(ctx, ConversationTimeout)
	defer cancel()
	// Identification SQOS prevents a malicious pipe server from impersonating
	// this user for reads or other effects. Authentication precedes every write.
	pipe, e := windows.CreateFile(windows.StringToUTF16Ptr(PipeName), pipeClientAccess, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if e != nil {
		return ErrUnavailable
	}
	defer windows.CloseHandle(pipe)
	var pid uint32
	if windows.GetNamedPipeServerProcessId(pipe, &pid) != nil {
		return ErrBinding
	}
	peer, e := openServerPeer(ctx, pid)
	if e != nil {
		return e
	}
	defer peer.close()
	return clientConversation(ctx, &pipeChannel{handle: pipe, peer: peer, own: own}, consent, captureForeground)
}
func IsForegroundConsole() bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) == nil && windows.GetConsoleMode(windows.Handle(os.Stdout.Fd()), &mode) == nil
}
