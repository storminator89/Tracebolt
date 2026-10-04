//go:build linux

package lanclient

import (
	"context"
	"io"
	"net"
	"time"

	"golang.org/x/sys/unix"
	"localrmm/internal/journalhelper"
)

// Only this fixed root-protected socket is used in production. SO_PEERCRED on
// a systemd-created listening socket identifies its creator, not the process
// writing the response. SO_PASSCRED/recvmsg authenticate the actual writer.
func callJournalHelper(ctx context.Context, local journalLocal, request journalhelper.Request) (journalhelper.Response, error) {
	dir, e := journalRootDirectory([]string{"run", "tracebolt-journal-reader"})
	if e != nil {
		return journalhelper.Response{}, errJournalHelper
	}
	defer dir.Close()
	var before, after unix.Stat_t
	valid := func(st unix.Stat_t) bool {
		return st.Uid == 0 && st.Gid == local.deployment.AgentGID && st.Mode&unix.S_IFMT == unix.S_IFSOCK && st.Mode&07777 == 0660 && st.Nlink == 1
	}
	if unix.Fstatat(int(dir.Fd()), "reader.sock", &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !valid(before) {
		return journalhelper.Response{}, errJournalHelper
	}
	var dialer net.Dialer
	conn, e := dialer.DialContext(ctx, "unix", journalhelper.SocketPath)
	if e != nil {
		return journalhelper.Response{}, errJournalHelper
	}
	defer conn.Close()
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return journalhelper.Response{}, errJournalHelper
	}
	fresh, e := journalRootDirectory([]string{"run", "tracebolt-journal-reader"})
	if e != nil {
		return journalhelper.Response{}, errJournalHelper
	}
	defer fresh.Close()
	var d1, d2 unix.Stat_t
	if unix.Fstatat(int(dir.Fd()), "reader.sock", &after, unix.AT_SYMLINK_NOFOLLOW) != nil || !valid(after) || !journalSame(before, after) || unix.Fstat(int(dir.Fd()), &d1) != nil || unix.Fstat(int(fresh.Fd()), &d2) != nil || !journalSame(d1, d2) {
		return journalhelper.Response{}, errJournalHelper
	}
	return journalSocketExchange(ctx, c, local.deployment.HelperUID, local.deployment.HelperGID, request)
}

func journalSocketExchange(ctx context.Context, c *net.UnixConn, uid, gid uint32, request journalhelper.Request) (journalhelper.Response, error) {
	if ctx == nil || ctx.Err() != nil || c == nil {
		return journalhelper.Response{}, errJournalHelper
	}
	raw, e := c.SyscallConn()
	if e != nil {
		return journalhelper.Response{}, errJournalHelper
	}
	var inner error
	if raw.Control(func(fd uintptr) { inner = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }) != nil || inner != nil {
		return journalhelper.Response{}, errJournalHelper
	}
	deadline := time.Now().Add(journalhelper.ConnectionTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if c.SetDeadline(deadline) != nil {
		return journalhelper.Response{}, errJournalHelper
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { c.Close(); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	body, e := journalhelper.EncodeRequest(request)
	if e != nil {
		return journalhelper.Response{}, errJournalHelper
	}
	for len(body) > 0 {
		n, e := c.Write(body)
		if e != nil || n <= 0 || n > len(body) {
			return journalhelper.Response{}, errJournalHelper
		}
		body = body[n:]
	}
	reader := &journalCredentialReader{c: c, uid: uid, gid: gid}
	response, e := journalhelper.ReadResponse(reader)
	if e != nil || ctx.Err() != nil {
		return journalhelper.Response{}, errJournalHelper
	}
	// Exactly one response frame per connection. Extra bytes or a missing EOF
	// are invalid, including attacker-controlled delayed appended frames.
	var sentinel [1]byte
	if n, e := reader.Read(sentinel[:]); n != 0 || e != io.EOF {
		return journalhelper.Response{}, errJournalHelper
	}
	return response, nil
}

type journalCredentialReader struct {
	c        *net.UnixConn
	uid, gid uint32
	pid      int32
}

func (r *journalCredentialReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(4*16))
	n, on, flags, _, e := r.c.ReadMsgUnix(p, oob)
	if n == 0 && on == 0 && (e == io.EOF || e == nil) {
		return 0, io.EOF
	}
	messages, parseErr := unix.ParseSocketControlMessage(oob[:on])
	valid := parseErr == nil && flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) == 0
	credentials := 0
	eof := n == 0 && e == io.EOF
	for _, message := range messages {
		if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS {
			fds, err := unix.ParseUnixRights(&message)
			if err == nil {
				for _, fd := range fds {
					unix.Close(fd)
				}
			}
			valid = false
			continue
		}
		if message.Header.Level != unix.SOL_SOCKET || message.Header.Type != unix.SCM_CREDENTIALS {
			valid = false
			continue
		}
		cred, err := unix.ParseUnixCredentials(&message)
		credentials++
		if eof && err == nil && cred != nil {
			continue
		}
		if err != nil || cred == nil || cred.Uid != r.uid || cred.Gid != r.gid || cred.Pid <= 0 {
			valid = false
			continue
		}
		if r.pid == 0 {
			r.pid = cred.Pid
		} else if r.pid != cred.Pid {
			valid = false
		}
	}
	// Linux may attach its zero-PID/nobody credential sentinel to EOF. It
	// carries no data and cannot authorize any byte of the response.
	if eof && valid && credentials <= 1 {
		return 0, io.EOF
	}
	if !valid || credentials != 1 || n <= 0 {
		return 0, errJournalHelper
	}
	if e != nil {
		return 0, errJournalHelper
	}
	return n, nil
}
