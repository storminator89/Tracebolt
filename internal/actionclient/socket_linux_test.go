//go:build linux

package actionclient

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestProtectedSocketAndDirectoryMetadata(t *testing.T) {
	base := unix.Stat_t{Uid: 0, Gid: 1234, Mode: unix.S_IFSOCK | 0660, Nlink: 1, Ino: 1, Dev: 1}
	if !safeSocket(base, 1234) {
		t.Fatal("safe socket denied")
	}
	for _, kind := range []string{"owner", "group", "mode", "symlink", "file", "links", "special", "zero_group"} {
		t.Run(kind, func(t *testing.T) {
			s := base
			group := uint32(1234)
			switch kind {
			case "owner":
				s.Uid = 1234
			case "group":
				s.Gid = 1235
			case "mode":
				s.Mode |= 0002
			case "symlink":
				s.Mode = unix.S_IFLNK | 0660
			case "file":
				s.Mode = unix.S_IFREG | 0660
			case "links":
				s.Nlink = 2
			case "special":
				s.Mode |= unix.S_ISGID
			case "zero_group":
				group = 0
				s.Gid = 0
			}
			if safeSocket(s, group) {
				t.Fatal("unsafe socket accepted")
			}
		})
	}
	d := unix.Stat_t{Uid: 0, Mode: unix.S_IFDIR | 0755}
	if !safeDirectory(d) {
		t.Fatal("safe ancestor denied")
	}
	d.Mode |= 0020
	if safeDirectory(d) {
		t.Fatal("writable ancestor accepted")
	}
	d.Mode = unix.S_IFLNK | 0755
	if safeDirectory(d) {
		t.Fatal("symlink ancestor accepted")
	}
	other := base
	other.Ino++
	if sameObject(base, other) {
		t.Fatal("replaced inode accepted")
	}
	other = base
	other.Ctim.Nsec++
	if sameObject(base, other) {
		t.Fatal("changed metadata accepted")
	}
}

// This is a constructed ancillary-metadata unit test, not a kernel exchange.
func TestCredentialReaderRequiresActualRootWriterEveryChunk(t *testing.T) {
	good := unix.UnixCredentials(&unix.Ucred{Pid: 123, Uid: 0, Gid: 0})
	r := &credentialReader{}
	if n, err := r.validateMessage(8, good, 0, nil); n != 8 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := r.validateMessage(4, good, 0, nil); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	for _, kind := range []string{"uid", "gid", "pid", "changed_pid", "missing", "duplicate", "truncated", "malformed", "read_error"} {
		t.Run(kind, func(t *testing.T) {
			r := &credentialReader{pid: 123}
			b := good
			flags := 0
			var readErr error
			switch kind {
			case "uid":
				b = unix.UnixCredentials(&unix.Ucred{Pid: 123, Uid: 1234})
			case "gid":
				b = unix.UnixCredentials(&unix.Ucred{Pid: 123, Gid: 1234})
			case "pid":
				b = unix.UnixCredentials(&unix.Ucred{})
			case "changed_pid":
				b = unix.UnixCredentials(&unix.Ucred{Pid: 124})
			case "missing":
				b = nil
			case "duplicate":
				b = append(append([]byte(nil), good...), good...)
			case "truncated":
				flags = unix.MSG_CTRUNC
			case "malformed":
				b = []byte("bad control message")
			case "read_error":
				readErr = io.ErrUnexpectedEOF
			}
			if n, err := r.validateMessage(1, b, flags, readErr); n != 0 || err == nil {
				t.Fatal("untrusted response bytes accepted", n, err)
			}
		})
	}
	if n, err := r.validateMessage(0, nil, 0, io.EOF); n != 0 || err != io.EOF {
		t.Fatal(n, err)
	}
	sentinel := unix.UnixCredentials(&unix.Ucred{Uid: 65534, Gid: 65534})
	if n, err := r.validateMessage(0, sentinel, 0, io.EOF); n != 0 || err != io.EOF {
		t.Fatal("EOF sentinel rejected", n, err)
	}
	if n, err := r.validateMessage(1, sentinel, 0, nil); n != 0 || err == nil {
		t.Fatal("EOF sentinel authorized data")
	}
}
func TestCredentialReaderRejectsAndClosesPassedDescriptors(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	r := &credentialReader{}
	b := append(unix.UnixCredentials(&unix.Ucred{Pid: 123}), unix.UnixRights(fds[0])...)
	if n, err := r.validateMessage(1, b, 0, nil); n != 0 || err == nil {
		t.Fatal("rights accepted", n, err)
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("passed descriptor leaked", err)
	}
}

func TestRootSocketPeerRequiresRootUIDGIDAndPID(t *testing.T) {
	for _, c := range []*unix.Ucred{nil, {}, {Pid: 1, Uid: 1}, {Pid: 1, Gid: 1}, {Pid: -1}} {
		if rootPeer(c) {
			t.Fatal("untrusted listening peer accepted", c)
		}
	}
	if !rootPeer(&unix.Ucred{Pid: 1}) {
		t.Fatal("root listening peer denied")
	}
	r := &credentialReader{}
	if _, err := r.validateMessage(0, nil, unix.MSG_CTRUNC, io.EOF); err == io.EOF {
		t.Fatal("truncated control frame accepted as EOF")
	}
}

// TestCredentialReaderNativePasscredRejectsNonRootWriter exchanges actual bytes
// over AF_UNIX. No credentials are constructed or supplied by the writer: Linux
// supplies SCM_CREDENTIALS because the receiver enables SO_PASSCRED. This proves
// ordinary-user writer rejection, never installed-helper/root-writer acceptance.
func TestCredentialReaderNativePasscredRejectsNonRootWriter(t *testing.T) {
	required := os.Getenv("TRACEBOLT_REQUIRE_NATIVE_ACTION_IPC") == "1"
	u, e, s := unix.Getresuid()
	g, eg, sg := unix.Getresgid()
	if u <= 0 || u != e || u != s || g <= 0 || g != eg || g != sg {
		if required {
			t.Fatal("required native action IPC must run as an ordinary unmodified user")
		}
		t.Skip("native non-root writer test requires an ordinary unmodified user")
	}
	// Keep AF_UNIX's pathname short independently of the Go test name.
	root, err := os.MkdirTemp("", "tb-action-client-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	name := filepath.Join(root, "action.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		if required {
			t.Fatal("required native Unix socket fixture unavailable", err)
		}
		t.Skipf("native Unix socket fixture unavailable in this environment: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("unix", name, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	receiver, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatal("receiver is not AF_UNIX")
	}
	writer, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	for _, conn := range []*net.UnixConn{receiver, writer} {
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := receiver.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	var enabled int
	if err := raw.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
		if optionErr == nil {
			enabled, optionErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED)
		}
	}); err != nil || optionErr != nil || enabled != 1 {
		t.Fatal("enable kernel per-message credentials", err, optionErr)
	}
	// First establish that actual bytes arrive with exactly the kernel's current
	// PID/UID/GID, independently of the production reader's root-only predicate.
	if n, err := writer.Write([]byte{'a'}); n != 1 || err != nil {
		t.Fatal("native writer", n, err)
	}
	data := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	n, on, flags, _, err := receiver.ReadMsgUnix(data, oob)
	if n != 1 || data[0] != 'a' || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 || err != nil {
		t.Fatal("native message", n, flags, err)
	}
	messages, err := unix.ParseSocketControlMessage(oob[:on])
	if err != nil || len(messages) != 1 || messages[0].Header.Level != unix.SOL_SOCKET || messages[0].Header.Type != unix.SCM_CREDENTIALS {
		t.Fatal("missing or unexpected kernel credential message", err)
	}
	credential, err := unix.ParseUnixCredentials(&messages[0])
	if err != nil || credential == nil || credential.Pid != int32(os.Getpid()) || credential.Uid != uint32(u) || credential.Gid != uint32(g) {
		t.Fatal("kernel writer credentials do not match the ordinary process", err)
	}
	// Now call the real Read method, not validateMessage with constructed bytes.
	// The buffer confirms each byte arrived, but n=0 prevents its authorization.
	reader := &credentialReader{conn: receiver}
	for _, payload := range []byte{'b', 'c'} {
		if n, err := writer.Write([]byte{payload}); n != 1 || err != nil {
			t.Fatal("native writer", n, err)
		}
		data[0] = 0
		if n, err := reader.Read(data); n != 0 || !errors.Is(err, ErrRejected) || data[0] != payload || reader.pid != 0 {
			t.Fatal("production reader did not reject the actual non-root writer", n, err)
		}
	}
}
