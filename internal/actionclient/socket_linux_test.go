//go:build linux

package actionclient

import (
	"errors"
	"io"
	"testing"

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
