//go:build linux

package socketowner

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestNamespaceDirectoryUsesTraversalOnlyDescriptor(t *testing.T) {
	expected := unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if nativeNamespaceDirFlags != expected || nativeDirFlags&unix.O_PATH != 0 {
		t.Fatal("namespace traversal changed directory enumeration flags")
	}
	// A disposable ordinary directory is enough to check descriptor semantics;
	// no host proc directory, namespace, process or capability is inspected.
	fd, err := unix.Open(t.TempDir(), nativeNamespaceDirFlags, 0)
	if err != nil {
		t.Fatal("temporary traversal descriptor")
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || unix.Fstatfs(fd, &fs) != nil {
		t.Fatal("traversal descriptor lost metadata operations")
	}
	if _, err := unix.Read(fd, make([]byte, 1)); !errors.Is(err, unix.EBADF) {
		t.Fatal("namespace traversal descriptor permits directory reads")
	}
	// Keep the runtime call site bound to the narrow helper, while task/PID
	// directory callers continue using their original enumeration descriptor.
	raw, err := os.ReadFile("native_process_linux.go")
	if err != nil || !bytes.Contains(raw, []byte("nsdir, e := procNamespaceDirectory(dir)")) ||
		bytes.Contains(raw, []byte("procDirectory(dir, \"ns\")")) {
		t.Fatal("namespace traversal call site changed")
	}
}

func fixtureStatus(uid, gid uint32, cap uint64) []byte {
	return []byte(fmt.Sprintf("Name:\tfixture\nPid:\t100\nUid:\t%d %d %d %d\nGid:\t%d %d %d %d\nGroups:\t\nCapEff:\t%016x\nCapPrm:\t%016x\nCapInh:\t%016x\nCapAmb:\t%016x\nCapBnd:\t%016x\nNoNewPrivs:\t1\nSeccomp:\t2\n", uid, uid, uid, uid, gid, gid, gid, gid, cap, cap, cap, cap, cap))
}
func TestNativeStatusAllCredentialSets(t *testing.T) {
	for _, cap := range []uint64{0, PtraceCapability} {
		raw := fixtureStatus(1201, 1201, cap)
		i, e := parseNativeStatus(raw)
		if e != nil || validateNativeIdentity(i, 1201, 1201, cap) != nil {
			t.Fatal("fixture", e)
		}
		for _, field := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"} {
			s := strings.Replace(string(raw), fmt.Sprintf("%s:\t%016x", field, cap), fmt.Sprintf("%s:\t%016x", field, cap|1), 1)
			i, e := parseNativeStatus([]byte(s))
			if e == nil && validateNativeIdentity(i, 1201, 1201, cap) == nil {
				t.Fatal("extra capability", field)
			}
		}
	}
	for _, replace := range [][2]string{{"1201 1201 1201 1201", "1201 0 1201 1201"}, {"1201 1201 1201 1201", "1201 1201 1201 0"}, {"Groups:\t", "Groups:\t500"}, {"NoNewPrivs:\t1", "NoNewPrivs:\t0"}, {"Seccomp:\t2", "Seccomp:\t0"}, {"CapAmb:\t0000000000080000\n", ""}, {"Pid:\t100", "Pid:\t0"}} {
		raw := bytes.Replace(fixtureStatus(1201, 1201, PtraceCapability), []byte(replace[0]), []byte(replace[1]), 1)
		i, e := parseNativeStatus(raw)
		if e == nil && validateNativeIdentity(i, 1201, 1201, PtraceCapability) == nil {
			t.Fatal("credential accepted", replace)
		}
	}
	duplicate := append(fixtureStatus(1201, 1201, PtraceCapability), []byte("CapEff:\t0000000000080000\n")...)
	if _, e := parseNativeStatus(duplicate); e == nil {
		t.Fatal("duplicate")
	}
}
func TestProtectedMetadataRulesWithoutFilesystem(t *testing.T) {
	st := unix.Stat_t{Uid: 0, Gid: 1201, Mode: unix.S_IFREG | 0640, Nlink: 1, Size: 100, Ino: 10, Dev: 1}
	if !safeNativeFile(st, 0640, 1024) {
		t.Fatal("fixture")
	}
	for _, change := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Uid = 1201 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFLNK | 0640 }, func(s *unix.Stat_t) { s.Nlink = 2 }, func(s *unix.Stat_t) { s.Mode |= 0020 }, func(s *unix.Stat_t) { s.Size = 1025 }, func(s *unix.Stat_t) { s.Mode |= unix.S_ISUID }} {
		bad := st
		change(&bad)
		if safeNativeFile(bad, 0640, 1024) {
			t.Fatal("unsafe file")
		}
	}
	for _, change := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Ino++ }, func(s *unix.Stat_t) { s.Gid++ }, func(s *unix.Stat_t) { s.Ctim.Sec++ }, func(s *unix.Stat_t) { s.Mtim.Nsec++ }} {
		bad := st
		change(&bad)
		if sameNativeObject(st, bad) || objectRevision(st) == objectRevision(bad) {
			t.Fatal("metadata revision")
		}
	}
}
func TestNativeArtifactModesMatchInstalledRoles(t *testing.T) {
	for _, tc := range []struct {
		id   fixedObject
		mode uint32
	}{{agentObject, 0555}, {helperObject, 0755}} {
		_, mode, max, ok := fixedSpec(tc.id)
		if !ok || mode != tc.mode || max != 128<<20 {
			t.Fatal("fixed installed role contract")
		}
		st := unix.Stat_t{Uid: 0, Gid: 0, Mode: unix.S_IFREG | tc.mode, Nlink: 1, Size: 1}
		if !safeNativeFile(st, mode, max) {
			t.Fatal("exact installed artifact rejected")
		}
		other := uint32(0755)
		if tc.id == helperObject {
			other = 0555
		}
		st.Mode = unix.S_IFREG | other
		if safeNativeFile(st, mode, max) {
			t.Fatal("different executable mode accepted")
		}
	}
}

func fixtureListenerProbe() listenerProbe {
	return listenerProbe{
		stat: func(_ int, s *unix.Stat_t) error {
			*s = unix.Stat_t{Uid: 0, Mode: unix.S_IFSOCK | 0777, Ino: 42}
			return nil
		},
		fs: func(_ int, s *unix.Statfs_t) error { s.Type = unix.SOCKFS_MAGIC; return nil },
		option: func(_ int, level, opt int) (int, error) {
			if level != unix.SOL_SOCKET {
				return 0, ErrRejected
			}
			return map[int]int{unix.SO_DOMAIN: unix.AF_UNIX, unix.SO_TYPE: unix.SOCK_STREAM, unix.SO_ACCEPTCONN: 1}[opt], nil
		},
		name: func(int) (unix.Sockaddr, error) { return &unix.SockaddrUnix{Name: SocketPath}, nil },
		statx: func(_ int, path string, flags, mask int, s *unix.Statx_t) error {
			if path != "" || flags != unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW || mask != unix.STATX_INO|unix.STATX_MNT_ID|unix.STATX_TYPE {
				return ErrRejected
			}
			s.Mask = uint32(mask)
			s.Ino = 42
			s.Mnt_id = 7
			s.Mode = unix.S_IFSOCK
			return nil
		},
		pathname: func(Policy) (string, error) { return strings.Repeat("c", 64), nil },
	}
}
func TestListenerWitnessInjectedSyscallsOnly(t *testing.T) {
	proof, e := inspectListenerUsing(3, fixturePolicy(), fixtureListenerProbe())
	if e != nil || proof.Mount != 7 || proof.Inode != 42 {
		t.Fatal(e)
	}
	cases := map[string]func(*listenerProbe){
		"nonroot listener": func(p *listenerProbe) {
			p.stat = func(_ int, s *unix.Stat_t) error { s.Uid = 1201; s.Mode = unix.S_IFSOCK; s.Ino = 42; return nil }
		},
		"wrong fs": func(p *listenerProbe) {
			p.fs = func(_ int, s *unix.Statfs_t) error { s.Type = unix.PROC_SUPER_MAGIC; return nil }
		},
		"not listening": func(p *listenerProbe) {
			orig := p.option
			p.option = func(fd, l, o int) (int, error) {
				if o == unix.SO_ACCEPTCONN {
					return 0, nil
				}
				return orig(fd, l, o)
			}
		},
		"inet socket": func(p *listenerProbe) {
			orig := p.option
			p.option = func(fd, l, o int) (int, error) {
				if o == unix.SO_DOMAIN {
					return unix.AF_INET, nil
				}
				return orig(fd, l, o)
			}
		},
		"foreign path": func(p *listenerProbe) {
			p.name = func(int) (unix.Sockaddr, error) { return &unix.SockaddrUnix{Name: "/tmp/other"}, nil }
		},
		"missing mount": func(p *listenerProbe) {
			p.statx = func(_ int, _ string, _, _ int, s *unix.Statx_t) error {
				s.Mask = unix.STATX_INO
				s.Ino = 42
				return nil
			}
		},
		"inode mismatch": func(p *listenerProbe) {
			p.statx = func(_ int, _ string, _, _ int, s *unix.Statx_t) error {
				s.Mask = unix.STATX_INO | unix.STATX_MNT_ID
				s.Ino = 99
				s.Mnt_id = 7
				return nil
			}
		},
		"path changed": func(p *listenerProbe) { p.pathname = func(Policy) (string, error) { return "", ErrChanged } },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := fixtureListenerProbe()
			change(&p)
			if _, e := inspectListenerUsing(3, fixturePolicy(), p); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}

type fixtureMessage struct {
	data, oob []byte
	flags     int
	err       error
}
type fixtureMessages struct {
	input               []fixtureMessage
	output, credentials [][]byte
	closes              int
	deadline            time.Time
}

func (s *fixtureMessages) ReadMsgUnix(p, oob []byte) (int, int, int, *net.UnixAddr, error) {
	if len(s.input) == 0 {
		return 0, 0, 0, nil, io.EOF
	}
	m := s.input[0]
	s.input = s.input[1:]
	return copy(p, m.data), copy(oob, m.oob), m.flags, nil, m.err
}
func (s *fixtureMessages) WriteMsgUnix(p, oob []byte, _ *net.UnixAddr) (int, int, error) {
	s.output = append(s.output, append([]byte(nil), p...))
	s.credentials = append(s.credentials, append([]byte(nil), oob...))
	return len(p), len(oob), nil
}
func (s *fixtureMessages) SetDeadline(d time.Time) error { s.deadline = d; return nil }
func (s *fixtureMessages) Close() error                  { s.closes++; return nil }
func fixtureNativeConn(s *fixtureMessages) *nativeConnection {
	return &nativeConnection{socket: s, expected: unix.Ucred{Pid: 100, Uid: 1200, Gid: 1200}, source: unix.Ucred{Pid: 101, Uid: 1201, Gid: 1201}, facts: func(context.Context) (Facts, error) { return fixtureFacts(), nil }, closeFD: func(int) error { return nil }}
}
func TestCredentialBoundaryAndResponseWriter(t *testing.T) {
	peer := unix.Ucred{Pid: 100, Uid: 1200, Gid: 1200}
	s := &fixtureMessages{input: []fixtureMessage{{data: []byte("hello"), oob: unix.UnixCredentials(&peer)}}}
	c := fixtureNativeConn(s)
	if _, e := c.Facts(context.Background()); e == nil {
		t.Fatal("facts before authenticated data")
	}
	var b [16]byte
	n, e := c.Read(b[:])
	if e != nil || string(b[:n]) != "hello" {
		t.Fatal("read", e)
	}
	f, e := c.Facts(context.Background())
	if e != nil || !f.WriterVerified || f.WriterPID != 100 {
		t.Fatal("facts", e)
	}
	if _, e = c.Write([]byte("reply")); e != nil {
		t.Fatal(e)
	}
	if _, e := recvCredentials(s.credentials[0], 0, len("reply"), c.source, func(int) error { t.Fatal("response passed fd"); return nil }); e != nil {
		t.Fatal("response actual source credentials", e)
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.Facts(cancelCtx); e == nil {
		t.Fatal("cancel")
	}
	if n, e := c.Read(b[:]); n != 0 || e != io.EOF {
		t.Fatal("half close")
	}
}
func TestRejectAncillaryAndCloseRightsBeforeMalformedTail(t *testing.T) {
	peer := unix.Ucred{Pid: 100, Uid: 1200, Gid: 1200}
	valid := unix.UnixCredentials(&peer)
	wrong := peer
	wrong.Pid++
	cases := []fixtureMessage{{data: []byte("x")}, {data: []byte("x"), oob: unix.UnixCredentials(&wrong)}, {data: []byte("x"), oob: append(append([]byte{}, valid...), valid...)}, {data: []byte("x"), oob: valid, flags: unix.MSG_CTRUNC}, {data: []byte("x"), oob: valid, flags: unix.MSG_TRUNC}, {data: []byte("x"), oob: valid, err: errors.New("read failure")}, {oob: valid, flags: unix.MSG_CTRUNC}}
	for _, m := range cases {
		s := &fixtureMessages{input: []fixtureMessage{m}}
		c := fixtureNativeConn(s)
		var b [8]byte
		if n, e := c.Read(b[:]); n != 0 || e == nil {
			t.Fatal("ancillary admitted")
		}
		if _, e := c.Write([]byte("forbidden")); e == nil {
			t.Fatal("poisoned stream wrote")
		}
	}
	closed := []int{}
	oob := append(unix.UnixRights(11, 12), []byte{1, 2, 3}...)
	if _, e := recvCredentials(oob, 0, 1, peer, func(fd int) error { closed = append(closed, fd); return nil }); e == nil || len(closed) != 2 || closed[0] != 11 || closed[1] != 12 {
		t.Fatal("rights leaked or admitted", closed)
	}
	// EOF zero-PID sentinel is allowed only with no payload, no truncation/rights.
	zero := unix.UnixCredentials(&unix.Ucred{})
	if _, e := recvCredentials(zero, 0, 0, peer, func(int) error { return nil }); e != nil {
		t.Fatal("EOF sentinel")
	}
	if _, e := recvCredentials(zero, 0, 1, peer, func(int) error { return nil }); e == nil {
		t.Fatal("data sentinel")
	}
}

func TestMalformedAncillaryLengthsNeverReachUnsafeParsers(t *testing.T) {
	peer := unix.Ucred{Pid: 100, Uid: 1200, Gid: 1200}
	makeControl := func(kind, size int) []byte {
		b := make([]byte, unix.CmsgSpace(size))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
		h.Level = unix.SOL_SOCKET
		h.Type = int32(kind)
		h.SetLen(unix.CmsgLen(size))
		return b
	}
	for _, size := range []int{0, 1, unix.SizeofUcred - 1, unix.SizeofUcred + 1, 2 * unix.SizeofUcred} {
		if _, e := recvCredentials(makeControl(unix.SCM_CREDENTIALS, size), 0, 1, peer, func(int) error { return nil }); e == nil {
			t.Fatalf("credentials length %d", size)
		}
	}
	for _, size := range []int{0, 1, 3, 5, 7} {
		closed := 0
		if _, e := recvCredentials(makeControl(unix.SCM_RIGHTS, size), 0, 1, peer, func(int) error { closed++; return nil }); e == nil || closed != size/4 {
			t.Fatalf("rights length %d closed %d", size, closed)
		}
	}
	if _, e := recvCredentials(makeControl(999, 4), 0, 1, peer, func(int) error { return nil }); e == nil {
		t.Fatal("unknown control")
	}
}

func TestTypedNamespacesAndPIDFDLivenessUseInjectedSyscalls(t *testing.T) {
	for _, kind := range []int{unix.CLONE_NEWPID, unix.CLONE_NEWNET, unix.CLONE_NEWUSER} {
		p := namespaceProbe{
			kind: func(_ int, request uint) (int, error) {
				if request != unix.NS_GET_NSTYPE {
					t.Fatal("wrong namespace ioctl")
				}
				return kind, nil
			},
			fs:   func(_ int, s *unix.Statfs_t) error { s.Type = unix.NSFS_MAGIC; return nil },
			stat: func(_ int, s *unix.Stat_t) error { s.Dev = 1; s.Ino = 100; return nil },
		}
		if id, e := inspectNamespace(9, kind, p); e != nil || id != (NamespaceID{1, 100}) {
			t.Fatal("typed namespace", e)
		}
		original := p.kind
		p.kind = func(int, uint) (int, error) { return unix.CLONE_NEWUTS, nil }
		if _, e := inspectNamespace(9, kind, p); e == nil {
			t.Fatal("wrong namespace type")
		}
		p.kind = original
		p.fs = func(_ int, s *unix.Statfs_t) error { s.Type = unix.PROC_SUPER_MAGIC; return nil }
		if _, e := inspectNamespace(9, kind, p); e == nil {
			t.Fatal("not nsfs")
		}
	}
	if !nativeAliveUsing(9, func(p []unix.PollFd, timeout int) (int, error) {
		if len(p) != 1 || p[0].Fd != 9 || p[0].Events != unix.POLLIN || timeout != 0 {
			t.Fatal("unbounded poll")
		}
		return 0, nil
	}) {
		t.Fatal("live pidfd")
	}
	for _, event := range []int16{unix.POLLIN, unix.POLLHUP, unix.POLLERR, unix.POLLNVAL} {
		if nativeAliveUsing(9, func(p []unix.PollFd, _ int) (int, error) { p[0].Revents = event; return 1, nil }) {
			t.Fatal("dead/invalid peer")
		}
	}
	if nativeAliveUsing(-1, func([]unix.PollFd, int) (int, error) { t.Fatal("invalid fd polled"); return 0, nil }) {
		t.Fatal("invalid pin")
	}
}
func TestPeerPIDFDHasNoFallbackAndEnablesCredentialsFirst(t *testing.T) {
	for _, unsupported := range []bool{false, true} {
		order := []string{}
		closed := 0
		p := peerProbe{
			set: func(_ int, level, opt, value int) error {
				if level == unix.SOL_SOCKET && opt == unix.SO_PASSPIDFD && value == 0 {
					order = append(order, "no-passpidfd")
					return nil
				}
				if level != unix.SOL_SOCKET || opt != unix.SO_PASSCRED || value != 1 {
					t.Fatal("credential option")
				}
				order = append(order, "passcred")
				return nil
			},
			credentials: func(_ int, level, opt int) (*unix.Ucred, error) {
				if level != unix.SOL_SOCKET || opt != unix.SO_PEERCRED {
					t.Fatal("credential source")
				}
				order = append(order, "peercred")
				return &unix.Ucred{Pid: 100, Uid: 1200, Gid: 1200}, nil
			},
			option: func(_ int, level, opt int) (int, error) {
				if level != unix.SOL_SOCKET || opt != unix.SO_PEERPIDFD {
					t.Fatal("pid fallback")
				}
				order = append(order, "peerpidfd")
				if unsupported {
					return 0, unix.ENOPROTOOPT
				}
				return 9, nil
			},
			cloexec: func(fd int) {
				if fd != 9 {
					t.Fatal("pin")
				}
				order = append(order, "cloexec")
			},
			close: func(int) error { closed++; return nil },
		}
		cred, pin, e := connectionPeer(3, fixturePolicy(), p)
		if unsupported {
			if e == nil || pin != -1 || strings.Join(order, ",") != "no-passpidfd,passcred,peercred,peerpidfd" {
				t.Fatal("unsupported adopted")
			}
		} else {
			if e != nil || cred.Pid != 100 || pin != 9 || strings.Join(order, ",") != "no-passpidfd,passcred,peercred,peerpidfd,cloexec" {
				t.Fatal("peer proof", e)
			}
		}
		if closed != 0 {
			t.Fatal("unexpected close")
		}
	}
}

func TestUnexpectedSCMPIDFDIsClosedAndRejected(t *testing.T) {
	for _, descriptor := range []int32{55, -1, -22} {
		b := make([]byte, unix.CmsgSpace(4))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
		h.Level = unix.SOL_SOCKET
		h.Type = unix.SCM_PIDFD
		h.SetLen(unix.CmsgLen(4))
		binary.NativeEndian.PutUint32(b[unix.CmsgLen(0):], uint32(descriptor))
		closed := []int{}
		_, e := recvCredentials(b, 0, 1, unix.Ucred{}, func(fd int) error { closed = append(closed, fd); return nil })
		if e == nil || descriptor >= 0 && (len(closed) != 1 || closed[0] != int(descriptor)) || descriptor < 0 && len(closed) != 0 {
			t.Fatal("pidfd cleanup", descriptor, closed)
		}
	}
	p := fixtureListenerProbe()
	orig := p.option
	p.option = func(fd, l, o int) (int, error) {
		if o == unix.SO_PASSPIDFD {
			return 1, nil
		}
		return orig(fd, l, o)
	}
	if _, e := inspectListenerUsing(3, fixturePolicy(), p); e == nil {
		t.Fatal("unexpected inherited SO_PASSPIDFD")
	}
}

func TestPIDFDOptionErrorNeverOwnsNumericResult(t *testing.T) {
	for _, result := range []int{0, 7, -1} {
		for _, optionErr := range []error{unix.ENOPROTOOPT, unix.EINVAL, unix.EPERM} {
			closed, marked := 0, 0
			p := peerProbe{
				set:         func(int, int, int, int) error { return nil },
				credentials: func(int, int, int) (*unix.Ucred, error) { return &unix.Ucred{Pid: 100, Uid: 1200, Gid: 1200}, nil },
				option:      func(int, int, int) (int, error) { return result, optionErr },
				cloexec:     func(int) { marked++ }, close: func(int) error { closed++; return nil },
			}
			if _, fd, e := connectionPeer(3, fixturePolicy(), p); e == nil || fd != -1 || closed != 0 || marked != 0 {
				t.Fatal("error result treated as owned descriptor", result, optionErr)
			}
		}
	}
}

func TestNativeGroupsAllowOnlyBoundPrimaryOnce(t *testing.T) {
	for _, gid := range []uint32{1200, 1201} {
		for _, groups := range []string{"", fmt.Sprint(gid)} {
			raw := bytes.Replace(fixtureStatus(gid, gid, 0), []byte("Groups:\t"), []byte("Groups:\t"+groups), 1)
			identity, err := parseNativeStatus(raw)
			if err != nil || validateNativeIdentity(identity, gid, gid, 0) != nil {
				t.Fatal("bound primary rejected", gid, groups, err)
			}
		}
		for _, groups := range []string{"500", fmt.Sprintf("%d %d", gid, gid), fmt.Sprintf("%d 500", gid), fmt.Sprintf("500 %d", gid), "0", "4294967295", "4294967296", "-1", "group"} {
			raw := bytes.Replace(fixtureStatus(gid, gid, 0), []byte("Groups:\t"), []byte("Groups:\t"+groups), 1)
			if _, err := parseNativeStatus(raw); err == nil {
				t.Fatal("parser admitted group", gid, groups)
			}
		}
		good, _ := parseNativeStatus(fixtureStatus(gid, gid, 0))
		for _, groups := range [][]uint32{{500}, {gid, gid}, {gid, 500}, {0}, {^uint32(0)}} {
			bad := good
			bad.Groups = groups
			if validateNativeIdentity(bad, gid, gid, 0) == nil {
				t.Fatal("native identity admitted group", groups)
			}
		}
		// This is the exact helper used by the current-thread Getgroups checkpoint.
		for _, tc := range []struct {
			groups  []int
			allowed bool
		}{{nil, true}, {[]int{int(gid)}, true}, {[]int{-1}, false}, {[]int{0}, false}, {[]int{500}, false}, {[]int{int(gid), int(gid)}, false}, {[]int{int(gid), 500}, false}} {
			if primaryOnlyGroups(tc.groups, gid) != tc.allowed {
				t.Fatal("syscall group policy", tc.groups)
			}
		}
	}
}
