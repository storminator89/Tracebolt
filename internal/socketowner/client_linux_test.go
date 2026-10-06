//go:build linux

package socketowner

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func clientControl(kind int, data []byte) []byte {
	b := make([]byte, unix.CmsgSpace(len(data)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.SOL_SOCKET
	h.Type = int32(kind)
	h.SetLen(unix.CmsgLen(len(data)))
	copy(b[unix.CmsgLen(0):], data)
	return b
}
func clientPIDFD(fd int32) []byte {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], uint32(fd))
	return clientControl(unix.SCM_PIDFD, b[:])
}
func clientWriter() unix.Ucred { return unix.Ucred{Pid: 101, Uid: 1201, Gid: 1201} }
func clientPair(fd int32) []byte {
	cred := clientWriter()
	return append(unix.UnixCredentials(&cred), clientPIDFD(fd)...)
}

type fixtureClientMessages struct {
	fixtureMessages
	halfClosed bool
}

func (s *fixtureClientMessages) CloseWrite() error { s.halfClosed = true; return nil }
func clientReaderFixture(messages []fixtureMessage) (*nativeClientConnection, *fixtureClientMessages, *[]int) {
	socket := &fixtureClientMessages{fixtureMessages: fixtureMessages{input: messages}}
	closed := []int{}
	conn := &nativeClientConnection{socket: socket, uid: 1201, gid: 1201, pin: -1, alive: func(int) bool { return true }, closeFD: func(fd int) error { closed = append(closed, fd); return nil }, checkPath: func() error { return nil }}
	return conn, socket, &closed
}
func TestClientSocketOptionsRequireActualWriterPIDFD(t *testing.T) {
	expected := map[int]int{unix.SO_DOMAIN: unix.AF_UNIX, unix.SO_TYPE: unix.SOCK_STREAM, unix.SO_ACCEPTCONN: 0, unix.SO_PASSCRED: 1, unix.SO_PASSPIDFD: 1}
	for _, bad := range []int{-1, unix.SO_DOMAIN, unix.SO_TYPE, unix.SO_ACCEPTCONN, unix.SO_PASSCRED, unix.SO_PASSPIDFD} {
		sets := []int{}
		p := clientSocketProbe{set: func(fd, level, opt, v int) error {
			if fd != 7 || level != unix.SOL_SOCKET || v != 1 {
				t.Fatal("setter")
			}
			sets = append(sets, opt)
			return nil
		}, get: func(fd, level, opt int) (int, error) {
			if len(sets) != 2 {
				t.Fatal("receive options not set first")
			}
			if opt == bad {
				return expected[opt] + 1, nil
			}
			v, ok := expected[opt]
			if !ok {
				t.Fatal("unexpected fallback option")
			}
			return v, nil
		}}
		err := prepareClientSocket(7, p)
		if (err == nil) != (bad == -1) || !reflect.DeepEqual(sets, []int{unix.SO_PASSCRED, unix.SO_PASSPIDFD}) {
			t.Fatal("option validation", bad, err)
		}
	}
	for _, fail := range []int{unix.SO_PASSCRED, unix.SO_PASSPIDFD} {
		p := clientSocketProbe{set: func(_, _, opt, _ int) error {
			if opt == fail {
				return unix.ENOPROTOOPT
			}
			return nil
		}, get: func(int, int, int) (int, error) { t.Fatal("fallback after unsupported option"); return 0, nil }}
		if prepareClientSocket(7, p) == nil {
			t.Fatal("unsupported profile admitted")
		}
	}
}
func TestResponseAncillaryRejectsAndClosesEveryReceivedFD(t *testing.T) {
	cred := clientWriter()
	valid := unix.UnixCredentials(&cred)
	wrong := cred
	wrong.Uid++
	negative := clientPIDFD(-int32(unix.EINVAL))
	extra := append([]byte{9, 0, 0, 0}, 1)
	controls := []struct {
		name   string
		oob    []byte
		flags  int
		closed []int
	}{
		{"missing both", nil, 0, nil},
		{"missing pidfd", valid, 0, nil},
		{"missing credentials", clientPIDFD(9), 0, []int{9}},
		{"wrong uid", append(unix.UnixCredentials(&wrong), clientPIDFD(9)...), 0, []int{9}},
		{"negative pidfd", append(append([]byte{}, valid...), negative...), 0, nil},
		{"duplicate pidfd", append(clientPair(9), clientPIDFD(10)...), 0, []int{9, 10}},
		{"duplicate credentials", append(clientPair(9), valid...), 0, []int{9}},
		{"rights", append(clientPair(9), unix.UnixRights(10, 11)...), 0, []int{9, 10, 11}},
		{"rights malformed tail", append(unix.UnixRights(10, 11), 1, 2, 3), 0, []int{10, 11}},
		{"unknown", append(clientPair(9), clientControl(999, []byte{0})...), 0, []int{9}},
		{"pidfd malformed tail", append(clientPair(9), 1, 2, 3), 0, []int{9}},
		{"oversize pidfd", append(append([]byte{}, valid...), clientControl(unix.SCM_PIDFD, extra)...), 0, []int{9}},
		{"ctrunc", clientPair(9), unix.MSG_CTRUNC, []int{9}},
		{"trunc", clientPair(9), unix.MSG_TRUNC, []int{9}},
	}
	for _, tc := range controls {
		t.Run(tc.name, func(t *testing.T) {
			var closed []int
			_, fd, err := responseAncillary(tc.oob, tc.flags, 1, 1201, 1201, func(fd int) error { closed = append(closed, fd); return nil })
			if err == nil || fd != -1 || !reflect.DeepEqual(closed, tc.closed) {
				t.Fatal("admitted or leaked", fd, err, closed)
			}
		})
	}
	for _, size := range []int{0, 1, 3, 5, 7, 8} {
		data := bytes.Repeat([]byte{0}, size)
		closed := 0
		_, _, err := responseAncillary(append(append([]byte{}, valid...), clientControl(unix.SCM_PIDFD, data)...), 0, 1, 1201, 1201, func(int) error { closed++; return nil })
		if err == nil || closed != size/4 {
			t.Fatal("invalid pidfd length", size, closed)
		}
	}
	for _, size := range []int{0, 1, unix.SizeofUcred - 1, unix.SizeofUcred + 1} {
		closed := 0
		_, _, err := responseAncillary(append(clientControl(unix.SCM_CREDENTIALS, make([]byte, size)), clientPIDFD(9)...), 0, 1, 1201, 1201, func(int) error { closed++; return nil })
		if err == nil || closed != 1 {
			t.Fatal("invalid credential length", size, closed)
		}
	}
	for _, empty := range [][]byte{nil, unix.UnixCredentials(&unix.Ucred{})} {
		if _, fd, err := responseAncillary(empty, 0, 0, 1201, 1201, func(int) error { t.Fatal("EOF fd"); return nil }); err != nil || fd != -1 {
			t.Fatal("EOF sentinel", err)
		}
	}
	closed := 0
	if _, _, err := responseAncillary(clientPair(9), 0, 0, 1201, 1201, func(int) error { closed++; return nil }); err == nil || closed != 1 {
		t.Fatal("data pin at EOF")
	}
}
func TestClientRetainsFirstWriterPinThroughAcceptance(t *testing.T) {
	response := fixtureClientResponse(true)
	raw, err := EncodeResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	conn, socket, closed := clientReaderFixture([]fixtureMessage{{data: raw[:8], oob: clientPair(10)}, {data: raw[8:], oob: clientPair(11)}})
	checks := []int{}
	conn.alive = func(fd int) bool {
		checks = append(checks, fd)
		for _, dead := range *closed {
			if dead == fd {
				t.Fatal("closed pin used", fd)
			}
		}
		return true
	}
	c, _ := fixtureClient(t, response)
	c.connect = func(context.Context, Policy) (clientConnection, error) { return conn, nil }
	got, err := c.Capture(context.Background(), fixturePolicy(), response.Observation.GenerationID, fixtureClientReference())
	if err != nil || got.GenerationID != response.Observation.GenerationID || !socket.halfClosed || !reflect.DeepEqual(*closed, []int{11, 10}) || len(checks) < 8 {
		t.Fatal("pin lifetime", err, *closed, checks)
	}
	request, err := ReadRequest(bytes.NewReader(bytes.Join(socket.output, nil)))
	if err != nil || request.Operation != CaptureOperation {
		t.Fatal("native fake request", err)
	}
	for _, oob := range socket.credentials {
		if len(oob) != 0 {
			t.Fatal("client passed fd")
		}
	}
	conn.Close()
	if !reflect.DeepEqual(*closed, []int{11, 10}) {
		t.Fatal("pin closed twice")
	}
}
func TestClientRejectsChangingWriterAndClosesPins(t *testing.T) {
	for name, change := range map[string]func(*unix.Ucred){"pid": func(c *unix.Ucred) { c.Pid++ }, "uid": func(c *unix.Ucred) { c.Uid++ }, "gid": func(c *unix.Ucred) { c.Gid++ }, "zero pid": func(c *unix.Ucred) { c.Pid = 0 }} {
		t.Run(name, func(t *testing.T) {
			cred := clientWriter()
			change(&cred)
			other := append(unix.UnixCredentials(&cred), clientPIDFD(11)...)
			conn, _, closed := clientReaderFixture([]fixtureMessage{{data: []byte("x"), oob: clientPair(10)}, {data: []byte("y"), oob: other}})
			var b [1]byte
			if _, err := conn.Read(b[:]); err != nil {
				t.Fatal(err)
			}
			if n, err := conn.Read(b[:]); n != 0 || err == nil || b[0] != 0 {
				t.Fatal("foreign writer exposed")
			}
			conn.Close()
			if !reflect.DeepEqual(*closed, []int{11, 10}) {
				t.Fatal("leaked", *closed)
			}
		})
	}
	for _, message := range []fixtureMessage{{data: []byte("x"), oob: clientPair(10), err: errors.New("injected")}, {data: []byte("x"), oob: clientPair(10), flags: unix.MSG_CTRUNC}} {
		conn, _, closed := clientReaderFixture([]fixtureMessage{message})
		var b [1]byte
		if n, err := conn.Read(b[:]); n != 0 || err == nil {
			t.Fatal("error bytes accepted")
		}
		conn.Close()
		if !reflect.DeepEqual(*closed, []int{10}) {
			t.Fatal("error pin leaked", *closed)
		}
	}
}
func TestClientWriterMustRemainAliveBeforeAndAfterBytes(t *testing.T) {
	// Calls cover before first acceptance, after first acceptance, before another
	// recv, candidate pin, original pin, and post-acceptance original pin.
	for fail := 1; fail <= 6; fail++ {
		conn, _, closed := clientReaderFixture([]fixtureMessage{{data: []byte("x"), oob: clientPair(10)}, {data: []byte("y"), oob: clientPair(11)}})
		calls := 0
		conn.alive = func(int) bool { calls++; return calls != fail }
		var b [1]byte
		_, first := conn.Read(b[:])
		if first == nil {
			if n, err := conn.Read(b[:]); n != 0 || err == nil {
				t.Fatal("dead writer accepted", fail)
			}
		}
		conn.Close()
		if conn.pin != -1 || len(*closed) == 0 {
			t.Fatal("dead pin leaked", fail)
		}
	}
	conn, _, _ := clientReaderFixture([]fixtureMessage{{data: []byte("x"), oob: clientPair(10)}})
	var b [1]byte
	if _, err := conn.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	conn.checkPath = func() error { return ErrChanged }
	if conn.Check() == nil {
		t.Fatal("path replaced")
	}
	conn.Close()
	empty, _, _ := clientReaderFixture(nil)
	if _, err := empty.Read(b[:]); err == nil || err == io.EOF {
		t.Fatal("unauthenticated EOF")
	}
	empty.Close()
}

// This fake blocks only on channels. Cancellation exercises descriptor cleanup
// without creating a socket, reading procfs or executing the native entrypoint.
type blockingClientMessages struct {
	fixtureClientMessages
	entered  chan struct{}
	released chan struct{}
	once     sync.Once
	reads    int
}

func (s *blockingClientMessages) ReadMsgUnix(p, oob []byte) (int, int, int, *net.UnixAddr, error) {
	s.reads++
	if s.reads == 1 {
		return s.fixtureClientMessages.ReadMsgUnix(p, oob)
	}
	close(s.entered)
	<-s.released
	return 0, 0, 0, nil, io.ErrClosedPipe
}
func (s *blockingClientMessages) Close() error { s.once.Do(func() { close(s.released) }); return nil }
func TestClientCancellationWaitsForFirstPinCleanup(t *testing.T) {
	response := fixtureClientResponse(false)
	raw, err := EncodeResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	socket := &blockingClientMessages{fixtureClientMessages: fixtureClientMessages{fixtureMessages: fixtureMessages{input: []fixtureMessage{{data: raw[:8], oob: clientPair(10)}}}}, entered: make(chan struct{}), released: make(chan struct{})}
	closed := []int{}
	conn := &nativeClientConnection{socket: socket, uid: 1201, gid: 1201, pin: -1, alive: func(int) bool { return true }, closeFD: func(fd int) error { closed = append(closed, fd); return nil }, checkPath: func() error { return nil }}
	c, _ := fixtureClient(t, response)
	c.connect = func(context.Context, Policy) (clientConnection, error) { return conn, nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.Verify(ctx, fixturePolicy(), nil); done <- err }()
	select {
	case <-socket.entered:
	case <-time.After(time.Second):
		t.Fatal("fake read never entered")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled response accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation failed to join cleanup")
	}
	if !reflect.DeepEqual(closed, []int{10}) || conn.pin != -1 || !conn.closed {
		t.Fatal("first pin leaked", closed)
	}
}
