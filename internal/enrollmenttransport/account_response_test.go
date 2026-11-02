package enrollmenttransport

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A real HTTP server owns the normal response buffers. Only the socket's Write
// is controlled, so these tests detect a lease released before net/http flushes.
type accountSocketFixture struct {
	net.Conn
	entered       chan struct{}
	proceed       chan struct{}
	fail          bool
	failed        atomic.Bool
	payloadWrites atomic.Int32
	afterFailure  atomic.Int32
}

func (c *accountSocketFixture) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("!")) {
		c.payloadWrites.Add(1)
		if c.failed.Load() {
			c.afterFailure.Add(1)
		}
		c.entered <- struct{}{}
		<-c.proceed
		if c.fail && c.failed.CompareAndSwap(false, true) {
			return 0, errors.New("synthetic socket write failure")
		}
	}
	return c.Conn.Write(p)
}

type accountSocketListener struct {
	net.Listener
	socket chan *accountSocketFixture
	fail   bool
}

func (l *accountSocketListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	wrapped := &accountSocketFixture{Conn: c, entered: make(chan struct{}, 1), proceed: make(chan struct{}), fail: l.fail}
	l.socket <- wrapped
	return wrapped, nil
}
func TestAccountBoundJSONHoldsLeaseThroughActualSocketWrite(t *testing.T) {
	for _, size := range []int{17, 4097, 32771} {
		t.Run(stringSize(size), func(t *testing.T) { testAccountSocket(t, size, false) })
	}
}
func TestAccountBoundJSONWriteFailureAbortsWithoutLaterDelivery(t *testing.T) {
	for _, size := range []int{17, 32771} {
		t.Run(stringSize(size), func(t *testing.T) { testAccountSocket(t, size, true) })
	}
}
func stringSize(n int) string {
	if n == 17 {
		return "small-buffered"
	}
	if n == 4097 {
		return "buffer-boundary-tail"
	}
	return "large-tail"
}
func testAccountSocket(t *testing.T, size int, fail bool) {
	t.Helper()
	raw := []byte(`{"fixture":"` + strings.Repeat("!", size) + `"}`)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	wrapped := &accountSocketListener{Listener: listener, socket: make(chan *accountSocketFixture, 1), fail: fail}
	var lease sync.RWMutex
	handlerDone := make(chan struct{})
	server := &http.Server{ErrorLog: log.New(io.Discard, "", 0), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lease.RLock()
		defer close(handlerDone)
		defer lease.RUnlock()
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			panic(err)
		}
		writeAccountBoundJSON(w, raw, true)
	})}
	serverDone := make(chan struct{})
	go func() { _ = server.Serve(wrapped); close(serverDone) }()
	t.Cleanup(func() { _ = server.Close(); <-serverDone })
	client, e := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if e = client.SetDeadline(time.Now().Add(5 * time.Second)); e != nil {
		t.Fatal(e)
	}
	_, e = io.WriteString(client, "GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
	if e != nil {
		t.Fatal(e)
	}
	var socket *accountSocketFixture
	select {
	case socket = <-wrapped.socket:
	case <-time.After(5 * time.Second):
		t.Fatal("no accepted socket")
	}
	// Unblock on every failure path before closing the server.
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(socket.proceed) }) })
	type responseResult struct {
		body []byte
		err  error
	}
	responseDone := make(chan responseResult, 1)
	go func() {
		response, e := http.ReadResponse(bufio.NewReader(client), nil)
		if e != nil {
			responseDone <- responseResult{err: e}
			return
		}
		b, e := io.ReadAll(response.Body)
		_ = response.Body.Close()
		responseDone <- responseResult{b, e}
	}()
	writes := 0
	for {
		select {
		case <-socket.entered:
			writes++
			if lease.TryLock() {
				lease.Unlock()
				t.Fatal("actual socket delivery escaped account lease")
			}
			socket.proceed <- struct{}{}
		case result := <-responseDone:
			if writes == 0 {
				t.Fatal("no controlled payload write")
			}
			if fail {
				if result.err == nil {
					t.Fatal("failed socket delivery appeared successful")
				}
				if len(result.body) != 0 || socket.afterFailure.Load() != 0 {
					t.Fatal("payload delivered after failed write")
				}
			} else if result.err != nil || !bytes.Equal(result.body, raw) {
				t.Fatal("response lost buffered tail", result.err)
			}
			select {
			case <-handlerDone:
			case <-time.After(5 * time.Second):
				t.Fatal("handler did not release lease")
			}
			if !lease.TryLock() {
				t.Fatal("lease retained after handler exit")
			}
			lease.Unlock()
			return
		case <-time.After(5 * time.Second):
			t.Fatal("socket write or handler stuck")
		}
	}
}

// A wrapper can fail without net/http's internal bufio.Writer seeing an error.
// In that case abort cleanup must not flush its buffered payload after release.
type accountErrorWrapper struct {
	http.ResponseWriter
	mode    string
	lease   *sync.RWMutex
	expired chan bool
}

func (w *accountErrorWrapper) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *accountErrorWrapper) Write(p []byte) (int, error) {
	n, e := w.ResponseWriter.Write(p)
	if e != nil {
		return n, e
	}
	if w.mode == "write" {
		return n, errors.New("synthetic wrapper write failure")
	}
	if w.mode == "short" {
		return n - 1, nil
	}
	return n, nil
}
func (w *accountErrorWrapper) FlushError() error {
	return errors.New("synthetic wrapper flush failure")
}
func (w *accountErrorWrapper) SetWriteDeadline(at time.Time) error {
	held := !w.lease.TryLock()
	if !held {
		w.lease.Unlock()
	}
	w.expired <- held && !at.After(time.Now())
	return http.NewResponseController(w.ResponseWriter).SetWriteDeadline(at)
}
func TestAccountBoundJSONWrapperErrorsExpireDeadlineBeforeReleasingLease(t *testing.T) {
	for _, mode := range []string{"write", "short", "flush"} {
		t.Run(mode, func(t *testing.T) {
			var lease sync.RWMutex
			expired := make(chan bool, 1)
			done := make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				lease.RLock()
				defer close(done)
				defer lease.RUnlock()
				if e := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second)); e != nil {
					panic(e)
				}
				writeAccountBoundJSON(&accountErrorWrapper{w, mode, &lease, expired}, []byte(`{"fixture":"!!!!"}`), true)
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.Start()
			defer server.Close()
			client := server.Client()
			client.Timeout = 5 * time.Second
			response, e := client.Get(server.URL)
			if response != nil {
				defer response.Body.Close()
				b, _ := io.ReadAll(response.Body)
				if len(b) > 0 {
					t.Fatal("aborted wrapper delivered buffered payload")
				}
			}
			if e == nil {
				t.Fatal("wrapper failure did not abort HTTP response")
			}
			select {
			case ok := <-expired:
				if !ok {
					t.Fatal("write deadline was not expired under lease")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("abort did not expire deadline")
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("handler did not finish")
			}
			if !lease.TryLock() {
				t.Fatal("lease leaked after abort")
			}
			lease.Unlock()
		})
	}
}

func TestAccountBoundJSONRejectsLiveHTTP2WithoutChangingStaticResponse(t *testing.T) {
	raw := []byte(`{"permit":"fixture-only"}`)
	for _, live := range []bool{true, false} {
		r := httptest.NewRequest(http.MethodGet, "http://fixture/", nil)
		r.ProtoMajor = 2
		r.ProtoMinor = 0
		r.Proto = "HTTP/2.0"
		w := httptest.NewRecorder()
		writeAccountBoundJSONResponse(w, r, raw, live)
		if live {
			if w.Code != http.StatusServiceUnavailable || bytes.Contains(w.Body.Bytes(), raw) {
				t.Fatal("live HTTP/2 exposed permit")
			}
		} else if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), raw) {
			t.Fatal("static HTTP/2 response changed")
		}
	}
}

type accountNoFlusher struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *accountNoFlusher) Header() http.Header         { return w.header }
func (w *accountNoFlusher) WriteHeader(code int)        { w.status = code }
func (w *accountNoFlusher) Write(p []byte) (int, error) { return w.body.Write(p) }

type accountUnwrapWriter struct{ http.ResponseWriter }

func (w accountUnwrapWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func TestAccountBoundJSONRequiresFlushBeforePermitWrite(t *testing.T) {
	raw := []byte(`{"permit":"fixture-only"}`)
	w := &accountNoFlusher{header: make(http.Header)}
	writeAccountBoundJSON(w, raw, true)
	if w.status != http.StatusServiceUnavailable || bytes.Contains(w.body.Bytes(), raw) {
		t.Fatal("unsupported writer received permit")
	}
	supported := httptest.NewRecorder()
	writeAccountBoundJSON(accountUnwrapWriter{supported}, raw, true)
	if supported.Code != http.StatusOK || !supported.Flushed || !bytes.Equal(supported.Body.Bytes(), raw) {
		t.Fatal("supported unwrap chain did not flush")
	}
}
