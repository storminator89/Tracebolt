package journalhelper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/journalview"
)

type fixtureProvider struct {
	raw    string
	closed *atomic.Bool
}

func (p fixtureProvider) Open(context.Context, journalview.Query) (io.ReadCloser, journalview.Reason, error) {
	return fixtureReader{Reader: strings.NewReader(p.raw), closed: p.closed}, journalview.ReasonNone, nil
}

type fixtureReader struct {
	*strings.Reader
	closed *atomic.Bool
}

func (r fixtureReader) Close() error {
	if r.closed != nil {
		r.closed.Store(true)
	}
	return nil
}
func fixtureDependencies() Dependencies {
	return Dependencies{Load: func() (State, error) { return fixtureState(), nil }, Identity: func() (Identity, error) { return fixtureIdentity(), nil }, Peer: func(net.Conn) (Peer, error) { return fixturePeer(), nil }, Now: func() time.Time { return sampleRequest().Query.End.Add(time.Minute) }, Capture: func(ctx context.Context, q journalview.Query, now time.Time) (journalview.Snapshot, error) {
		return journalview.CollectWithProvider(ctx, q, now, fixtureProvider{raw: `{"__REALTIME_TIMESTAMP":"1791115230000000","_SYSTEMD_UNIT":"demo.service","PRIORITY":"4","MESSAGE":"synthetic safe message"}` + "\n"})
	}}
}
func exchange(t *testing.T, s *Server, ctx context.Context, request Request) (Response, error) {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { s.ServeConn(ctx, a); close(done) }()
	defer func() {
		b.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("handler did not finish")
		}
	}()
	b.SetDeadline(time.Now().Add(2 * time.Second))
	encoded, e := EncodeRequest(request)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Write(encoded); e != nil {
		return Response{}, e
	}
	return ReadResponse(b)
}
func TestCaptureAndVerifyUseEncodedSnapshotOnly(t *testing.T) {
	d := fixtureDependencies()
	var calls atomic.Int32
	original := d.Capture
	d.Capture = func(ctx context.Context, q journalview.Query, n time.Time) (journalview.Snapshot, error) {
		calls.Add(1)
		return original(ctx, q, n)
	}
	s, _ := New(d)
	r, e := exchange(t, s, context.Background(), sampleRequest())
	if e != nil || r.Status != StatusSnapshot {
		t.Fatalf("capture: %v status %v", e, r.Status)
	}
	var snapshot journalview.Snapshot
	if json.Unmarshal(r.Body(), &snapshot) != nil {
		t.Fatal("not snapshot JSON")
	}
	encoded, e := journalview.Encode(snapshot)
	if e != nil || !bytes.Equal(encoded, r.Body()) || len(snapshot.Rows) != 1 {
		t.Fatal("not canonical source output")
	}
	q := sampleRequest()
	q.Operation = VerifyOperation
	q.PolicyDigest = r.PolicyDigest
	q.Revision = r.Revision
	verify, e := exchange(t, s, context.Background(), q)
	if e != nil || verify.Status != StatusVerified || len(verify.Body()) != 0 || calls.Load() != 1 {
		t.Fatal("verify collected or leaked content")
	}
	q.PolicyDigest = "sha256:" + strings.Repeat("e", 64)
	verify, e = exchange(t, s, context.Background(), q)
	if e != nil || verify.Status != StatusDenied || calls.Load() != 1 {
		t.Fatal("stale verify accepted")
	}
}
func TestAllDenialsPrecedeCapture(t *testing.T) {
	for name, edit := range map[string]func(*Dependencies, *Request){
		"missing-policy": func(d *Dependencies, r *Request) {
			d.Load = func() (State, error) { return State{}, errors.New("PRIVATE RAW ERROR") }
		},
		"disabled": func(d *Dependencies, r *Request) {
			d.Load = func() (State, error) { s := fixtureState(); s.Policy.Enabled = false; return s, nil }
		},
		"root": func(d *Dependencies, r *Request) {
			d.Identity = func() (Identity, error) { i := fixtureIdentity(); i.EffectiveUID = 0; return i, nil }
		},
		"extra-group": func(d *Dependencies, r *Request) {
			d.Identity = func() (Identity, error) { i := fixtureIdentity(); i.Groups = append(i.Groups, 4); return i, nil }
		},
		"peer-error": func(d *Dependencies, r *Request) {
			d.Peer = func(net.Conn) (Peer, error) { return Peer{}, errors.New("PRIVATE PEER ERROR") }
		},
		"wrong-peer": func(d *Dependencies, r *Request) {
			d.Peer = func(net.Conn) (Peer, error) { p := fixturePeer(); p.UID++; return p, nil }
		},
		"wrong-binding": func(d *Dependencies, r *Request) { r.SenderBinding = strings.Repeat("b", 64) },
		"wrong-unit":    func(d *Dependencies, r *Request) { r.Query.Unit = "other.service" },
		"severity":      func(d *Dependencies, r *Request) { r.Query.MaxPriority = 7 },
		"future": func(d *Dependencies, r *Request) {
			r.Query.Start = r.Query.Start.Add(time.Hour)
			r.Query.End = r.Query.End.Add(time.Hour)
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := fixtureDependencies()
			var calls atomic.Int32
			d.Capture = func(context.Context, journalview.Query, time.Time) (journalview.Snapshot, error) {
				calls.Add(1)
				return journalview.Snapshot{}, nil
			}
			q := sampleRequest()
			edit(&d, &q)
			s, _ := New(d)
			// A peer rejection can happen before writing the request. Send concurrently
			// so the test exercises a fixed rejection frame without requiring a half-close.
			a, b := net.Pipe()
			defer b.Close()
			done := make(chan struct{})
			go func() { s.ServeConn(context.Background(), a); close(done) }()
			encoded, _ := EncodeRequest(q)
			written := make(chan struct{})
			go func() { b.Write(encoded); close(written) }()
			b.SetDeadline(time.Now().Add(time.Second))
			r, e := ReadResponse(b)
			b.Close()
			<-done
			<-written
			if e != nil || r.Status != StatusDenied || len(r.Body()) != 0 || calls.Load() != 0 {
				t.Fatalf("denial: %v status %v captures %v", e, r.Status, calls.Load())
			}
		})
	}
}
func TestRevocationBeforeReleaseSuppressesContent(t *testing.T) {
	for _, change := range []func(*State){func(s *State) { s.Policy.Enabled = false }, func(s *State) { s.Policy.MaxPriority = 3 }, func(s *State) { s.Revision = "sha256:" + strings.Repeat("e", 64) }} {
		d := fixtureDependencies()
		var reads atomic.Int32
		d.Load = func() (State, error) {
			s := fixtureState()
			if reads.Add(1) > 1 {
				change(&s)
			}
			return s, nil
		}
		srv, _ := New(d)
		r, e := exchange(t, srv, context.Background(), sampleRequest())
		if e != nil || r.Status != StatusDenied || len(r.Body()) != 0 {
			t.Fatal("revoked content released")
		}
	}
	d := fixtureDependencies()
	var reads atomic.Int32
	d.Load = func() (State, error) {
		if reads.Add(1) > 1 {
			return State{}, ErrRejected
		}
		return fixtureState(), nil
	}
	s, _ := New(d)
	r, e := exchange(t, s, context.Background(), sampleRequest())
	if e != nil || r.Status != StatusDenied {
		t.Fatal("missing policy at release accepted")
	}
}
func TestCancellationWaitsForSynchronousCleanupAndKeepsCaptureSlot(t *testing.T) {
	d := fixtureDependencies()
	entered := make(chan struct{})
	cancelSeen := make(chan struct{})
	cleanup := make(chan struct{})
	var calls atomic.Int32
	d.Capture = func(ctx context.Context, q journalview.Query, n time.Time) (journalview.Snapshot, error) {
		calls.Add(1)
		close(entered)
		<-ctx.Done()
		close(cancelSeen)
		<-cleanup
		return journalview.Snapshot{}, ctx.Err()
	}
	s, _ := New(d)
	ctx, cancel := context.WithCancel(context.Background())
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { s.ServeConn(ctx, a); close(done) }()
	wire, _ := EncodeRequest(sampleRequest())
	b.Write(wire)
	<-entered
	cancel()
	<-cancelSeen
	select {
	case <-done:
		t.Fatal("abandoned cleanup")
	default:
	}
	copied := *s
	r, e := exchange(t, &copied, context.Background(), sampleRequest())
	if e != nil || r.Status != StatusBusy || calls.Load() != 1 {
		t.Fatal("capture slot released before cleanup")
	}
	close(cleanup)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish")
	}
	b.Close()
}
func TestOnlyTwoConnectionsAreAdmitted(t *testing.T) {
	d := fixtureDependencies()
	var peers atomic.Int32
	d.Peer = func(net.Conn) (Peer, error) { peers.Add(1); return fixturePeer(), nil }
	s, _ := New(d)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	clients := []net.Conn{}
	for i := 0; i < 2; i++ {
		a, b := net.Pipe()
		clients = append(clients, b)
		wg.Go(func() { s.ServeConn(ctx, a) })
	}
	until := time.Now().Add(time.Second)
	for peers.Load() != 2 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if peers.Load() != 2 {
		t.Fatal("connections not admitted")
	}
	a, b := net.Pipe()
	s.ServeConn(ctx, a)
	b.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := b.Read(make([]byte, 1)); e == nil {
		t.Fatal("third connection admitted")
	}
	b.Close()
	if peers.Load() != 2 {
		t.Fatal("third peer processed")
	}
	cancel()
	for _, c := range clients {
		c.Close()
	}
	wg.Wait()
}
func TestDeadlineClosesBlockedReadAndNoCapture(t *testing.T) {
	d := fixtureDependencies()
	d.Capture = func(context.Context, journalview.Query, time.Time) (journalview.Snapshot, error) {
		t.Error("capture on partial request")
		return journalview.Snapshot{}, nil
	}
	s, _ := New(d)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	a, b := net.Pipe()
	defer b.Close()
	done := make(chan struct{})
	go func() { s.ServeConn(ctx, a); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("deadline did not stop read")
	}
}
func TestRevocationDuringResponseLeavesOnlyAnIncompleteDiscardedFrame(t *testing.T) {
	d := fixtureDependencies()
	var reads atomic.Int32
	d.Load = func() (State, error) {
		s := fixtureState()
		if reads.Add(1) >= 3 {
			s.Policy.Enabled = false
		}
		return s, nil
	}
	s, _ := New(d)
	r, e := exchange(t, s, context.Background(), sampleRequest())
	if e == nil || len(r.Body()) != 0 {
		t.Fatal("partial revoked frame accepted")
	}
}

func TestProviderCannotRelabelCaptureTime(t *testing.T) {
	d := fixtureDependencies()
	capture := d.Capture
	d.Capture = func(c context.Context, q journalview.Query, n time.Time) (journalview.Snapshot, error) {
		s, e := capture(c, q, n)
		s.ObservedAt = n.Add(time.Minute)
		return s, e
	}
	s, _ := New(d)
	r, e := exchange(t, s, context.Background(), sampleRequest())
	if e != nil || r.Status != StatusUnavailable || len(r.Body()) != 0 {
		t.Fatal("relabeled provider timestamp accepted")
	}
}

type memoryListener struct {
	incoming chan net.Conn
	done     chan struct{}
	once     sync.Once
}

func (l *memoryListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.incoming:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *memoryListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (*memoryListener) Addr() net.Addr { return memoryAddr{} }

type memoryAddr struct{}

func (memoryAddr) Network() string { return "fixture" }
func (memoryAddr) String() string  { return "inert-listener" }
func TestServeWaitsForCleanupAndClosesListener(t *testing.T) {
	d := fixtureDependencies()
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	cleanup := make(chan struct{})
	d.Capture = func(c context.Context, q journalview.Query, n time.Time) (journalview.Snapshot, error) {
		close(entered)
		<-c.Done()
		close(cancelled)
		<-cleanup
		return journalview.Snapshot{}, c.Err()
	}
	s, _ := New(d)
	l := &memoryListener{incoming: make(chan net.Conn), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- s.Serve(ctx, l) }()
	a, b := net.Pipe()
	l.incoming <- a
	wire, _ := EncodeRequest(sampleRequest())
	b.Write(wire)
	<-entered
	cancel()
	<-cancelled
	select {
	case <-result:
		t.Fatal("Serve abandoned source cleanup")
	default:
	}
	close(cleanup)
	select {
	case e := <-result:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve failed to join source")
	}
	b.Close()
	select {
	case <-l.done:
	default:
		t.Fatal("listener left open")
	}
}
func TestServeAcceptFailureAndZeroServerAreFixed(t *testing.T) {
	d := fixtureDependencies()
	s, _ := New(d)
	l := &memoryListener{incoming: make(chan net.Conn), done: make(chan struct{})}
	l.Close()
	if e := s.Serve(context.Background(), l); e != ErrRejected {
		t.Fatal("accept error leaked or hidden")
	}
	var zero Server
	a, b := net.Pipe()
	zero.ServeConn(context.Background(), a)
	defer b.Close()
	if _, e := b.Read(make([]byte, 1)); e == nil {
		t.Fatal("zero server accepted")
	}
}
func TestOneConnectionNeverCapturesASecondQuery(t *testing.T) {
	d := fixtureDependencies()
	var calls atomic.Int32
	capture := d.Capture
	d.Capture = func(c context.Context, q journalview.Query, n time.Time) (journalview.Snapshot, error) {
		calls.Add(1)
		return capture(c, q, n)
	}
	s, _ := New(d)
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { s.ServeConn(context.Background(), a); close(done) }()
	wire, _ := EncodeRequest(sampleRequest())
	writes := make(chan error, 1)
	go func() { _, e := b.Write(append(wire, wire...)); writes <- e }()
	b.SetDeadline(time.Now().Add(time.Second))
	r, e := ReadResponse(b)
	if e != nil || r.Status != StatusSnapshot {
		t.Fatal("first frame failed")
	}
	<-done
	b.Close()
	<-writes
	if calls.Load() != 1 {
		t.Fatal("second query processed")
	}
}
