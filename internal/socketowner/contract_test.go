package socketowner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/systeminventory"
)

var fixtureTime = time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)

const fixtureGeneration = "sample_0123456789abcdef0123456789abcdef"

func fixturePolicy() Policy {
	return Policy{Version: PolicyVersion, Scope: Scope, SenderBinding: strings.Repeat("a", 64), ManagerOrigin: "https://manager.invalid", TransportProfile: "tls", CollectionProfile: "managed-operations-v3", AgentUID: 1200, AgentGID: 1200, HelperUID: 1201, HelperGID: 1201, Epoch: strings.Repeat("b", 64), Enabled: true, MetadataAcknowledged: true, PtraceRiskAcknowledged: true}
}
func fixtureFacts() Facts {
	n := NamespaceSet{PID: NamespaceID{1, 10}, Net: NamespaceID{1, 11}, User: NamespaceID{1, 12}}
	return Facts{OwnedDeploymentVerified: true, ProcViewVerified: true, SocketWitnessVerified: true, PeerUIDs: [3]uint32{1200, 1200, 1200}, PeerGIDs: [3]uint32{1200, 1200, 1200}, HelperUIDs: [3]uint32{1201, 1201, 1201}, HelperGIDs: [3]uint32{1201, 1201, 1201}, Capabilities: [5]uint64{PtraceCapability, PtraceCapability, PtraceCapability, PtraceCapability, PtraceCapability}, PeerUID: 1200, PeerGID: 1200, PeerPID: 100, WriterPID: 100, PeerPIDFDSupported: true, PeerAlive: true, WriterVerified: true, NamespaceTypesVerified: true, HelperNamespaces: n, PeerNamespaces: n, ManagerNamespaces: n, ProcPIDView: n.PID, RuntimeID: strings.Repeat("c", 64)}
}
func fixtureRequest(op string) Request {
	p := fixturePolicy()
	r := Request{Version: ProtocolVersion, Operation: op, SenderBinding: p.SenderBinding, GrantEpoch: p.Epoch, PolicyDigest: PolicyDigest(p)}
	if op == CaptureOperation {
		r.GenerationID = fixtureGeneration
	}
	return r
}
func fixtureRows(n int) []systeminventory.Socket {
	rows := make([]systeminventory.Socket, n)
	name := "PRIVATE_FIXTURE_PROCESS"
	for i := range rows {
		rows[i] = systeminventory.Socket{Protocol: "tcp", Family: "ipv4", Kind: "listener", Local: systeminventory.Endpoint{Address: "127.0.0.1", Port: uint16(1000 + i)}, Remote: systeminventory.Endpoint{Address: "0.0.0.0"}, State: "listen", Owners: []systeminventory.Owner{{PID: 10, ProcessName: &name, NameReason: systeminventory.ReasonNone}}, Attribution: systeminventory.Attribution{Coverage: systeminventory.AttributionObserved, Reason: systeminventory.ReasonNone}}
	}
	return rows
}

type fixtureConn struct {
	mu       sync.Mutex
	in       *bytes.Reader
	out      bytes.Buffer
	facts    Facts
	factsFn  func(context.Context) (Facts, error)
	closed   bool
	writes   int
	onWrite  func(int)
	deadline time.Time
}

func connection(r Request) *fixtureConn {
	b, e := EncodeRequest(r)
	if e != nil {
		panic(e)
	}
	return &fixtureConn{in: bytes.NewReader(b), facts: fixtureFacts()}
}
func (c *fixtureConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.in.Read(p)
}
func (c *fixtureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	n, e := c.out.Write(p)
	c.writes++
	w, fn := c.writes, c.onWrite
	c.mu.Unlock()
	if fn != nil {
		fn(w)
	}
	return n, e
}
func (c *fixtureConn) Close() error                  { c.mu.Lock(); defer c.mu.Unlock(); c.closed = true; return nil }
func (c *fixtureConn) SetDeadline(t time.Time) error { c.deadline = t; return nil }
func (c *fixtureConn) Facts(ctx context.Context) (Facts, error) {
	if c.factsFn != nil {
		return c.factsFn(ctx)
	}
	return c.facts, nil
}
func (c *fixtureConn) result() (Response, error) {
	c.mu.Lock()
	b := append([]byte(nil), c.out.Bytes()...)
	c.mu.Unlock()
	return ReadResponse(bytes.NewReader(b))
}

type fixtureServer struct {
	mu        sync.Mutex
	authority Authority
	now       time.Time
	tick      time.Duration
	calls     int
	capture   func(context.Context, string, time.Time, func() error) ([]systeminventory.Socket, error)
	server    *Server
}

func newFixture(t *testing.T) *fixtureServer {
	t.Helper()
	f := &fixtureServer{authority: Authority{Policy: fixturePolicy(), Revision: strings.Repeat("d", 64), ProtectedPolicyVerified: true, ProtectedGrantBindingVerified: true}, now: fixtureTime}
	s, e := New(Dependencies{Load: func() (Authority, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.authority, nil }, Now: func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }, Monotonic: func() time.Duration { f.mu.Lock(); defer f.mu.Unlock(); return f.tick }, Capture: func(ctx context.Context, id string, at time.Time, guard func() error) ([]systeminventory.Socket, error) {
		f.mu.Lock()
		f.calls++
		fn := f.capture
		f.mu.Unlock()
		if fn != nil {
			return fn(ctx, id, at, guard)
		}
		if err := guard(); err != nil {
			return nil, err
		}
		return fixtureRows(1), nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	f.server = s
	return f
}
func (f *fixtureServer) run(t *testing.T, r Request) Response {
	t.Helper()
	c := connection(r)
	f.server.ServeConn(context.Background(), c)
	v, e := c.result()
	if e != nil {
		t.Fatal(e)
	}
	return v
}

func TestPolicyAndIPCCanonicalShape(t *testing.T) {
	p := fixturePolicy()
	b, e := EncodePolicy(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodePolicy(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(b, []byte("{}")...), bytes.Replace(b, []byte(`"scope":`), []byte(`"pid":1,"scope":`), 1), bytes.Replace(b, []byte(`"enabled":true`), []byte(`"enabled":true,"enabled":true`), 1)} {
		if _, e := DecodePolicy(bad); e == nil {
			t.Fatal("ambiguous policy accepted")
		}
	}
	raw, _ := EncodeRequest(fixtureRequest(CaptureOperation))
	if _, e := ReadRequest(bytes.NewReader(raw)); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{raw[:len(raw)-1], append(append([]byte(nil), raw...), 1), append([]byte("BAD!"), raw[4:]...)} {
		if _, e := ReadRequest(bytes.NewReader(bad)); e == nil {
			t.Fatal("malformed frame accepted")
		}
	}
	for _, edit := range []func(*Request){func(r *Request) { r.Operation = "/bin/sh" }, func(r *Request) { r.GenerationID = "../../proc/1" }, func(r *Request) { r.SenderBinding = "" }, func(r *Request) { r.Reference = &Reference{} }, func(r *Request) { r.Version = "future" }} {
		r := fixtureRequest(CaptureOperation)
		edit(&r)
		if _, e := EncodeRequest(r); e == nil {
			t.Fatal("unsafe request admitted")
		}
	}
}

func TestCaptureAndVerifyPreserveAuthorityAndActualTime(t *testing.T) {
	f := newFixture(t)
	f.capture = func(ctx context.Context, id string, at time.Time, guard func() error) ([]systeminventory.Socket, error) {
		if id != fixtureGeneration || !at.Equal(fixtureTime) || guard() != nil {
			t.Fatal("caller chose source time/authority")
		}
		f.mu.Lock()
		f.now = f.now.Add(time.Second)
		f.mu.Unlock()
		return fixtureRows(1), nil
	}
	got := f.run(t, fixtureRequest(CaptureOperation))
	if got.Status != StatusCaptured || !got.Observation.StartedAt.Equal(fixtureTime) || !got.Observation.FinishedAt.Equal(fixtureTime.Add(time.Second)) {
		t.Fatalf("bad capture: %s", got.Status)
	}
	r := fixtureRequest(VerifyOperation)
	r.Reference = got.Reference
	if v := f.run(t, r); v.Status != StatusVerified || v.Observation != nil {
		t.Fatal("verification recaptured")
	}
	if f.calls != 1 {
		t.Fatal("verify read source")
	}
	for _, text := range []string{fmt.Sprintf("%v", got), fmt.Sprintf("%#v", got), fmt.Sprintf("%v", got.Observation)} {
		if strings.Contains(text, "PRIVATE_FIXTURE_PROCESS") {
			t.Fatal("formatting leaked rows")
		}
	}
}

func TestAuthorityAndPeerDenialsNeverCapture(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*fixtureServer, *fixtureConn)
	}{
		{"unverified policy", func(f *fixtureServer, c *fixtureConn) { f.authority.ProtectedPolicyVerified = false }},
		{"unverified protected grant binding", func(f *fixtureServer, c *fixtureConn) { f.authority.ProtectedGrantBindingVerified = false }},
		{"unverified deployment", func(f *fixtureServer, c *fixtureConn) { c.facts.OwnedDeploymentVerified = false }},
		{"unverified proc view", func(f *fixtureServer, c *fixtureConn) { c.facts.ProcViewVerified = false }},
		{"unverified socket witness", func(f *fixtureServer, c *fixtureConn) { c.facts.SocketWitnessVerified = false }},
		{"foreign helper supplementary group", func(f *fixtureServer, c *fixtureConn) { c.facts.Groups = []uint32{1200} }},
		{"peer saved uid mismatch", func(f *fixtureServer, c *fixtureConn) { c.facts.PeerUIDs[2]++ }},
		{"foreign peer supplementary group", func(f *fixtureServer, c *fixtureConn) { c.facts.PeerGroups = []uint32{1201} }},
		{"peer capability present", func(f *fixtureServer, c *fixtureConn) { c.facts.PeerCapabilities[4] = 1 }},
		{"disabled", func(f *fixtureServer, c *fixtureConn) { f.authority.Policy.Enabled = false }},
		{"risk not acknowledged", func(f *fixtureServer, c *fixtureConn) { f.authority.Policy.PtraceRiskAcknowledged = false }},
		{"wrong uid", func(f *fixtureServer, c *fixtureConn) { c.facts.PeerUID++ }},
		{"writer not verified", func(f *fixtureServer, c *fixtureConn) { c.facts.WriterVerified = false }},
		{"writer differs", func(f *fixtureServer, c *fixtureConn) { c.facts.WriterPID++ }},
		{"unsupported pidfd", func(f *fixtureServer, c *fixtureConn) { c.facts.PeerPIDFDSupported = false }},
		{"peer exited", func(f *fixtureServer, c *fixtureConn) { c.facts.PeerAlive = false }},
		{"extra cap", func(f *fixtureServer, c *fixtureConn) { c.facts.Capabilities[0] |= 1 }},
		{"root helper", func(f *fixtureServer, c *fixtureConn) { c.facts.HelperUIDs = [3]uint32{0, 0, 0} }},
		{"extra group", func(f *fixtureServer, c *fixtureConn) { c.facts.Groups = []uint32{1201, 500} }},
		{"foreign net", func(f *fixtureServer, c *fixtureConn) { c.facts.PeerNamespaces.Net.Inode++ }},
		{"foreign manager view", func(f *fixtureServer, c *fixtureConn) {
			c.facts.HelperNamespaces.Net.Inode++
			c.facts.PeerNamespaces.Net = c.facts.HelperNamespaces.Net
		}},
		{"wrong proc PID view", func(f *fixtureServer, c *fixtureConn) { c.facts.ProcPIDView.Inode++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			c := connection(fixtureRequest(CaptureOperation))
			tc.edit(f, c)
			f.server.ServeConn(context.Background(), c)
			got, e := c.result()
			if e != nil || got.Status != StatusDenied || f.calls != 0 {
				t.Fatalf("status=%s err=%v calls=%d", got.Status, e, f.calls)
			}
		})
	}
}

func TestRevocationAndRuntimeChangeInvalidateExactReference(t *testing.T) {
	for _, change := range []func(*fixtureServer, *fixtureConn){func(f *fixtureServer, c *fixtureConn) { f.authority.Policy.Enabled = false }, func(f *fixtureServer, c *fixtureConn) { f.authority.Policy.Epoch = strings.Repeat("e", 64) }, func(f *fixtureServer, c *fixtureConn) { f.authority.Revision = strings.Repeat("e", 64) }, func(f *fixtureServer, c *fixtureConn) { c.facts.RuntimeID = strings.Repeat("e", 64) }} {
		f := newFixture(t)
		first := f.run(t, fixtureRequest(CaptureOperation))
		r := fixtureRequest(VerifyOperation)
		r.Reference = first.Reference
		c := connection(r)
		change(f, c)
		f.server.ServeConn(context.Background(), c)
		got, e := c.result()
		if e != nil || got.Status != StatusDenied || f.calls != 1 {
			t.Fatal("old reference regained authority")
		}
	}
	f := newFixture(t)
	f.capture = func(ctx context.Context, id string, at time.Time, guard func() error) ([]systeminventory.Socket, error) {
		f.mu.Lock()
		f.authority.Policy.Enabled = false
		f.mu.Unlock()
		if guard() == nil {
			t.Fatal("guard missed withdrawal")
		}
		return fixtureRows(1), nil
	}
	if got := f.run(t, fixtureRequest(CaptureOperation)); got.Status != StatusDenied || got.Observation != nil {
		t.Fatal("revoked rows returned")
	}
}

func TestCaptureRateLimitConsumesFailedAttemptAndVerifyStaysAvailable(t *testing.T) {
	f := newFixture(t)
	f.capture = func(context.Context, string, time.Time, func() error) ([]systeminventory.Socket, error) {
		return nil, fmt.Errorf("PRIVATE_SOURCE_DIAGNOSTIC")
	}
	if got := f.run(t, fixtureRequest(CaptureOperation)); got.Status != StatusUnavailable {
		t.Fatal(got.Status)
	}
	if got := f.run(t, fixtureRequest(CaptureOperation)); got.Status != StatusRateLimited {
		t.Fatal(got.Status)
	}
	if got := f.run(t, fixtureRequest(VerifyOperation)); got.Status != StatusVerified {
		t.Fatal("verify throttled")
	}
	f.mu.Lock()
	f.tick = CaptureInterval
	f.capture = nil
	f.mu.Unlock()
	if got := f.run(t, fixtureRequest(CaptureOperation)); got.Status != StatusCaptured {
		t.Fatal("exact boundary denied")
	}
	f.mu.Lock()
	f.tick--
	f.mu.Unlock()
	if got := f.run(t, fixtureRequest(CaptureOperation)); got.Status != StatusUnavailable {
		t.Fatal("monotonic rollback admitted")
	}
}

func TestResponseLimitsInvalidRowsAndInterruptedFrame(t *testing.T) {
	for _, rows := range [][]systeminventory.Socket{nil, fixtureRows(systeminventory.MaxSocketRows + 1)} {
		f := newFixture(t)
		f.capture = func(context.Context, string, time.Time, func() error) ([]systeminventory.Socket, error) {
			return rows, nil
		}
		if got := f.run(t, fixtureRequest(CaptureOperation)); got.Status != StatusUnavailable {
			t.Fatal("invalid result accepted")
		}
	}
	f := newFixture(t)
	f.capture = func(context.Context, string, time.Time, func() error) ([]systeminventory.Socket, error) {
		return fixtureRows(200), nil
	}
	c := connection(fixtureRequest(CaptureOperation))
	c.onWrite = func(n int) {
		if n == 2 {
			f.mu.Lock()
			f.authority.Policy.Enabled = false
			f.mu.Unlock()
		}
	}
	f.server.ServeConn(context.Background(), c)
	if _, e := c.result(); e == nil {
		t.Fatal("partial revoked frame admitted")
	}
}

func TestConcurrentVerifyBusyAndCancellationKeepCaptureSlotUntilCleanup(t *testing.T) {
	f := newFixture(t)
	entered := make(chan struct{})
	cleanup := make(chan struct{})
	sourceCanceled := make(chan struct{})
	done := make(chan struct{})
	f.capture = func(ctx context.Context, _ string, _ time.Time, _ func() error) ([]systeminventory.Socket, error) {
		close(entered)
		<-ctx.Done()
		close(sourceCanceled)
		<-cleanup
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := connection(fixtureRequest(CaptureOperation))
	go func() { f.server.ServeConn(ctx, c); close(done) }()
	<-entered
	if got := f.run(t, fixtureRequest(VerifyOperation)); got.Status != StatusVerified {
		t.Fatal("verify unavailable during capture")
	}
	if got := f.run(t, fixtureRequest(CaptureOperation)); got.Status != StatusBusy {
		t.Fatal("second capture admitted")
	}
	cancel()
	<-sourceCanceled
	select {
	case <-done:
		t.Fatal("abandoned source cleanup")
	default:
	}
	if got := f.run(t, fixtureRequest(CaptureOperation)); got.Status != StatusBusy {
		t.Fatal("slot freed before cleanup")
	}
	close(cleanup)
	<-done
	// The fixed denial can beat context.AfterFunc's socket close. No captured
	// metadata may survive; source cleanup and admission ownership are unchanged.
	if response, e := c.result(); e == nil && (response.Status != StatusDenied || response.Reference != nil || response.Observation != nil) {
		t.Fatal("canceled capture produced metadata or a successful response")
	}
	if got := f.run(t, fixtureRequest(CaptureOperation)); got.Status != StatusRateLimited {
		t.Fatal("canceled attempt did not consume interval")
	}
}

func TestConnectionLimitIsSharedAndDoesNotQueue(t *testing.T) {
	f := newFixture(t)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	done := make(chan struct{}, 2)
	for i := 0; i < MaxConnections; i++ {
		c := connection(fixtureRequest(VerifyOperation))
		first := true
		c.factsFn = func(ctx context.Context) (Facts, error) {
			if first {
				first = false
				entered <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
					return Facts{}, ctx.Err()
				}
			}
			return fixtureFacts(), nil
		}
		go func() { f.server.ServeConn(context.Background(), c); done <- struct{}{} }()
	}
	<-entered
	<-entered
	c := connection(fixtureRequest(CaptureOperation))
	copyOfServer := *f.server
	copyOfServer.ServeConn(context.Background(), c)
	if _, e := c.result(); e == nil || !c.closed || f.calls != 0 {
		t.Fatal("excess connection queued/admitted")
	}
	close(release)
	<-done
	<-done
}

func TestRequestAmbiguityAndByteCeilingFailBeforeSource(t *testing.T) {
	good, _ := EncodeRequest(fixtureRequest(CaptureOperation))
	body := good[8:]
	for _, raw := range [][]byte{
		bytes.Replace(body, []byte(`"operation":`), []byte(`"pid":1,"operation":`), 1),
		bytes.Replace(body, []byte(`"operation":"capture"`), []byte(`"operation":"capture","operation":"capture"`), 1),
		bytes.Replace(body, []byte(`"reference":null`), []byte(`"reference":{"ContextID":"`+strings.Repeat("a", 64)+`"}`), 1),
		append(body, []byte("{}")...),
	} {
		wire, e := frame(raw, MaxRequestBytes)
		if e != nil {
			t.Fatal(e)
		}
		f := newFixture(t)
		c := connection(fixtureRequest(CaptureOperation))
		c.in = bytes.NewReader(wire)
		f.server.ServeConn(context.Background(), c)
		got, e := c.result()
		if e != nil || got.Status != StatusInvalid || f.calls != 0 {
			t.Fatal("malformed JSON reached source")
		}
	}
	if _, e := frame(make([]byte, MaxRequestBytes+1), MaxRequestBytes); e == nil {
		t.Fatal("request cap")
	}
	f := newFixture(t)
	f.capture = func(context.Context, string, time.Time, func() error) ([]systeminventory.Socket, error) {
		return fixtureRows(2000), nil
	}
	if got := f.run(t, fixtureRequest(CaptureOperation)); got.Status != StatusUnavailable {
		t.Fatal("oversized encoded socket section returned")
	}
}

func TestHelperClockFailureAndEmptyEnumerationStayDistinct(t *testing.T) {
	for _, duration := range []time.Duration{-time.Second, CaptureTimeout + time.Second} {
		f := newFixture(t)
		f.capture = func(context.Context, string, time.Time, func() error) ([]systeminventory.Socket, error) {
			f.mu.Lock()
			f.now = f.now.Add(duration)
			f.mu.Unlock()
			return fixtureRows(1), nil
		}
		if got := f.run(t, fixtureRequest(CaptureOperation)); got.Status != StatusUnavailable {
			t.Fatal("invalid source interval")
		}
	}
	f := newFixture(t)
	f.capture = func(context.Context, string, time.Time, func() error) ([]systeminventory.Socket, error) {
		return []systeminventory.Socket{}, nil
	}
	got := f.run(t, fixtureRequest(CaptureOperation))
	if got.Status != StatusCaptured || got.Observation.Sockets == nil || len(got.Observation.Sockets) != 0 {
		t.Fatal("valid empty enumeration misclassified")
	}
	f = newFixture(t)
	rows := fixtureRows(1)
	rows[0].Owners = []systeminventory.Owner{}
	rows[0].Attribution = systeminventory.Attribution{Coverage: systeminventory.AttributionPartial, Reason: systeminventory.ReasonPermissionDenied}
	f.capture = func(context.Context, string, time.Time, func() error) ([]systeminventory.Socket, error) {
		return rows, nil
	}
	got = f.run(t, fixtureRequest(CaptureOperation))
	if got.Status != StatusCaptured || len(got.Observation.Sockets[0].Owners) != 0 || got.Observation.Sockets[0].Attribution.Reason != systeminventory.ReasonPermissionDenied {
		t.Fatal("invented complete ownership")
	}
}

func TestFactsGroupsAllowOnlyBoundPrimaryOnce(t *testing.T) {
	a := Authority{Policy: fixturePolicy(), Revision: strings.Repeat("d", 64), ProtectedPolicyVerified: true, ProtectedGrantBindingVerified: true}
	for _, helper := range [][]uint32{nil, {1201}} {
		for _, peer := range [][]uint32{nil, {1200}} {
			facts := fixtureFacts()
			facts.Groups = helper
			facts.PeerGroups = peer
			if _, err := reference(a, facts); err != nil {
				t.Fatal("primary-only facts rejected", err)
			}
		}
	}
	for _, groups := range [][]uint32{{0}, {500}, {1200, 1200}, {1201, 1201}, {1200, 1201}, {1201, 500}} {
		for _, peer := range []bool{false, true} {
			facts := fixtureFacts()
			if peer {
				facts.PeerGroups = groups
			} else {
				facts.Groups = groups
			}
			if _, err := reference(a, facts); err == nil {
				t.Fatal("group facts admitted", groups, peer)
			}
		}
	}
}
