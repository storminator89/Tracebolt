//go:build linux

package actionhelper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
)

func TestIPCSubmissionAndStatusFrames(t *testing.T) {
	f := newFixture(t)
	r := f.request(t, 1)
	wire, e := EncodeRequest(r)
	if e != nil {
		t.Fatal(e)
	}
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { f.s.ServeConn(context.Background(), a); close(done) }()
	if _, e = b.Write(wire); e != nil {
		t.Fatal(e)
	}
	response, e := ReadResponse(b)
	if e != nil || response.Result == nil || response.Result.Phase != actionstate.OperationCompleted || response.Error != "" {
		t.Fatal(response, e)
	}
	b.Close()
	<-done
	_, starts, _ := f.backend.counts()
	if starts != 1 {
		t.Fatal(starts)
	}
	status := Request{Version: RequestVersion, Operation: StatusOperation, JobID: response.Result.JobID}
	wire, _ = EncodeRequest(status)
	decoded, e := readRequest(bytes.NewReader(wire))
	if e != nil || decoded.JobID != status.JobID {
		t.Fatal(decoded, e)
	}
}
func TestIPCDisconnectedCallerCannotDiscardCompletedState(t *testing.T) {
	f := newFixture(t)
	r := f.request(t, 1)
	wire, _ := EncodeRequest(r)
	began := make(chan struct{})
	release := make(chan struct{})
	f.backend.start = func(ctx context.Context) error {
		close(began)
		<-release
		if ctx.Err() != nil {
			t.Error("disconnect canceled backend")
		}
		return nil
	}
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { f.s.ServeConn(context.Background(), a); close(done) }()
	if _, e := b.Write(wire); e != nil {
		t.Fatal(e)
	}
	<-began
	b.Close()
	close(release)
	<-done
	p, _ := actionpermit.Decode(r.Envelope)
	st, e := f.state.Status(context.Background(), p.JobID)
	if e != nil || st.Phase != actionstate.OperationCompleted {
		t.Fatal(st, e)
	}
	again, e := f.s.Handle(context.Background(), f.peer, r)
	if e != nil || again != st {
		t.Fatal(again, e)
	}
	_, starts, _ := f.backend.counts()
	if starts != 1 {
		t.Fatal(starts)
	}
}
func TestIPCShutdownWaitsForInvokedOperationAndPersists(t *testing.T) {
	f := newFixture(t)
	r := f.request(t, 1)
	wire, _ := EncodeRequest(r)
	began := make(chan struct{})
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.backend.start = func(operation context.Context) error {
		close(began)
		<-release
		if operation.Err() != nil {
			t.Error("shutdown canceled operation")
		}
		return nil
	}
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { f.s.ServeConn(ctx, a); close(done) }()
	if _, e := b.Write(wire); e != nil {
		t.Fatal(e)
	}
	<-began
	cancel()
	select {
	case <-done:
		t.Fatal("abandoned operation")
	default:
	}
	close(release)
	<-done
	b.Close()
	p, _ := actionpermit.Decode(r.Envelope)
	st, e := f.state.Status(context.Background(), p.JobID)
	if e != nil || st.Phase != actionstate.OperationCompleted {
		t.Fatal(st, e)
	}
}
func TestIPCPeerDeniedBeforeReading(t *testing.T) {
	f := newFixture(t)
	f.s.inner.deps.Peer = func(net.Conn) (Peer, error) { return Peer{UID: 9999, GID: 9999, PID: 9}, nil }
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { f.s.ServeConn(context.Background(), a); close(done) }()
	<-done
	if _, e := b.Write([]byte("never read")); e == nil {
		t.Fatal("peer accepted")
	}
	b.Close()
	_, starts, _ := f.backend.counts()
	if starts != 0 {
		t.Fatal(starts)
	}
}
func TestIPCConnectionLimitAndCanceledPartialFrames(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accepted := make(chan struct{}, MaxConnections)
	f.s.inner.deps.Peer = func(net.Conn) (Peer, error) { accepted <- struct{}{}; return f.peer, nil }
	var wg sync.WaitGroup
	var clients []net.Conn
	for i := 0; i < MaxConnections; i++ {
		a, b := net.Pipe()
		clients = append(clients, b)
		wg.Go(func() { f.s.ServeConn(ctx, a) })
		<-accepted
	}
	a, b := net.Pipe()
	f.s.ServeConn(ctx, a)
	if _, e := b.Write([]byte{0}); e == nil {
		t.Fatal("extra connection admitted")
	}
	b.Close()
	cancel()
	wg.Wait()
	for _, c := range clients {
		c.Close()
	}
	_, starts, _ := f.backend.counts()
	if starts != 0 {
		t.Fatal(starts)
	}
}
func TestIPCRejectsMalformedCanonicalRequests(t *testing.T) {
	f := newFixture(t)
	r := f.request(t, 1)
	wire, _ := EncodeRequest(r)
	raw := wire[8:]
	malformed := [][]byte{frame(append(raw, ' ')), frame(append(raw[:len(raw)-1], []byte(",\"arbitrary\":\"command\"}")...)), frame([]byte(`{"version":"tracebolt.action-helper-request.v1","operation":"complete","jobId":"action_00000000000000000000000000000001"}`)), frame([]byte(`{"version":"tracebolt.action-helper-request.v1","operation":"status","jobId":"../../etc/shadow"}`)), wire[:7], wire[:len(wire)-1]}
	huge := append([]byte(nil), wire[:8]...)
	binary.BigEndian.PutUint32(huge[4:], MaxRequestBytes+1)
	malformed = append(malformed, huge)
	for i, b := range malformed {
		if _, e := readRequest(bytes.NewReader(b)); e == nil {
			t.Fatal("accepted malformed", i)
		}
	}
	// One connection processes exactly one frame; it never executes trailing work.
	joined := append(append([]byte(nil), wire...), wire...)
	reader := bytes.NewReader(joined)
	if _, e := readRequest(reader); e != nil || reader.Len() != len(wire) {
		t.Fatal(e, reader.Len())
	}
}
func completedResponse(t *testing.T) Response {
	t.Helper()
	f := newFixture(t)
	st, e := f.s.Handle(context.Background(), f.peer, f.request(t, 1))
	if e != nil {
		t.Fatal(e)
	}
	var b bytes.Buffer
	if e = writeResponse(&b, st, nil); e != nil {
		t.Fatal(e)
	}
	r, e := ReadResponse(&b)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestResponseRejectsContradictoryOrUnboundedResult(t *testing.T) {
	for _, kind := range []string{"job", "sequence", "digest", "phase", "reason", "outcome", "observed", "time", "dispatch", "missing_dispatch", "error", "empty"} {
		t.Run(kind, func(t *testing.T) {
			r := completedResponse(t)
			switch kind {
			case "job":
				r.Result.JobID = "other"
			case "sequence":
				r.Result.Sequence = 0
			case "digest":
				r.Result.EnvelopeDigest = "sha256:no"
			case "phase":
				r.Result.Phase = "succeeded"
			case "reason":
				r.Result.Reason = "arbitrary"
			case "outcome":
				r.Result.Outcome = "arbitrary"
			case "observed":
				r.Result.ObservedState = "healthy"
			case "time":
				r.Result.TransitionAt = r.Result.ConsumedAt - 1
			case "dispatch":
				r.Result.DispatchAt = r.Result.TransitionAt + 1
			case "missing_dispatch":
				r.Result.DispatchAt = 0
			case "error":
				r.Error = "denied"
			case "empty":
				r.Result = nil
			}
			raw, _ := json.Marshal(r)
			if _, e := ReadResponse(bytes.NewReader(frame(raw))); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestResponseAllowsAllActualLifecycleStatuses(t *testing.T) {
	f := newFixture(t)
	r := f.request(t, 1)
	now := time.UnixMicro(f.clock.Load()).UTC()
	st, a, e := f.state.Begin(context.Background(), r.Envelope, now)
	if e != nil {
		t.Fatal(e)
	}
	check := func(s actionstate.Status) {
		t.Helper()
		var b bytes.Buffer
		if e := writeResponse(&b, s, nil); e != nil {
			t.Fatal(e)
		}
		if _, e := ReadResponse(&b); e != nil {
			t.Fatalf("%s: %v", s.Phase, e)
		}
	}
	check(st)
	st, e = a.MarkDispatching(context.Background(), now)
	if e != nil {
		t.Fatal(e)
	}
	check(st)
	st, e = a.Complete(context.Background(), actionstate.OutcomeUnknown, actionstate.ObservedUnknown, now)
	if e != nil {
		t.Fatal(e)
	}
	check(st)
}
func FuzzRequestFrame(f *testing.F) {
	f.Add(frame([]byte(`{"version":"tracebolt.action-helper-request.v1","operation":"status","jobId":"action_00000000000000000000000000000001"}`)))
	f.Add([]byte("TBA1"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, e := readRequest(bytes.NewReader(raw))
		if e == nil {
			wire, e := EncodeRequest(r)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = readRequest(bytes.NewReader(wire)); e != nil {
				t.Fatal(e)
			}
		}
	})
}
func TestNoRawBackendErrorsInWireResponse(t *testing.T) {
	var b bytes.Buffer
	_ = writeResponse(&b, actionstate.Status{}, io.ErrUnexpectedEOF)
	if strings.Contains(b.String(), io.ErrUnexpectedEOF.Error()) {
		t.Fatal("raw error leaked")
	}
	r, e := ReadResponse(&b)
	if e != nil || r.Error != "denied" {
		t.Fatal(r, e)
	}
}
