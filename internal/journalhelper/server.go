package journalhelper

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalview"
)

// Dependencies must all be locally supplied. Production constructs these from
// root-protected files and kernel credentials; callers cannot set them via IPC.
// Capture is synchronous and must finish cooperative cancellation and cleanup
// before returning. No worker is abandoned on timeout or disconnect.
type Dependencies struct {
	Load     func() (State, error)
	Identity func() (Identity, error)
	Peer     func(net.Conn) (Peer, error)
	Capture  func(context.Context, journalview.Query, time.Time) (journalview.Snapshot, error)
	Now      func() time.Time
}

// Server handles may be copied; all copies share admission and capture state.
type Server struct{ runtime *serverState }
type serverState struct {
	deps        Dependencies
	connections chan struct{}
	capture     atomic.Bool
}

func New(d Dependencies) (*Server, error) {
	if d.Load == nil || d.Identity == nil || d.Peer == nil || d.Capture == nil || d.Now == nil {
		return nil, ErrRejected
	}
	return &Server{runtime: &serverState{deps: d, connections: make(chan struct{}, MaxConnections)}}, nil
}
func (s *Server) state() (State, Identity, error) {
	i, e := s.runtime.deps.Identity()
	if e != nil || !validID(i.RealUID) || !validID(i.EffectiveUID) || !validID(i.SavedUID) || !i.NoCapabilities {
		return State{}, Identity{}, ErrRejected
	}
	state, e := s.runtime.deps.Load()
	if e != nil || validateState(state, i) != nil {
		return State{}, Identity{}, ErrRejected
	}
	return state, i, nil
}
func (s *Server) recheck(r Request, permit journalpolicy.Permit, initial State, p Peer) (State, error) {
	state, i, e := s.state()
	if e != nil || state.Revision != initial.Revision {
		return State{}, ErrRejected
	}
	c, e := authorityContext(state, i, p, r.SenderBinding)
	if e != nil || permit.Recheck(state.Policy, c, s.runtime.deps.Now().UTC()) != nil {
		return State{}, ErrRejected
	}
	return state, nil
}

// ServeConn admits at most two connections and closes after exactly one frame.
// Additional bytes/queries are never processed. Hard network deadlines also
// cover slow or absent readers. Capture cancellation is synchronous; a provider
// that breaks its contract may delay shutdown but never frees its capture slot
// or leaks an abandoned goroutine in order to pretend it has stopped.
func (s *Server) ServeConn(ctx context.Context, c net.Conn) {
	if c == nil {
		return
	}
	if s == nil || s.runtime == nil {
		c.Close()
		return
	}
	select {
	case s.runtime.connections <- struct{}{}:
		defer func() { <-s.runtime.connections }()
	default:
		c.Close()
		return
	}
	s.handleReserved(ctx, c)
}
func (s *Server) handleReserved(ctx context.Context, c net.Conn) {
	defer c.Close()
	if ctx == nil || ctx.Err() != nil {
		return
	}
	deadline := time.Now().Add(ConnectionTimeout)
	if p, ok := ctx.Deadline(); ok && p.Before(deadline) {
		deadline = p
	}
	if c.SetDeadline(deadline) != nil {
		return
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stopped := make(chan struct{})
	stopClose := context.AfterFunc(ctx, func() { c.Close(); close(stopped) })
	defer func() {
		if !stopClose() {
			<-stopped
		}
	}()
	p, e := s.runtime.deps.Peer(c)
	if e != nil {
		s.failure(c, StatusDenied)
		return
	}
	r, e := readRequest(c)
	if e != nil {
		s.failure(c, StatusInvalid)
		return
	}
	if ctx.Err() != nil {
		return
	}
	state, i, e := s.state()
	if e != nil {
		s.failure(c, StatusDenied)
		return
	}
	trusted, e := authorityContext(state, i, p, r.SenderBinding)
	if e != nil {
		s.failure(c, StatusDenied)
		return
	}
	now := s.runtime.deps.Now().UTC()
	permit, e := journalpolicy.Authorize(state.Policy, trusted, r.Query, now)
	if e != nil {
		s.failure(c, StatusDenied)
		return
	}
	result := Response{PolicyDigest: permit.PolicyDigest(), Revision: state.Revision}
	switch r.Operation {
	case VerifyOperation:
		if r.PolicyDigest != result.PolicyDigest || r.Revision != result.Revision {
			s.failure(c, StatusDenied)
			return
		}
		result.Status = StatusVerified
	case QueryOperation:
		if !s.runtime.capture.CompareAndSwap(false, true) {
			s.failure(c, StatusBusy)
			return
		}
		// Keep the slot until Capture has completed cleanup, even after cancellation.
		snapshot, err := s.runtime.deps.Capture(ctx, permit.Query(), now)
		s.runtime.capture.Store(false)
		if ctx.Err() != nil {
			return
		}
		if err != nil || snapshot.Query != r.Query || snapshot.ObservedAt != now {
			s.failure(c, StatusUnavailable)
			return
		}
		var payload []byte
		payload, err = journalview.Encode(snapshot)
		result.body = &responseBody{raw: payload}
		if err != nil || len(result.payload()) > maxResponsePayload {
			s.failure(c, StatusUnavailable)
			return
		}
		result.Status = StatusSnapshot
	default:
		s.failure(c, StatusInvalid)
		return
	}
	if _, e = s.recheck(r, permit, state, p); e != nil {
		s.failure(c, StatusDenied)
		return
	}
	if ctx.Err() != nil {
		return
	}
	header, e := responseHeader(result)
	if e != nil {
		s.failure(c, StatusUnavailable)
		return
	}
	if writeAll(c, header) != nil {
		return
	}
	// Recheck between bounded chunks as well as before the header. Revocation
	// truncates the frame; receivers must discard all incomplete frames. Bytes
	// already passed to the kernel cannot be recalled by any local policy check.
	for b := result.payload(); len(b) > 0; {
		if ctx.Err() != nil {
			return
		}
		if _, e = s.recheck(r, permit, state, p); e != nil {
			return
		}
		n := min(len(b), 16<<10)
		if writeAll(c, b[:n]) != nil {
			return
		}
		b = b[n:]
	}
}
func (*Server) failure(c net.Conn, status byte) {
	h, e := responseHeader(Response{Status: status})
	if e == nil {
		_ = writeAll(c, h)
	}
}
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, e := w.Write(p)
		if e != nil {
			return e
		}
		if n <= 0 || n > len(p) {
			return ErrRejected
		}
		p = p[n:]
	}
	return nil
}

// Serve owns the supplied listener until cancellation or an accept failure and
// waits for all admitted connection handlers and synchronous source cleanup.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	if s == nil || s.runtime == nil || ctx == nil || l == nil {
		return ErrRejected
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer l.Close()
	stopped := make(chan struct{})
	stopClose := context.AfterFunc(ctx, func() { l.Close(); close(stopped) })
	defer func() {
		if !stopClose() {
			<-stopped
		}
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, e := l.Accept()
		if e != nil {
			wasCanceled := ctx.Err() != nil
			cancel()
			if wasCanceled {
				return nil
			}
			return ErrRejected
		}
		// Admission before spawning prevents an unbounded goroutine burst. Reserve
		// the slot here; the private handler avoids a second reservation.
		select {
		case s.runtime.connections <- struct{}{}:
			wg.Go(func() { defer func() { <-s.runtime.connections }(); s.handleReserved(ctx, c) })
		default:
			c.Close()
		}
	}
}
