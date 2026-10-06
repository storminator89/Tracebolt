package socketowner

import (
	"context"
	"io"
	"sync"
	"time"

	"localrmm/internal/systeminventory"
)

// Connection is a trusted native wrapper, not a plain net.Conn adapter.
// Each Read must authenticate actual SCM_CREDENTIALS and reject ancillary FDs.
// Facts retain/recheck the peer pidfd and namespace descriptors. The native
// implementation requires the v2 activated-client deployment; tests are inert.
type Connection interface {
	io.Reader
	io.Writer
	Close() error
	SetDeadline(time.Time) error
	Facts(context.Context) (Facts, error)
}

// Capture must honor guard before bounded source batches, cooperatively cancel,
// and close all source handles before returning. No detached work is allowed.
// These injected functions establish neither root ownership nor kernel proof.
type Dependencies struct {
	Load      func() (Authority, error)
	Now       func() time.Time
	Monotonic func() time.Duration
	Capture   func(context.Context, string, time.Time, func() error) ([]systeminventory.Socket, error)
}
type Server struct{ state *serverState }
type serverState struct {
	deps                 Dependencies
	connections          chan struct{}
	mu                   sync.Mutex
	capturing, attempted bool
	lastAttempt          time.Duration
}

func New(d Dependencies) (*Server, error) {
	if d.Load == nil || d.Now == nil || d.Monotonic == nil || d.Capture == nil {
		return nil, ErrRejected
	}
	return &Server{&serverState{deps: d, connections: make(chan struct{}, MaxConnections)}}, nil
}
func (s *Server) authority(ctx context.Context, c Connection, r Request) (Reference, error) {
	if ctx.Err() != nil {
		return Reference{}, ErrChanged
	}
	a, e := s.state.deps.Load()
	if e != nil {
		return Reference{}, ErrChanged
	}
	f, e := c.Facts(ctx)
	if e != nil {
		return Reference{}, ErrChanged
	}
	ref, e := reference(a, f)
	if e != nil || r.SenderBinding != a.Policy.SenderBinding || r.GrantEpoch != ref.GrantEpoch || r.PolicyDigest != ref.PolicyDigest || r.Reference != nil && *r.Reference != ref {
		return Reference{}, ErrChanged
	}
	return ref, nil
}
func (s *Server) beginCapture() string {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if s.state.capturing {
		return StatusBusy
	}
	tick := s.state.deps.Monotonic()
	if tick < 0 || s.state.attempted && tick < s.state.lastAttempt {
		return StatusUnavailable
	}
	if s.state.attempted && tick-s.state.lastAttempt < CaptureInterval {
		return StatusRateLimited
	}
	s.state.capturing = true
	s.state.attempted = true
	s.state.lastAttempt = tick
	return ""
}
func (s *Server) endCapture() { s.state.mu.Lock(); s.state.capturing = false; s.state.mu.Unlock() }

// ServeConn owns one admitted stream through synchronous capture/cleanup and
// output. At most two connections and one capture exist across copied handles.
func (s *Server) ServeConn(parent context.Context, c Connection) {
	if c == nil {
		return
	}
	defer c.Close()
	if s == nil || s.state == nil || parent == nil || parent.Err() != nil {
		return
	}
	select {
	case s.state.connections <- struct{}{}:
		defer func() { <-s.state.connections }()
	default:
		return
	}
	deadline := time.Now().Add(ConnectionTimeout)
	if d, ok := parent.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if c.SetDeadline(deadline) != nil {
		return
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { c.Close(); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	r, e := ReadRequest(c)
	if e != nil {
		s.failure(c, StatusInvalid)
		return
	}
	ref, e := s.authority(ctx, c, r)
	if e != nil {
		s.failure(c, StatusDenied)
		return
	}
	guard := func() error {
		now, e := s.authority(ctx, c, r)
		if e != nil || now != ref {
			return ErrChanged
		}
		return nil
	}
	result := Response{Version: ProtocolVersion, Status: StatusVerified, Reference: &ref}
	if r.Operation == CaptureOperation {
		if status := s.beginCapture(); status != "" {
			s.failure(c, status)
			return
		}
		defer s.endCapture()
		captureCtx, finish := context.WithTimeout(ctx, CaptureTimeout)
		started := s.state.deps.Now().UTC()
		captureGuard := func() error {
			if captureCtx.Err() != nil {
				return captureCtx.Err()
			}
			return guard()
		}
		if captureGuard() != nil {
			finish()
			s.failure(c, StatusDenied)
			return
		}
		rows, err := s.state.deps.Capture(captureCtx, r.GenerationID, started, captureGuard)
		ended := s.state.deps.Now().UTC()
		captureErr := captureCtx.Err()
		finish()
		if guard() != nil {
			s.failure(c, StatusDenied)
			return
		}
		if err != nil || captureErr != nil {
			s.failure(c, StatusUnavailable)
			return
		}
		result.Status = StatusCaptured
		result.Observation = &Observation{GenerationID: r.GenerationID, StartedAt: started, FinishedAt: ended, Sockets: rows}
	}
	// References are checked again for Verify as well as after capture. Readiness
	// (nil request Reference) never refreshes an already staged observation.
	if guard() != nil {
		s.failure(c, StatusDenied)
		return
	}
	b, e := EncodeResponse(result)
	if e != nil {
		s.failure(c, StatusUnavailable)
		return
	}
	if guard() != nil {
		return
	}
	if writeAll(c, b[:8]) != nil {
		return
	}
	for payload := b[8:]; len(payload) > 0; {
		if guard() != nil {
			return
		}
		n := min(len(payload), 16<<10)
		if writeAll(c, payload[:n]) != nil {
			return
		}
		payload = payload[n:]
	}
}
func (s *Server) failure(c Connection, status string) {
	b, e := EncodeResponse(Response{Version: ProtocolVersion, Status: status})
	if e == nil {
		_ = writeAll(c, b)
	}
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil || n <= 0 || n > len(b) {
			return ErrRejected
		}
		b = b[n:]
	}
	return nil
}
