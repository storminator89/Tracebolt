package windowssoftwareipc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	job "localrmm/internal/windowssoftwarejob"
	"sync"
	"time"
)

// Server has one independent bounded operation owner, never a goroutine per
// submitted permit. The kernel persists consumption before a successful reply.
// Connection cancellation cannot revoke or repeat an accepted install.
type Server struct {
	executor *job.Executor
	config   PeerConfig
	key      ed25519.PrivateKey
	ctx      context.Context
	cancel   context.CancelFunc
	pending  chan *job.Accepted
	done     chan struct{}
	close    sync.Once
	check    func(context.Context) error
}

func NewServer(ctx context.Context, x *job.Executor, c PeerConfig, key ed25519.PrivateKey, check func(context.Context) error) (*Server, error) {
	if ctx == nil || ctx.Err() != nil || x == nil || c.Validate() != nil || check == nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) || !bytes.Equal(key.Public().(ed25519.PublicKey), c.ExecutorPublicKey) {
		return nil, job.ErrInvalid
	}
	c.ExecutorPublicKey = bytes.Clone(c.ExecutorPublicKey)
	ctx, cancel := context.WithCancel(ctx)
	s := &Server{executor: x, config: c, key: bytes.Clone(key), ctx: ctx, cancel: cancel, pending: make(chan *job.Accepted, 1), done: make(chan struct{}), check: check}
	go s.run()
	return s, nil
}
func (s *Server) run() {
	defer close(s.done)
	for {
		select {
		case <-s.ctx.Done():
			return
		case h := <-s.pending:
			ctx, cancel := context.WithTimeout(s.ctx, 31*time.Minute)
			_, _ = s.executor.RunAccepted(ctx, h)
			cancel()
		}
	}
}

// Close must run after Serve returns. Cancellation is not rollback; an unfinished
// protected attempt remains intervention-required and is never resumed.
func (s *Server) Close() {
	if s == nil {
		return
	}
	s.close.Do(func() { s.cancel(); <-s.done; clear(s.key) })
}
func (s *Server) dispatch(ctx context.Context, raw []byte) response {
	out := response{Version: Version}
	var r request
	if decode(raw, &r) != nil || r.validate() != nil {
		out.Error = "invalid"
		return out
	}
	if s.ctx.Err() != nil || s.check(ctx) != nil {
		out.Error = "unavailable"
		return out
	}
	var e error
	switch r.Operation {
	case "peer":
	case "readiness":
		out.Report, e = s.executor.Readiness(ctx, r.Envelope)
	case "submit":
		var h *job.Accepted
		h, e = s.executor.Accept(ctx, r.Envelope)
		if e == nil {
			select {
			case s.pending <- h:
			case <-s.ctx.Done():
				e = job.ErrUncertain
			default:
				e = job.ErrUncertain
			}
		}
	case "status":
		var status job.ExecutorStatus
		status, e = s.executor.Status(ctx)
		if e == nil {
			out.Status = &status
		}
	case "outbox":
		out.Report, e = s.executor.Outbox(ctx, r.Kind, r.JobID, r.ReferenceDigest)
	}
	if e != nil {
		out.Error = "unavailable"
		out.Report = nil
		out.Status = nil
	}
	return out
}

func (*Server) String() string   { return "<dedicated Windows software IPC server>" }
func (*Server) GoString() string { return "<dedicated Windows software IPC server>" }
func (*Server) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "<dedicated Windows software IPC server>")
}
func (*Server) MarshalJSON() ([]byte, error) { return []byte(`{"secretsRedacted":true}`), nil }
