package actionhelper

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
	"localrmm/internal/mutationfence"
)

const (
	MaxConnections     = 4
	ReadTimeout        = 5 * time.Second
	PreflightTimeout   = 5 * time.Second
	OperationTimeout   = 30 * time.Second
	PersistenceTimeout = 5 * time.Second
)

// Dependencies are trusted in-process adapters, never request data. Backend
// operations are synchronous, with cancellation/cleanup completed before return.
// No goroutine is abandoned to pretend an operation stopped.
type Dependencies struct {
	// Fence is mandatory at runtime whenever the separate package scope exists.
	Fence         *mutationfence.Fence
	FenceRequired bool
	Load          func() (Authority, error)
	Identity      func() error
	Peer          func(net.Conn) (Peer, error)
	Backend       Backend
	State         *actionstate.State
	Now           func() time.Time
}
type Server struct{ inner *server }
type server struct {
	deps        Dependencies
	binding     string
	busy        atomic.Bool
	connections chan struct{}
}

func New(d Dependencies) (*Server, error) {
	if d.Load == nil || d.Identity == nil || d.Peer == nil || d.Backend == nil || d.State == nil || d.Now == nil || d.FenceRequired && d.Fence == nil || d.Identity() != nil {
		return nil, ErrRejected
	}
	a, e := d.Load()
	if e != nil {
		return nil, ErrRejected
	}
	v, e := a.verifier()
	if e != nil {
		return nil, ErrRejected
	}
	binding, e := v.BindingDigest()
	if e != nil {
		return nil, ErrRejected
	}
	snapshotPolicy, e := d.State.RootPolicyDigest(context.Background())
	currentPolicy, policyErr := v.RootPolicyDigest()
	if e != nil || policyErr != nil || snapshotPolicy != currentPolicy {
		return nil, ErrRejected
	}
	persisted, e := d.State.BindingDigest(context.Background())
	if e != nil || binding != persisted {
		return nil, ErrRejected
	}
	return &Server{&server{deps: d, binding: binding, connections: make(chan struct{}, MaxConnections)}}, nil
}
func (s *server) authority(peer Peer) (Authority, actionpermit.Verifier, error) {
	if s.deps.Identity() != nil {
		return Authority{}, actionpermit.Verifier{}, ErrRejected
	}
	a, e := s.deps.Load()
	if e != nil || !a.permitsPeer(peer) {
		return Authority{}, actionpermit.Verifier{}, ErrRejected
	}
	v, e := a.verifier()
	if e != nil {
		return Authority{}, v, ErrRejected
	}
	binding, e := v.BindingDigest()
	if e != nil || binding != s.binding {
		return Authority{}, v, ErrRejected
	}
	return a, v, nil
}
func (s *server) recheck(peer Peer, raw []byte, initial Authority, clockFloor time.Time) error {
	a, v, e := s.authority(peer)
	if e != nil || a.Revision != initial.Revision {
		return ErrRejected
	}
	p, e := v.Verify(raw)
	if e != nil {
		return e
	}
	now := s.deps.Now()
	if now.Before(clockFloor) {
		return actionpermit.ErrClock
	}
	return v.CheckTime(p, now)
}
func (s *Server) Handle(ctx context.Context, peer Peer, r Request) (actionstate.Status, error) {
	if s == nil || s.inner == nil || ctx == nil || ctx.Err() != nil || validateRequest(r) != nil {
		return actionstate.Status{}, ErrRejected
	}
	x := s.inner
	initial, v, e := x.authority(peer)
	if e != nil {
		return actionstate.Status{}, e
	}
	if r.Operation == StatusOperation {
		return x.deps.State.Status(ctx, r.JobID)
	}
	if r.Operation != SubmitOperation {
		return actionstate.Status{}, ErrRejected
	}
	p, e := v.CheckSignature(r.Envelope)
	if e != nil {
		return actionstate.Status{}, ErrRejected
	}
	existing := func() (actionstate.Status, error) {
		st, err := x.deps.State.Status(ctx, p.JobID)
		if err == nil && st.EnvelopeDigest != actionpermit.Digest(r.Envelope) {
			return actionstate.Status{}, actionstate.ErrConflict
		}
		return st, err
	}
	if old, err := existing(); !errors.Is(err, actionstate.ErrNotFound) {
		return old, err
	}
	if _, e = v.Verify(r.Envelope); e != nil {
		return actionstate.Status{}, e
	}
	if !x.busy.CompareAndSwap(false, true) {
		if old, err := existing(); !errors.Is(err, actionstate.ErrNotFound) {
			return old, err
		}
		return actionstate.Status{}, ErrBusy
	}
	defer x.busy.Store(false)
	fenceOwner := mutationfence.Owner{Action: mutationfence.Service, JobID: p.JobID, Sequence: p.Sequence, EnvelopeDigest: actionpermit.Digest(r.Envelope)}
	if x.deps.Fence != nil {
		_, fresh, err := x.deps.Fence.Acquire(ctx, fenceOwner, x.deps.Now().Unix())
		if err != nil || !fresh {
			return actionstate.Status{}, ErrBusy
		}
	}
	finishFence := func(outcome string) error {
		if x.deps.Fence == nil {
			return nil
		}
		c, stop := context.WithTimeout(context.Background(), PersistenceTimeout)
		defer stop()
		return x.deps.Fence.Complete(c, fenceOwner, outcome, x.deps.Now().Unix())
	}
	// Only Begin's fresh in-memory attempt can proceed. A duplicate, legacy
	// admission, migration or status lookup can never reconstruct that capability.
	st, attempt, e := x.deps.State.Begin(ctx, r.Envelope, x.deps.Now())
	if e != nil || attempt == nil {
		return st, e
	}
	notStarted := func(reason actionstate.NotStartedReason) (actionstate.Status, error) {
		finishCtx, stop := context.WithTimeout(context.Background(), PersistenceTimeout)
		defer stop()
		result, err := attempt.NotStarted(finishCtx, reason, x.deps.Now())
		if err == nil {
			err = finishFence("not_started")
		}
		return result, err
	}
	reasonFor := func(err error) actionstate.NotStartedReason {
		if errors.Is(err, actionpermit.ErrExpired) {
			return actionstate.ReasonExpired
		}
		if ctx.Err() != nil {
			return actionstate.ReasonCanceled
		}
		return actionstate.ReasonPolicyChanged
	}
	if e = x.recheck(peer, r.Envelope, initial, st.TransitionAt); e != nil {
		return notStarted(reasonFor(e))
	}
	target, e := initial.target(p.Plan.Unit)
	if e != nil {
		return notStarted(actionstate.ReasonPolicyChanged)
	}
	check := func() (Observation, error) {
		c, cancel := context.WithTimeout(ctx, PreflightTimeout)
		defer cancel()
		return x.deps.Backend.Check(c, target)
	}
	observation, e := check()
	if e != nil {
		if ctx.Err() != nil {
			return notStarted(actionstate.ReasonCanceled)
		}
		return notStarted(actionstate.ReasonPreflight)
	}
	if observation != Active {
		return notStarted(actionstate.ReasonInactive)
	}
	if ctx.Err() != nil {
		return notStarted(actionstate.ReasonCanceled)
	}
	if e = x.recheck(peer, r.Envelope, initial, st.TransitionAt); e != nil {
		return notStarted(reasonFor(e))
	}
	if st, e = attempt.MarkDispatching(ctx, x.deps.Now()); e != nil {
		if errors.Is(e, actionpermit.ErrExpired) {
			return notStarted(actionstate.ReasonExpired)
		}
		return st, e
	}
	// This second concrete check happens AFTER the durable dispatch marker. A
	// crash from here is unknown. Only this live process knows a failed final
	// check happened before any backend mutation, allowing not_started.
	observation, e = check()
	if e != nil {
		if ctx.Err() != nil {
			return notStarted(actionstate.ReasonCanceled)
		}
		return notStarted(actionstate.ReasonPreflight)
	}
	if observation != Active {
		return notStarted(actionstate.ReasonInactive)
	}
	if ctx.Err() != nil {
		return notStarted(actionstate.ReasonCanceled)
	}
	if e = x.recheck(peer, r.Envelope, initial, st.TransitionAt); e != nil {
		return notStarted(reasonFor(e))
	}
	if ctx.Err() != nil {
		return notStarted(actionstate.ReasonCanceled)
	}
	// The original deadline limits start only. Caller disconnection/cancellation
	// after this point does not kill systemd's job. We wait independently, bounded
	// by an observation timeout, and never retry an uncertain invocation.
	operationCtx, cancel := context.WithTimeout(context.Background(), OperationTimeout)
	e = x.deps.Backend.TryRestart(operationCtx, p.Plan.Unit)
	cancel()
	outcome := actionstate.OutcomeUnknown
	observed := actionstate.ObservedUnknown
	if e == nil {
		outcome = actionstate.OutcomeCompleted
		observeCtx, stop := context.WithTimeout(context.Background(), PreflightTimeout)
		observation, err := x.deps.Backend.Observe(observeCtx, p.Plan.Unit)
		stop()
		if err == nil {
			switch observation {
			case Active:
				observed = actionstate.ObservedActive
			case Inactive:
				observed = actionstate.ObservedInactive
			case Failed:
				observed = actionstate.ObservedFailed
			}
		}
	}
	finishCtx, stop := context.WithTimeout(context.Background(), PersistenceTimeout)
	defer stop()
	result, finishErr := attempt.Complete(finishCtx, outcome, observed, x.deps.Now())
	if finishErr == nil && outcome == actionstate.OutcomeCompleted {
		finishErr = finishFence("completed")
	}
	return result, finishErr
}
func (s *Server) ServeConn(ctx context.Context, c net.Conn) {
	if c == nil {
		return
	}
	if s == nil || s.inner == nil {
		c.Close()
		return
	}
	select {
	case s.inner.connections <- struct{}{}:
		defer func() { <-s.inner.connections }()
	default:
		c.Close()
		return
	}
	s.handleConn(ctx, c)
}
func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	if ctx == nil || ctx.Err() != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if c.SetDeadline(time.Now().Add(ReadTimeout)) != nil {
		return
	}
	peer, e := s.inner.deps.Peer(c)
	if e != nil {
		return
	}
	// Reject an unauthorized peer before reading a payload.
	if _, _, e = s.inner.authority(peer); e != nil {
		return
	}
	r, e := readRequest(c)
	if e != nil {
		return
	}
	if r.Operation == CapabilitiesOperation {
		if c.SetWriteDeadline(time.Now().Add(2*time.Second)) != nil {
			return
		}
		capabilities, err := s.Capabilities(ctx, peer)
		_ = writeCapabilities(c, capabilities, err)
		return
	}
	st, e := s.Handle(ctx, peer, r)
	if c.SetWriteDeadline(time.Now().Add(2*time.Second)) != nil {
		return
	}
	_ = writeResponse(c, st, e)
}
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	if s == nil || s.inner == nil || ctx == nil || l == nil {
		return ErrRejected
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer l.Close()
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
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
			return ErrUnavailable
		}
		select {
		case s.inner.connections <- struct{}{}:
			wg.Go(func() { defer func() { <-s.inner.connections }(); s.handleConn(ctx, c) })
		default:
			c.Close()
		}
	}
}
