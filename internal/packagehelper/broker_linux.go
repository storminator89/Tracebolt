//go:build linux

package packagehelper

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"localrmm/internal/actionpermit"
	"localrmm/internal/mutationfence"
	"localrmm/internal/nativeapt"
	"localrmm/internal/packagepermit"
	"localrmm/internal/packageupdate"
	"net"
	"os"
	"strconv"
	"time"
)

type fence interface {
	Acquire(context.Context, mutationfence.Owner, int64) (mutationfence.Entry, bool, error)
	Complete(context.Context, mutationfence.Owner, string, int64) error
	Status(context.Context, mutationfence.Owner) (mutationfence.Entry, error)
}
type broker struct {
	fs       protectedFS
	fence    fence
	commands commands
	now      func() time.Time
	load     func() (authority, error)
}

func (b broker) caps(a authority) Capabilities {
	p := a.policy
	return Capabilities{Version: CapabilitiesVersion, Enabled: p.Enabled, HTTPTestAcknowledged: p.HTTPTestAcknowledged, ManagerID: p.ManagerID, EndpointID: p.EndpointID, IncarnationDigest: p.IncarnationDigest, KeyID: p.KeyID, RootPolicyDigest: a.digest, TransportProfile: p.TransportProfile, CapturedAt: b.now().Unix(), Allowed: append([]packagepermit.Selection(nil), p.Allowed...)}
}
func (b broker) submit(ctx context.Context, a authority, raw []byte) (Snapshot, error) {
	p, e := packagepermit.CheckSignature(ctx, raw, a.pins())
	if e != nil {
		return Snapshot{}, e
	}
	unlock, e := b.fs.lock(nativeapt.JobRoot + "/broker.lock")
	if e != nil {
		return Snapshot{}, e
	}
	defer unlock()
	mode := "prepare"
	if p.Action == packagepermit.Execute {
		mode = "execute"
	}
	existing, e := b.fs.read(jobFile(p.JobID, mode+".permit"), packagepermit.MaxEnvelopeBytes)
	if e == nil {
		if !equalBytes(existing, raw) {
			return Snapshot{}, ErrConflict
		}
		return b.fs.snapshot(p.JobID)
	}
	if !os.IsNotExist(e) {
		return Snapshot{}, e
	}
	if !a.policy.Enabled {
		return Snapshot{}, ErrRejected
	}
	now := b.now().Unix()
	if _, e = packagepermit.Verify(ctx, raw, a.pins(), now); e != nil {
		return Snapshot{}, e
	}
	latest, e := b.load()
	if e != nil || !a.same(latest) || !latest.policy.Enabled {
		return Snapshot{}, ErrRejected
	}
	if e = checkState(b.fs, a); e != nil {
		return Snapshot{}, e
	}
	if mode == "execute" {
		s, e := b.fs.snapshot(p.JobID)
		if e != nil || s.State != packageupdate.PreviewReady || s.Preview == nil || s.Preview.Digest != p.PreviewDigest || s.Preview.ActorID != p.ActorID || s.Preview.PlanDigest != p.PlanDigest || !rawEqual(s.Preview.Plan, p.Plan) || s.Sequence != p.Sequence {
			return Snapshot{}, ErrConflict
		}
		if e = reserveOutcomeCapacity(s); e != nil {
			return Snapshot{}, e
		}
		if e = runnerInactive(b.commands, p.JobID); e != nil {
			return Snapshot{}, e
		}
	}
	// A definite shared-fence rejection publishes no new job/envelope. Once the
	// shared admission commits, all later uncertainty is consumed permanently.
	_, fresh, e := b.fence.Acquire(ctx, owner(p, raw), now)
	if e != nil {
		return Snapshot{}, e
	}
	if !fresh {
		return Snapshot{}, ErrUncertain
	}
	if mode == "prepare" {
		if e = b.fs.mkdir(jobFile(p.JobID, "")); e != nil {
			return Snapshot{}, ErrUncertain
		}
		if e = b.fs.create(jobFile(p.JobID, "prepare.permit"), raw); e != nil {
			return Snapshot{}, e
		}
		ss := make([]nativeapt.Selection, len(p.Selection))
		for i, s := range p.Selection {
			ss[i] = nativeapt.Selection{Name: s.Name, Architecture: s.Architecture}
		}
		selection, e := nativeapt.SelectionBytes(ss)
		if e != nil {
			return Snapshot{}, e
		}
		paths, _ := nativeapt.JobPaths(p.JobID)
		if e = b.fs.create(paths.Selection, selection); e != nil {
			return Snapshot{}, e
		}
		if e = b.fs.create(paths.Config, nativeapt.ConfigBytes(paths, p.JobID)); e != nil {
			return Snapshot{}, e
		}
	} else {
		if e = b.fs.create(jobFile(p.JobID, "execute.permit"), raw); e != nil {
			return Snapshot{}, e
		}
	}

	if e = b.fs.createJSON(jobFile(p.JobID, mode+".admitted"), admission{actionpermit.Digest(raw), now}); e != nil {
		return Snapshot{}, e
	}
	if e = startRunner(b.commands, p.JobID); e != nil {
		return Snapshot{}, ErrUncertain
	}
	return b.fs.snapshot(p.JobID)
}
func peer(conn *net.UnixConn) (*unix.Ucred, error) {
	raw, e := conn.SyscallConn()
	if e != nil {
		return nil, e
	}
	var cred *unix.Ucred
	var failure error
	if e = raw.Control(func(fd uintptr) { cred, failure = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); e != nil {
		return nil, e
	}
	return cred, failure
}
func inheritedListener(p Policy) (*net.UnixListener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return nil, ErrRejected
	}
	var st unix.Stat_t
	if unix.Fstat(3, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil, ErrRejected
	}
	a, e := unix.Getsockname(3)
	u, ok := a.(*unix.SockaddrUnix)
	if e != nil || !ok || u.Name != SocketPath {
		return nil, ErrRejected
	}
	accept, e := unix.GetsockoptInt(3, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if e != nil || accept != 1 {
		return nil, ErrRejected
	}
	if e = unix.Lstat(SocketPath, &st); e != nil || st.Uid != 0 || st.Gid != p.AgentGID || st.Mode&0777 != 0660 {
		return nil, ErrRejected
	}
	d, e := hostFS().dir("/run/tracebolt-package-helper")
	if e != nil {
		return nil, e
	}
	d.Close()
	f := os.NewFile(3, "inherited-package-socket")
	defer f.Close()
	l, e := net.FileListener(f)
	if e != nil {
		return nil, e
	}
	listener, ok := l.(*net.UnixListener)
	if !ok {
		l.Close()
		return nil, ErrRejected
	}
	listener.SetUnlinkOnClose(false)
	return listener, nil
}
func errorCode(e error) string {
	switch {
	case errors.Is(e, mutationfence.ErrBusy):
		return "busy"
	case errors.Is(e, packagepermit.ErrExpired):
		return "expired"
	case errors.Is(e, ErrConflict) || errors.Is(e, mutationfence.ErrConflict):
		return "conflict"
	case errors.Is(e, ErrUncertain) || errors.Is(e, ErrUnavailable):
		return "unavailable"
	default:
		return "denied"
	}
}
func (b broker) serveOne(c *net.UnixConn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	a, e := b.fs.identityAuthority()
	if e != nil {
		_ = writeResponse(c, Response{Error: "unavailable"})
		return
	}
	cred, e := peer(c)
	if e != nil || cred.Pid <= 0 || cred.Uid != a.policy.AgentUID || cred.Gid != a.policy.AgentGID {
		_ = writeResponse(c, Response{Error: "denied"})
		return
	}
	q, e := readRequest(c)
	if e != nil {
		_ = writeResponse(c, Response{Error: "denied"})
		return
	}
	var r Response
	switch q.Operation {
	case CapabilitiesOperation:
		v := b.caps(a)
		live, e := b.load()
		if e != nil || !a.same(live) || !live.policy.Enabled {
			v.Enabled = false
		}
		r.Capabilities = &v
	case StatusOperation:
		v, err := b.status(q.JobID, claimLive)
		e = err
		if e == nil {
			r.Snapshot = &v
		}
	case SubmitOperation:
		v, err := b.submit(context.Background(), a, q.Envelope)
		e = err
		if e == nil {
			r.Snapshot = &v
		}
	}
	if e != nil {
		r = Response{Error: errorCode(e)}
	}
	_ = writeResponse(c, r)
}

// RunBroker consumes one protected systemd-activated socket and existing state.
// No socket/directory/ledger/key/policy is provisioned at startup.
func RunBroker(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || rootIdentity() != nil {
		return ErrRejected
	}
	fs := hostFS()
	a, e := fs.identityAuthority()
	if e != nil {
		return e
	}
	if e = checkState(fs, a); e != nil {
		return e
	}
	c := realCommands{}
	f, e := mutationfence.Open(ctx, mutationfence.DefaultDirectory, binding(a))
	if e != nil {
		return e
	}
	defer f.Close()
	l, e := inheritedListener(a.policy)
	if e != nil {
		return e
	}
	defer l.Close()
	b := broker{fs, f, c, time.Now, func() (authority, error) {
		a, e := fs.authority()
		if e != nil {
			return a, e
		}
		if e = checkServiceGeneration(c, a); e != nil {
			return authority{}, e
		}
		return a, nil
	}}
	go func() { <-ctx.Done(); l.Close() }()
	slots := make(chan struct{}, 8)
	for {
		conn, e := l.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return e
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); b.serveOne(conn) }()
		default:
			conn.Close()
		}
	}
}

func claimLive(c runnerClaim) bool {
	_, start, e := procIdentity(c.PID)
	return e == nil && start == c.Start
}

// Missing live runner custody is interrupted evidence, never proof of rollback,
// completion or permission to relaunch. Any surviving dpkg child is left alone.
func (b broker) status(id string, alive func(runnerClaim) bool) (Snapshot, error) {
	unlock, e := b.fs.lock(nativeapt.JobRoot + "/broker.lock")
	if e != nil {
		return Snapshot{}, e
	}
	defer unlock()
	s, e := b.fs.snapshot(id)
	if e != nil {
		return s, e
	}
	a, e := b.fs.identityAuthority()
	if e != nil || checkState(b.fs, a) != nil {
		return Snapshot{}, ErrRejected
	}
	prep, pp, e := readPermit(b.fs, id, "prepare")
	if e != nil {
		return Snapshot{}, e
	}
	if e = verifySavedPermit(a, prep, pp); e != nil {
		return Snapshot{}, e
	}
	mode := "prepare"
	raw, p := prep, pp
	if s.ExecutionEnvelopeDigest != "" {
		mode = "execute"
		raw, p, e = readPermit(b.fs, id, mode)
		if e != nil {
			return Snapshot{}, e
		}
		if e = verifySavedPermit(a, raw, p); e != nil {
			return Snapshot{}, e
		}
	}
	if s.State == packageupdate.Succeeded {
		entry, e := b.fence.Status(context.Background(), owner(p, raw))
		if e != nil || entry.CompletedAt == 0 || entry.Outcome != "completed" {
			return Snapshot{}, ErrUncertain
		}
		return s, nil
	}
	if s.State == packageupdate.NeedsIntervention || s.State == packageupdate.PreparationFailed || s.State == packageupdate.PreviewReady {
		return s, nil
	}
	var claim runnerClaim
	e = b.fs.json(jobFile(id, mode+".claim"), 4096, &claim)
	if e != nil && !os.IsNotExist(e) {
		return s, e
	}
	if e == nil && alive(claim) {
		return s, nil
	}
	// Includes no-claim expiry/disabled/failed-start cases. A single systemd
	// property snapshot must show no live main process AND no pending start job.
	if !unitStopped(b.commands, id) {
		return s, nil
	}
	now := b.now().Unix()
	if now < s.UpdatedAt {
		return Snapshot{}, ErrUncertain
	}
	if mode == "prepare" {
		if e = b.fs.createJSON(jobFile(id, "prepare.interrupted"), admission{actionpermit.Digest(raw), now}); e != nil {
			return Snapshot{}, e
		}
	} else {
		if p.Plan == nil {
			return Snapshot{}, ErrUncertain
		}
		if e = b.fs.appendResult(id, resultFor(*p.Plan, uint64(len(s.Results)+1), packageupdate.NeedsIntervention, now, "runner_state_unknown", nil, "unknown")); e != nil {
			return Snapshot{}, e
		}
	}
	return b.fs.snapshot(id)
}

func verifySavedPermit(a authority, raw []byte, p packagepermit.Permit) error {
	pins := a.pins()
	pins.RootPolicyDigest = p.RootPolicyDigest
	pins.Allowed = p.Selection
	_, e := packagepermit.CheckSignature(context.Background(), raw, pins)
	return e
}
