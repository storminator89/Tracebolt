//go:build linux

package socketowner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"localrmm/internal/systeminventory"
)

// Run has no flags, paths, request-selected process targets or network dialer.
// It never creates a listener or changes IDs, capabilities, permissions or units.
// Its authority requires the explicit v2 activated-client deployment contract;
// it does not read enrollment state or install/provision that contract.
// Inert tests must never call Run or execute the native helper binary.
func Run(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrRejected
	}
	reader := &nativeProtectedReader{}
	initial, e := loadNativeAuthority(reader)
	if e != nil {
		return e
	}
	return runNative(ctx, reader, initial)
}

type nativeRuntime struct {
	initial         nativeAuthority
	proc            int
	procStat        unix.Stat_t
	manager, helper *processPin
	listenerFile    *os.File
	listenerProof   listenerEvidence
	runtimeID       string
}

func (r *nativeRuntime) close() {
	if r.manager != nil {
		r.manager.close()
	}
	if r.helper != nil {
		r.helper.close()
	}
	if r.proc >= 0 {
		unix.Close(r.proc)
	}
}
func (r *nativeRuntime) currentProc() bool {
	fd, e := unix.Open("/proc", nativeDirFlags, 0)
	if e != nil {
		return false
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	var fs unix.Statfs_t
	return unix.Fstat(fd, &st) == nil && unix.Fstatfs(fd, &fs) == nil && fs.Type == unix.PROC_SUPER_MAGIC && st.Dev == r.procStat.Dev && st.Ino == r.procStat.Ino
}
func newNativeRuntime(a nativeAuthority, f *os.File, proof listenerEvidence) (*nativeRuntime, error) {
	r := &nativeRuntime{initial: a, proc: -1, listenerFile: f, listenerProof: proof}
	fail := func() (*nativeRuntime, error) { r.close(); return nil, ErrRejected }
	proc, e := unix.Open("/proc", nativeDirFlags, 0)
	if e != nil {
		return fail()
	}
	r.proc = proc
	var fs unix.Statfs_t
	if unix.Fstat(proc, &r.procStat) != nil || unix.Fstatfs(proc, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return fail()
	}
	own, e := unix.PidfdOpen(os.Getpid(), 0)
	if e != nil {
		return fail()
	}
	r.helper, e = pinProcess(proc, int32(os.Getpid()), own)
	if e != nil {
		return fail()
	}
	init, e := unix.PidfdOpen(1, 0)
	if e != nil {
		return fail()
	}
	r.manager, e = pinProcess(proc, 1, init)
	if e != nil {
		return fail()
	}
	if !systemdPID1(r.manager) || r.manager.namespaces.IDs != r.helper.namespaces.IDs {
		return fail()
	}
	// /proc/1's typed PID namespace must equal the current helper's namespace.
	// Together with a self numeric-directory match, this rejects foreign proc PID
	// domains before any kernel peer PID is interpreted below this proc root.
	self, e := unix.Openat(proc, "self", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return fail()
	}
	var x, y unix.Stat_t
	ok := unix.Fstat(self, &x) == nil && unix.Fstat(r.helper.dir, &y) == nil && x.Dev == y.Dev && x.Ino == y.Ino
	unix.Close(self)
	if !ok || !r.currentProc() {
		return fail()
	}
	var random [32]byte
	if _, e := rand.Read(random[:]); e != nil {
		return fail()
	}
	r.runtimeID = hex.EncodeToString(random[:])
	return r, nil
}

func runNative(ctx context.Context, reader protectedReader, initial nativeAuthority) error {
	l, f, proof, e := inheritedNativeListener(initial.Policy)
	if e != nil {
		return e
	}
	defer f.Close()
	defer l.Close()
	r, e := newNativeRuntime(initial, f, proof)
	if e != nil {
		return e
	}
	defer r.close()
	started := time.Now()
	s, e := New(Dependencies{
		Load: func() (Authority, error) {
			if ctx.Err() != nil {
				return Authority{}, ErrChanged
			}
			a, e := loadNativeAuthority(reader)
			return a.Authority, e
		},
		Now: func() time.Time { return time.Now().UTC() }, Monotonic: func() time.Duration { return time.Since(started) },
		Capture: func(ctx context.Context, id string, start time.Time, guard func() error) ([]systeminventory.Socket, error) {
			return systeminventory.CaptureSocketOwners(ctx, id, start, f, guard)
		},
	})
	if e != nil {
		return e
	}
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	slots := make(chan struct{}, MaxConnections)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return ErrRejected
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		workers.Add(1)
		go func(c *net.UnixConn) {
			defer workers.Done()
			defer func() { <-slots }()
			// All helper status/namespace checks, recv/send and synchronous capture stay
			// on this OS thread; the source adapter's nested lock is balanced separately.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			deadline := time.Now().Add(ConnectionTimeout)
			if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
				deadline = d
			}
			connectionCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			if c.SetDeadline(deadline) != nil {
				c.Close()
				return
			}
			native, e := r.connection(connectionCtx, c)
			if e != nil {
				c.Close()
				return
			}
			s.ServeConn(connectionCtx, native)
		}(c)
	}
}

func (r *nativeRuntime) connection(ctx context.Context, c *net.UnixConn) (*nativeConnection, error) {
	raw, e := c.SyscallConn()
	if e != nil {
		return nil, ErrRejected
	}
	var cred unix.Ucred
	pidfd := -1
	var inner error
	e = raw.Control(func(fd uintptr) {
		cred, pidfd, inner = connectionPeer(int(fd), r.initial.Policy, peerProbe{unix.SetsockoptInt, unix.GetsockoptUcred, unix.GetsockoptInt, unix.CloseOnExec, unix.Close})
	})
	if e != nil || inner != nil {
		if pidfd >= 0 {
			unix.Close(pidfd)
		}
		return nil, ErrRejected
	}
	peer, e := pinProcess(r.proc, cred.Pid, pidfd)
	if e != nil {
		return nil, e
	}
	thread, e := unix.Openat(r.proc, "thread-self", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		peer.close()
		return nil, ErrRejected
	}
	tid := unix.Gettid()
	closePins := func() { peer.close(); unix.Close(thread) }
	facts := func(ctx context.Context) (Facts, error) { return r.facts(ctx, peer, thread, tid) }
	if _, e := facts(ctx); e != nil {
		closePins()
		return nil, e
	}
	return &nativeConnection{socket: c, expected: cred, source: unix.Ucred{Pid: int32(os.Getpid()), Uid: r.initial.Policy.HelperUID, Gid: r.initial.Policy.HelperGID}, facts: facts, closePins: closePins, closeFD: unix.Close}, nil
}
func (r *nativeRuntime) facts(ctx context.Context, peer *processPin, thread, tid int) (Facts, error) {
	var out Facts
	p := r.initial.Policy
	if ctx == nil || ctx.Err() != nil || unix.Gettid() != tid || !r.currentProc() || !systemdPID1(r.manager) || !sameNamespaceView(r.manager.dir, r.manager.namespaces.IDs) || !listenerUnchanged(r.listenerFile, p, r.listenerProof) {
		return out, ErrChanged
	}
	h, e := r.helper.check(ctx, p.HelperUID, p.HelperGID, PtraceCapability, helperObject, r.initial.Objects[helperObject])
	if e != nil {
		return out, e
	}
	a, e := peer.check(ctx, p.AgentUID, p.AgentGID, 0, agentObject, r.initial.Objects[agentObject])
	if e != nil {
		return out, e
	}
	b, e := readProcFile(thread, "status", 64<<10)
	t, e2 := parseNativeStatus(b)
	if e != nil || e2 != nil || t.PID != int32(tid) || validateNativeIdentity(t, p.HelperUID, p.HelperGID, PtraceCapability) != nil || !sameNamespaceView(thread, r.helper.namespaces.IDs) {
		return out, ErrChanged
	}
	// Current-thread syscalls independently check saved identities and cap words;
	// proc thread-self supplies ambient/bounding and typed namespace identities.
	ru, eu, su := unix.Getresuid()
	rg, eg, sg := unix.Getresgid()
	groups, e := unix.Getgroups()
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if e != nil || !primaryOnlyGroups(groups, p.HelperGID) || [3]uint32{uint32(ru), uint32(eu), uint32(su)} != h.UIDs || [3]uint32{uint32(rg), uint32(eg), uint32(sg)} != h.GIDs || unix.Capget(&hdr, &caps[0]) != nil {
		return out, ErrChanged
	}
	for _, value := range []uint64{uint64(caps[0].Effective) | uint64(caps[1].Effective)<<32, uint64(caps[0].Permitted) | uint64(caps[1].Permitted)<<32, uint64(caps[0].Inheritable) | uint64(caps[1].Inheritable)<<32} {
		if value != PtraceCapability {
			return out, ErrChanged
		}
	}
	n := r.helper.namespaces.IDs
	if n != peer.namespaces.IDs || n != r.manager.namespaces.IDs || ctx.Err() != nil || !nativeAlive(peer.pidfd) || !nativeAlive(r.helper.pidfd) || !nativeAlive(r.manager.pidfd) {
		return out, ErrChanged
	}
	out = Facts{OwnedDeploymentVerified: true, ProcViewVerified: true, SocketWitnessVerified: true, PeerUIDs: a.UIDs, PeerGIDs: a.GIDs, PeerGroups: a.Groups, PeerCapabilities: a.Caps, HelperUIDs: h.UIDs, HelperGIDs: h.GIDs, Groups: h.Groups, Capabilities: h.Caps, PeerUID: p.AgentUID, PeerGID: p.AgentGID, PeerPID: peer.pid, PeerPIDFDSupported: true, PeerAlive: true, NamespaceTypesVerified: true, HelperNamespaces: n, PeerNamespaces: peer.namespaces.IDs, ManagerNamespaces: r.manager.namespaces.IDs, ProcPIDView: r.manager.namespaces.IDs.PID, RuntimeID: r.runtimeID}
	return out, nil
}

type peerProbe struct {
	set         func(int, int, int, int) error
	credentials func(int, int, int) (*unix.Ucred, error)
	option      func(int, int, int) (int, error)
	cloexec     func(int)
	close       func(int) error
}

func connectionPeer(fd int, p Policy, k peerProbe) (unix.Ucred, int, error) {
	// Normalize inherited ancillary options before any receive. Queued unexpected
	// SCM_PIDFD is still closed/rejected by recvCredentials.
	if k.set(fd, unix.SOL_SOCKET, unix.SO_PASSPIDFD, 0) != nil {
		return unix.Ucred{}, -1, ErrRejected
	}

	if k.set(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1) != nil {
		return unix.Ucred{}, -1, ErrRejected
	}
	cred, e := k.credentials(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if e != nil || cred == nil || cred.Pid <= 0 || cred.Uid != p.AgentUID || cred.Gid != p.AgentGID {
		return unix.Ucred{}, -1, ErrRejected
	}
	// Linux >=6.5 required; unsupported SO_PEERPIDFD has no numeric fallback.
	pidfd, e := k.option(fd, unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	// GetsockoptInt returns (0, errno) on failure; that zero is not an owned FD.
	if e != nil || pidfd < 0 {
		return unix.Ucred{}, -1, ErrRejected
	}
	k.cloexec(pidfd)
	return *cred, pidfd, nil
}
