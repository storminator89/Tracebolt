//go:build linux

package systeminventory

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// CaptureSocketOwners is a SOURCE-ONLY adapter for the fixed socket-owner helper.
// No ordinary inventory path calls it. The helper runtime must first verify its
// protected policy, exact identities, activation/path, PID-1-local namespaces,
// proc PID view and Linux 6.5+ peer pidfd/writer credentials. This defense gate
// additionally requires nonroot equal real/effective/saved IDs, no groups beyond
// the primary GID (empty or singleton), and exactly CAP_SYS_PTRACE in each of the five capability sets.
//
// validatedSockfsWitness is the runtime's held inherited listener, never an IPC
// argument or caller-supplied mount/inode. It remains owned by the caller. This
// adapter duplicates and independently validates it and keeps the duplicate
// until all source cleanup finishes. guard must recheck current runtime authority
// before every bounded source batch. Exact fdinfo ino headers require Linux
// >=5.14; descriptor statx INO/MNT_ID and sockfs checks are separate native
// feature gates. Native acceptance has NOT been performed.
func CaptureSocketOwners(ctx context.Context, generationID string, helperStart time.Time, validatedSockfsWitness *os.File, guard func() error) ([]Socket, error) {
	// Linux credentials/capabilities are thread-local. Keep the defensive gate
	// and all synchronous collection syscalls on the same thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return captureSocketOwnersWith(ctx, generationID, helperStart, guard, socketHelperDependencies{
		gate: func() error { return verifySocketHelperIdentity(nativeSocketHelperIdentityOps()) },
		pin: func() (*socketHelperWitness, error) {
			return pinSocketHelperWitness(func() (int, error) {
				if validatedSockfsWitness == nil {
					return -1, ErrInvalidInput
				}
				raw, err := validatedSockfsWitness.SyscallConn()
				if err != nil {
					return -1, SourceError{ReasonInvalidSource}
				}
				fd := -1
				var dupErr error
				err = raw.Control(func(n uintptr) { fd, dupErr = unix.FcntlInt(n, unix.F_DUPFD_CLOEXEC, 0) })
				if err != nil || dupErr != nil {
					if fd >= 0 {
						_ = unix.Close(fd)
					}
					return -1, SourceError{ReasonInvalidSource}
				}
				return fd, nil
			}, nativeSocketHelperWitnessOps())
		},
		files: nativeSocketHelperFiles(),
	})
}

type socketHelperWitness struct {
	mount, inode uint64
	close        func() error
}
type socketHelperDependencies struct {
	gate  func() error
	pin   func() (*socketHelperWitness, error)
	files socketHelperFiles
}

func captureSocketOwnersWith(ctx context.Context, id string, at time.Time, guard func() error, deps socketHelperDependencies) (rows []Socket, err error) {
	if ctx == nil || guard == nil || deps.gate == nil || deps.pin == nil || !deps.files.valid() || Validate(Empty(id, at, ReasonNotCollected)) != nil {
		return nil, ErrInvalidInput
	}
	g := &socketHelperGuard{ctx: ctx, authority: guard}
	if err = g.check(ctx); err != nil {
		return nil, err
	}
	if err = deps.gate(); err != nil {
		return nil, err
	}
	witness, err := deps.pin()
	if err != nil {
		return nil, err
	}
	if witness == nil || witness.close == nil {
		return nil, ErrInvalidSource
	}
	defer func() {
		if e := witness.close(); e != nil {
			rows, err = nil, SourceError{ReasonReadFailed}
		}
	}()
	if witness.mount == 0 || witness.mount > 1<<31-1 || witness.inode == 0 {
		return nil, ErrInvalidSource
	}
	p := &socketHelperProvider{files: deps.files, witness: witness, guard: g}
	defer func() {
		if e := p.Close(); e != nil {
			rows, err = nil, e
		}
		if e := g.check(ctx); e != nil {
			rows, err = nil, e
		}
		if e := deps.gate(); e != nil {
			rows, err = nil, e
		}
	}()
	section := collectSockets(ctx, p, id, at)
	if err = g.check(ctx); err != nil {
		return nil, err
	}
	if section.Meta.Coverage != Complete {
		return nil, SourceError{section.Meta.Reason}
	}
	check := Empty(id, at, ReasonNotCollected)
	check.Sockets = section
	if err = Validate(check); err != nil {
		return nil, err
	}
	return section.Items, nil
}

// Once authority fails, a later successful check cannot resurrect this capture.
// Attribution's narrower timeout is represented by existing partial-row rules;
// cancellation of the capture context suppresses the complete observation.
type socketHelperGuard struct {
	ctx       context.Context
	authority func() error
	failed    error
}

func (g *socketHelperGuard) check(ctx context.Context) error {
	if g.failed != nil {
		return g.failed
	}
	if err := g.ctx.Err(); err != nil {
		g.failed = err
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if g.authority() != nil {
		g.failed = SourceError{ReasonPermissionDenied}
		return g.failed
	}
	return nil
}

type socketHelperDir interface {
	ownerEntries
	fd() int
}
type socketHelperFiles struct {
	openDir  func(int, string) (socketHelperDir, error)
	openFile func(int, string) (io.ReadCloser, error)
	readlink func(int, string, []byte) (int, error)
}

func (f socketHelperFiles) valid() bool {
	return f.openDir != nil && f.openFile != nil && f.readlink != nil
}

type socketHelperOSDir struct{ *os.File }

func (d socketHelperOSDir) fd() int { return int(d.Fd()) }
func nativeSocketHelperFiles() socketHelperFiles {
	return socketHelperFiles{
		openDir: func(parent int, name string) (socketHelperDir, error) {
			f, err := openProcDir(parent, name)
			if err != nil {
				return nil, err
			}
			return socketHelperOSDir{f}, nil
		},
		openFile: func(parent int, name string) (io.ReadCloser, error) { return openProcFile(parent, name) },
		readlink: unix.Readlinkat,
	}
}

type socketHelperProvider struct {
	files     socketHelperFiles
	witness   *socketHelperWitness
	guard     *socketHelperGuard
	proc, net socketHelperDir
	closeErr  error
}

func (p *socketHelperProvider) closed(err error) {
	if err != nil {
		p.closeErr = SourceError{ReasonReadFailed}
	}
}
func (p *socketHelperProvider) initProc(ctx context.Context) error {
	if err := p.guard.check(ctx); err != nil {
		return err
	}
	if p.proc != nil && p.net != nil {
		return nil
	}
	proc, err := p.files.openDir(-1, "/proc")
	if err != nil {
		return err
	}
	p.proc = proc
	selfPID, err := resolveProcSelf(func(name string, target []byte) (int, error) { return p.files.readlink(proc.fd(), name, target) })
	if err != nil {
		return err
	}
	if err = p.guard.check(ctx); err != nil {
		return err
	}
	self, err := p.files.openDir(proc.fd(), selfPID)
	if err != nil {
		return err
	}
	defer func() { p.closed(self.Close()) }()
	p.net, err = p.files.openDir(self.fd(), "net")
	return err
}
func (p *socketHelperProvider) OpenServices(context.Context, ServiceSource) (io.ReadCloser, error) {
	return nil, ErrInvalidInput // No service/command path exists in this provider.
}
func (p *socketHelperProvider) OpenSockets(ctx context.Context, kind SocketSource) (io.ReadCloser, error) {
	switch kind {
	case TCP4Source, TCP6Source, UDP4Source, UDP6Source:
	default:
		return nil, ErrInvalidInput
	}
	if err := p.initProc(ctx); err != nil {
		return nil, err
	}
	r, err := p.files.openFile(p.net.fd(), string(kind))
	if err != nil {
		return nil, err
	}
	return &socketHelperReader{ReadCloser: r, p: p, ctx: ctx}, nil
}
func (p *socketHelperProvider) Attribute(ctx context.Context, inodes []uint64) (map[uint64]AttributionResult, error) {
	if err := p.initProc(ctx); err != nil {
		return nil, err
	}
	return attributeOwners(ctx, inodes, socketHelperOwners{p, ctx})
}
func (p *socketHelperProvider) Close() error {
	if p.net != nil {
		p.closed(p.net.Close())
		p.net = nil
	}
	if p.proc != nil {
		p.closed(p.proc.Close())
		p.proc = nil
	}
	return p.closeErr
}

// Every userspace read is bounded too. This does not bound fdinfo's kernel
// seq_file generation or make a blocked filesystem syscall cancellable.
type socketHelperReader struct {
	io.ReadCloser
	p   *socketHelperProvider
	ctx context.Context
}

func (r *socketHelperReader) Read(b []byte) (int, error) {
	if err := r.p.guard.check(r.ctx); err != nil {
		return 0, err
	}
	if len(b) > 16<<10 {
		b = b[:16<<10]
	}
	return r.ReadCloser.Read(b)
}
func (r *socketHelperReader) Close() error { err := r.ReadCloser.Close(); r.p.closed(err); return err }

type socketHelperOwners struct {
	p   *socketHelperProvider
	ctx context.Context
}

func (s socketHelperOwners) openProcesses() (ownerEntries, error) {
	if err := s.p.guard.check(s.ctx); err != nil {
		return nil, err
	}
	d, err := s.p.files.openDir(s.p.proc.fd(), ".")
	if err != nil {
		return nil, err
	}
	return &socketHelperEntries{socketHelperDir: d, p: s.p, ctx: s.ctx}, nil
}
func (s socketHelperOwners) openProcess(pid uint32) (ownerProcess, error) {
	if err := s.p.guard.check(s.ctx); err != nil {
		return nil, err
	}
	name := strconv.FormatUint(uint64(pid), 10)
	if _, ok := numericPID(name); !ok {
		return nil, ErrInvalidInput
	}
	d, err := s.p.files.openDir(s.p.proc.fd(), name)
	if err != nil {
		return nil, err
	}
	return &socketHelperProcess{socketHelperEntries{d, s.p, s.ctx}}, nil
}

type socketHelperEntries struct {
	socketHelperDir
	p   *socketHelperProvider
	ctx context.Context
}

func (d *socketHelperEntries) Readdirnames(n int) ([]string, error) {
	if err := d.p.guard.check(d.ctx); err != nil {
		return nil, err
	}
	if n <= 0 || n > 128 {
		return nil, ErrInvalidInput
	}
	return d.socketHelperDir.Readdirnames(n)
}
func (d *socketHelperEntries) Close() error {
	err := d.socketHelperDir.Close()
	d.p.closed(err)
	return err
}

type socketHelperProcess struct{ socketHelperEntries }

func (p *socketHelperProcess) openFDs() (ownerFDs, error) {
	if err := p.p.guard.check(p.ctx); err != nil {
		return nil, err
	}
	d, err := p.p.files.openDir(p.fd(), "fdinfo")
	if err != nil {
		return nil, err
	}
	return &socketHelperFDs{socketHelperEntries{d, p.p, p.ctx}}, nil
}
func (p *socketHelperProcess) openComm() (io.ReadCloser, error) {
	if err := p.p.guard.check(p.ctx); err != nil {
		return nil, err
	}
	r, err := p.p.files.openFile(p.fd(), "comm")
	if err != nil {
		return nil, err
	}
	return &socketHelperReader{r, p.p, p.ctx}, nil
}

type socketHelperFDs struct{ socketHelperEntries }

func (f *socketHelperFDs) socketInode(name string) (inode uint64, socket bool, err error) {
	// Readdirnames guarded this batch of at most 128 entries. Per-header
	// context checks avoid repeating expensive authority verification per byte.
	if err = f.ctx.Err(); err != nil {
		return 0, false, err
	}
	if f.p.guard.failed != nil {
		return 0, false, f.p.guard.failed
	}
	n, e := strconv.ParseUint(name, 10, 31)
	if e != nil || strconv.FormatUint(n, 10) != name {
		return 0, false, ErrInvalidSource
	}
	r, err := f.p.files.openFile(f.fd(), name)
	if err != nil {
		return 0, false, err
	}
	defer func() {
		if e := r.Close(); e != nil {
			f.p.closed(e)
			inode, socket, err = 0, false, SourceError{ReasonReadFailed}
		}
	}()
	// Header parser reads single bytes with context checks, no suffix or read-ahead.
	// The mount comes exclusively from the pinned validated listener descriptor.
	return parseSocketFDInfo(f.ctx, r, f.p.witness.mount)
}

// Syscall seams below are injected by tests. Tests never invoke native factories.
type socketHelperWitnessOps struct {
	fstat      func(int, *unix.Stat_t) error
	fstatfs    func(int, *unix.Statfs_t) error
	getsockopt func(int, int, int) (int, error)
	statx      func(int, string, int, int, *unix.Statx_t) error
	close      func(int) error
}

func nativeSocketHelperWitnessOps() socketHelperWitnessOps {
	return socketHelperWitnessOps{unix.Fstat, unix.Fstatfs, unix.GetsockoptInt, unix.Statx, unix.Close}
}
func pinSocketHelperWitness(duplicate func() (int, error), ops socketHelperWitnessOps) (w *socketHelperWitness, err error) {
	fd, err := duplicate()
	if err != nil {
		return nil, err
	}
	if fd < 0 {
		return nil, ErrInvalidSource
	}
	defer func() {
		if w == nil {
			_ = ops.close(fd)
		}
	}()
	var st unix.Stat_t
	var fs unix.Statfs_t
	if ops.fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Ino == 0 || ops.fstatfs(fd, &fs) != nil || fs.Type != unix.SOCKFS_MAGIC {
		return nil, ErrInvalidSource
	}
	for _, check := range [][2]int{{unix.SO_DOMAIN, unix.AF_UNIX}, {unix.SO_TYPE, unix.SOCK_STREAM}, {unix.SO_ACCEPTCONN, 1}} {
		got, e := ops.getsockopt(fd, unix.SOL_SOCKET, check[0])
		if e != nil || got != check[1] {
			return nil, ErrInvalidSource
		}
	}
	var sx unix.Statx_t
	const mask = unix.STATX_INO | unix.STATX_MNT_ID | unix.STATX_TYPE
	if e := ops.statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, mask, &sx); e != nil {
		if errors.Is(e, unix.ENOSYS) || errors.Is(e, unix.EINVAL) || errors.Is(e, unix.EOPNOTSUPP) {
			return nil, SourceError{ReasonNotSupported}
		}
		return nil, ErrInvalidSource
	}
	if sx.Mask&mask != mask {
		return nil, SourceError{ReasonNotSupported}
	}
	if sx.Ino != st.Ino || sx.Mode&unix.S_IFMT != unix.S_IFSOCK || unix.Mkdev(sx.Dev_major, sx.Dev_minor) != uint64(st.Dev) || sx.Mnt_id == 0 || sx.Mnt_id > 1<<31-1 {
		return nil, ErrInvalidSource
	}
	return &socketHelperWitness{mount: sx.Mnt_id, inode: sx.Ino, close: func() error { return ops.close(fd) }}, nil
}

type socketHelperIdentityOps struct {
	uids   func() (int, int, int)
	gids   func() (int, int, int)
	groups func() ([]int, error)
	capget func(*unix.CapUserHeader, *unix.CapUserData) error
	prctl  func(int, uintptr, uintptr, uintptr, uintptr) (int, error)
}

func nativeSocketHelperIdentityOps() socketHelperIdentityOps {
	return socketHelperIdentityOps{unix.Getresuid, unix.Getresgid, unix.Getgroups, unix.Capget, unix.PrctlRetInt}
}
func verifySocketHelperIdentity(ops socketHelperIdentityOps) error {
	denied := SourceError{ReasonPermissionDenied}
	r, e, s := ops.uids()
	if r <= 0 || r != e || r != s {
		return denied
	}
	r, e, s = ops.gids()
	if r <= 0 || r != e || r != s {
		return denied
	}
	groups, err := ops.groups()
	if err != nil || len(groups) > 1 || len(groups) == 1 && groups[0] != r {
		return denied
	}
	data := [2]unix.CapUserData{}
	h := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if ops.capget(&h, &data[0]) != nil || h.Version != unix.LINUX_CAPABILITY_VERSION_3 {
		return denied
	}
	const ptrace = uint32(1 << unix.CAP_SYS_PTRACE)
	if data[0] != (unix.CapUserData{Effective: ptrace, Permitted: ptrace, Inheritable: ptrace}) || data[1] != (unix.CapUserData{}) {
		return denied
	}
	// Query the contiguous kernel capability range rather than assuming this
	// build's CAP_LAST_CAP. A larger-than-64-bit capability ABI is unsupported.
	for cap := 0; cap <= 64; cap++ {
		bound, err := ops.prctl(unix.PR_CAPBSET_READ, uintptr(cap), 0, 0, 0)
		if errors.Is(err, unix.EINVAL) && cap > unix.CAP_SYS_PTRACE {
			return nil
		}
		if err != nil || cap == 64 {
			return denied
		}
		ambient, err := ops.prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(cap), 0, 0)
		want := 0
		if cap == unix.CAP_SYS_PTRACE {
			want = 1
		}
		if err != nil || bound != want || ambient != want {
			return denied
		}
	}
	return denied
}
