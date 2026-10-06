//go:build linux

package systeminventory

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// This implementation is intentionally not called by tests. Only Collect
// constructs it, after external runtime consent; no package init touches hosts.
type linuxProvider struct {
	proc *os.File
	net  *os.File
}

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
const readFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK

func newSystemProvider() (Provider, error) {
	if os.Geteuid() == 0 {
		return nil, SourceError{ReasonPermissionDenied}
	}
	return &linuxProvider{}, nil
}

func (p *linuxProvider) initProc() error {
	if p.proc != nil && p.net != nil {
		return nil
	}
	proc, e := openProcDir(-1, "/proc")
	if e != nil {
		return e
	}
	// A pinned proc mount can use a different PID namespace than Getpid.
	// Resolve only its documented net/self links, then open the exact numeric
	// self child with no-follow/procfs checks; never substitute caller Getpid.
	selfPID, e := resolveProcSelf(func(name string, target []byte) (int, error) {
		return unix.Readlinkat(int(proc.Fd()), name, target)
	})
	if e != nil {
		proc.Close()
		return e
	}
	self, e := openProcDir(int(proc.Fd()), selfPID)
	if e != nil {
		proc.Close()
		return e
	}
	net, e := openProcDir(int(self.Fd()), "net")
	self.Close()
	if e != nil {
		proc.Close()
		return e
	}
	p.proc, p.net = proc, net
	return nil
}

// resolveProcSelf is a bounded pure injection seam for proc-mount PID
// resolution. It admits only the fixed net/self link names and canonical PID
// text, never arbitrary link traversal or a process-global Getpid fallback.
func resolveProcSelf(readlink func(string, []byte) (int, error)) (string, error) {
	if readlink == nil {
		return "", ErrInvalidInput
	}
	var target [64]byte
	n, err := readlink("net", target[:])
	if err != nil {
		return "", osFailure(err)
	}
	if n <= 0 || n >= len(target) || string(target[:n]) != "self/net" {
		return "", SourceError{ReasonInvalidSource}
	}
	n, err = readlink("self", target[:])
	if err != nil {
		return "", osFailure(err)
	}
	if n <= 0 || n >= len(target) {
		return "", SourceError{ReasonInvalidSource}
	}
	pid := string(target[:n])
	if _, ok := numericPID(pid); !ok {
		return "", SourceError{ReasonInvalidSource}
	}
	return pid, nil
}

func openProcDir(parent int, name string) (*os.File, error) {
	var fd int
	var e error
	if parent < 0 {
		fd, e = unix.Open(name, dirFlags, 0)
	} else {
		fd, e = unix.Openat(parent, name, dirFlags, 0)
	}
	if e != nil {
		return nil, osFailure(e)
	}
	var fs unix.Statfs_t
	if e = unix.Fstatfs(fd, &fs); e != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		unix.Close(fd)
		return nil, SourceError{ReasonInvalidSource}
	}
	return os.NewFile(uintptr(fd), "proc-source"), nil
}
func openProcFile(parent int, name string) (*os.File, error) {
	fd, e := unix.Openat(parent, name, readFlags, 0)
	if e != nil {
		return nil, osFailure(e)
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		unix.Close(fd)
		return nil, SourceError{ReasonInvalidSource}
	}
	return os.NewFile(uintptr(fd), "proc-source"), nil
}
func (p *linuxProvider) Close() error {
	var a, b error
	if p.net != nil {
		a = p.net.Close()
	}
	if p.proc != nil {
		b = p.proc.Close()
	}
	if a != nil || b != nil {
		return SourceError{ReasonReadFailed}
	}
	return nil
}
func (p *linuxProvider) OpenSockets(ctx context.Context, kind SocketSource) (io.ReadCloser, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	switch kind {
	case TCP4Source, TCP6Source, UDP4Source, UDP6Source:
	default:
		return nil, ErrInvalidInput
	}
	if err := p.initProc(); err != nil {
		return nil, err
	}
	return openProcFile(int(p.net.Fd()), string(kind))
}
func serviceArgs(kind ServiceSource) ([]string, error) {
	args := []string{"--system", "--no-pager", "--no-ask-password", "--all", "--type=service", "--full", "--plain", "--no-legend"}
	switch kind {
	case RuntimeSource:
		return append(args, "list-units"), nil
	case UnitFilesSource:
		return append(args, "list-unit-files"), nil
	default:
		return nil, ErrInvalidInput
	}
}
func commandEnv() []string {
	return []string{"LC_ALL=C", "LANG=C", "TZ=UTC", "SYSTEMD_COLORS=0", "SYSTEMD_URLIFY=0", "SYSTEMD_PAGERSECURE=1"}
}
func (p *linuxProvider) OpenServices(parent context.Context, kind ServiceSource) (io.ReadCloser, error) {
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	args, e := serviceArgs(kind)
	if e != nil {
		return nil, e
	}
	tool, e := openSystemctl()
	if e != nil {
		return nil, e
	}
	defer tool.Close()
	ctx, cancel := context.WithTimeout(parent, CommandTimeout)
	defer cancel()
	// The descriptor is passed explicitly as child fd 3 and executed directly.
	// No PATH search, shell, inherited loader/proxy variables or authorization agent.
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{tool}
	cmd.Env = commandEnv()
	cmd.WaitDelay = time.Second
	stdout := &limitedBuffer{limit: MaxRawSourceBytes}
	stderr := &discardBounded{limit: 64 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	e = cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if stdout.exceeded || stderr.exceeded {
		return nil, SourceError{ReasonByteLimit}
	}
	if e != nil || stderr.seen != 0 {
		return nil, SourceError{ReasonReadFailed}
	}
	return io.NopCloser(bytes.NewReader(stdout.Bytes())), nil
}
func openSystemctl() (*os.File, error) {
	// Pin and verify root-owned, non-writable ancestors then the final executable;
	// a rename after checks cannot substitute a different executable inode.
	fd, e := unix.Open("/", dirFlags, 0)
	if e != nil {
		return nil, osFailure(e)
	}
	for _, name := range []string{"", "usr", "bin"} {
		if name != "" {
			next, err := unix.Openat(fd, name, dirFlags, 0)
			unix.Close(fd)
			if err != nil {
				return nil, osFailure(err)
			}
			fd = next
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			unix.Close(fd)
			return nil, SourceError{ReasonInvalidSource}
		}
	}
	tool, e := unix.Openat(fd, "systemctl", readFlags, 0)
	unix.Close(fd)
	if e != nil {
		return nil, osFailure(e)
	}
	var st unix.Stat_t
	var magic [4]byte
	n, readErr := unix.Pread(tool, magic[:], 0)
	capBytes, capErr := unix.Fgetxattr(tool, "security.capability", nil)
	capSafe := noFileCapabilities(capBytes, capErr)
	if unix.Fstat(tool, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 || !capSafe || st.Mode&0111 == 0 || readErr != nil || n != 4 || magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		unix.Close(tool)
		return nil, SourceError{ReasonInvalidSource}
	}
	return os.NewFile(uintptr(tool), "systemctl"), nil
}

// noFileCapabilities checks errors before the returned size: Linux Fgetxattr
// returns size -1 with ENODATA when the attribute is absent. EOPNOTSUPP means
// the filesystem does not support it. Only a successful zero size or these
// absence results are safe; present capabilities and all other errors fail closed.
func noFileCapabilities(size int, err error) bool {
	if err != nil {
		return errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP)
	}
	return size == 0
}

type limitedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.exceeded = true
		return 0, ErrSourceLimit
	}
	return b.Buffer.Write(p)
}

type discardBounded struct {
	limit    int
	seen     int
	exceeded bool
}

func (b *discardBounded) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.seen {
		b.exceeded = true
		return 0, ErrSourceLimit
	}
	b.seen += len(p)
	return len(p), nil
}
func osFailure(e error) error {
	switch {
	case errors.Is(e, unix.EACCES), errors.Is(e, unix.EPERM):
		return SourceError{ReasonPermissionDenied}
	case errors.Is(e, unix.ENOENT), errors.Is(e, unix.ENOTDIR):
		return SourceError{ReasonSourceMissing}
	case errors.Is(e, unix.ELOOP):
		return SourceError{ReasonInvalidSource}
	default:
		return SourceError{ReasonReadFailed}
	}
}

// Attribute scans only numeric agent-visible /proc PID/fd entries, one process
// at a time. The source seam changes no production permission or source path.
func (p *linuxProvider) Attribute(ctx context.Context, inodes []uint64) (map[uint64]AttributionResult, error) {
	if err := p.initProc(); err != nil {
		return nil, err
	}
	return attributeOwners(ctx, inodes, procOwnerSource{p.proc})
}

type procOwnerSource struct{ proc *os.File }

func (s procOwnerSource) openProcesses() (ownerEntries, error) {
	return openProcDir(int(s.proc.Fd()), ".")
}
func (s procOwnerSource) openProcess(pid uint32) (ownerProcess, error) {
	process, err := openProcDir(int(s.proc.Fd()), strconv.FormatUint(uint64(pid), 10))
	if err != nil {
		return nil, err
	}
	return procOwnerProcess{process}, nil
}

type procOwnerProcess struct{ *os.File }

func (p procOwnerProcess) openFDs() (ownerFDs, error) {
	fds, err := openProcDir(int(p.Fd()), "fd")
	if err != nil {
		return nil, err
	}
	return procOwnerFDs{fds}, nil
}
func (p procOwnerProcess) openComm() (io.ReadCloser, error) {
	return openProcFile(int(p.Fd()), "comm")
}

type procOwnerFDs struct{ *os.File }

func (f procOwnerFDs) socketInode(name string) (uint64, bool, error) {
	// Never follow/open an FD target. Non-socket link text is discarded locally.
	var target [128]byte
	n, err := unix.Readlinkat(int(f.Fd()), name, target[:])
	if err != nil {
		return 0, false, osFailure(err)
	}
	if n == len(target) {
		return 0, false, nil
	}
	text := string(target[:n])
	if !strings.HasPrefix(text, "socket:[") || !strings.HasSuffix(text, "]") {
		return 0, false, nil
	}
	inode, err := strconv.ParseUint(text[8:len(text)-1], 10, 64)
	if err != nil {
		return 0, true, ErrInvalidSource
	}
	return inode, true, nil
}
