//go:build linux

package journalview

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

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
const readFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
const maxStderrBytes = 8 << 10

type journalRunner func(context.Context, *os.File, []string, []string, io.Writer, io.Writer) error
type linuxProvider struct {
	uid      func() int
	euid     func() int
	openTool func() (*os.File, error)
	run      journalRunner
}

func newSystemProvider() (Provider, error) {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return nil, SourceError{ReasonPermissionDenied}
	}
	return &linuxProvider{os.Getuid, os.Geteuid, openJournalctl, runJournalctl}, nil
}
func journalArgs(q Query) ([]string, error) {
	// Use End as a deterministic validation anchor here; Collect additionally
	// validates against trusted now before touching any provider.
	if ValidateQuery(q, q.End) != nil {
		return nil, ErrInvalidInput
	}
	return []string{"--system", "--no-pager", "--utc", "--all", "--output=json", "--output-fields=__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,_PID,_UID,UNIT,PRIORITY,MESSAGE",
		"--since=@" + journalTime(q.Start), "--until=@" + journalTime(q.End), "--priority=0.." + strconv.Itoa(q.MaxPriority), "--", "_SYSTEMD_UNIT=" + q.Unit, "+", "_PID=1", "_UID=0", "UNIT=" + q.Unit}, nil
}
func journalTime(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10) + "." + t.Format(".000000")[1:]
}
func commandEnv() []string {
	return []string{"LC_ALL=C", "LANG=C", "TZ=UTC", "SYSTEMD_COLORS=0", "SYSTEMD_URLIFY=0", "SYSTEMD_PAGERSECURE=1"}
}
func (p *linuxProvider) Open(parent context.Context, q Query) (io.ReadCloser, Reason, error) {
	if parent == nil || p == nil || p.uid == nil || p.euid == nil || p.openTool == nil || p.run == nil {
		return nil, ReasonNone, ErrInvalidInput
	}
	if parent.Err() != nil {
		return nil, ReasonNone, parent.Err()
	}
	if p.uid() == 0 || p.euid() == 0 {
		return nil, ReasonNone, SourceError{ReasonPermissionDenied}
	}
	args, err := journalArgs(q)
	if err != nil {
		return nil, ReasonNone, err
	}
	tool, err := p.openTool()
	if err != nil {
		return nil, ReasonNone, err
	}
	if tool == nil {
		return nil, ReasonNone, SourceError{ReasonInvalidSource}
	}
	defer tool.Close()
	ctx, cancel := context.WithTimeout(parent, CommandTimeout)
	defer cancel()
	stdout := &boundedBuffer{limit: MaxRawBytes}
	stderr := &boundedBuffer{limit: maxStderrBytes}
	err = p.run(ctx, tool, args, commandEnv(), stdout, stderr)
	if ctx.Err() != nil {
		return nil, ReasonNone, ctx.Err()
	}
	if stdout.exceeded || stderr.exceeded {
		return io.NopCloser(bytes.NewReader(stdout.Bytes())), ReasonByteLimit, nil
	}
	if err != nil {
		// C locale, fixed diagnostic only; no raw diagnostic text leaves here.
		if strings.Contains(stderr.String(), "No journal files were opened due to insufficient permissions") || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return nil, ReasonNone, SourceError{ReasonPermissionDenied}
		}
		return nil, ReasonNone, SourceError{ReasonReadFailed}
	}
	reason := ReasonNone
	// Any successful diagnostic makes visibility uncertain. In particular,
	// journalctl may exit 0 despite access to only a subset of system journals.
	if stderr.Len() != 0 {
		reason = ReasonVisibilityRestricted
	}
	return io.NopCloser(bytes.NewReader(stdout.Bytes())), reason, nil
}
func runJournalctl(ctx context.Context, tool *os.File, args, env []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{tool}
	cmd.Env = env
	cmd.Stdin = nil // closed input; no pager, privilege helper, shell or prompt agent
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = time.Second
	return cmd.Run()
}
func openJournalctl() (*os.File, error) {
	// Fixed trusted path and pinned inode. Symlinks, writable ancestors,
	// set-id executables, file capabilities and non-ELF payloads fail closed.
	fd, err := unix.Open("/", dirFlags, 0)
	if err != nil {
		return nil, osFailure(err)
	}
	for _, name := range []string{"", "usr", "bin"} {
		if name != "" {
			next, e := unix.Openat(fd, name, dirFlags, 0)
			unix.Close(fd)
			if e != nil {
				return nil, osFailure(e)
			}
			fd = next
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || !safeDirectory(st.Uid, st.Mode) {
			unix.Close(fd)
			return nil, SourceError{ReasonInvalidSource}
		}
	}
	fdTool, err := unix.Openat(fd, "journalctl", readFlags, 0)
	unix.Close(fd)
	if err != nil {
		return nil, osFailure(err)
	}
	var st unix.Stat_t
	var magic [4]byte
	n, readErr := unix.Pread(fdTool, magic[:], 0)
	capBytes, capErr := unix.Fgetxattr(fdTool, "security.capability", nil)
	if unix.Fstat(fdTool, &st) != nil || !safeExecutable(st.Uid, st.Mode, magic, n, readErr, capBytes, capErr) {
		unix.Close(fdTool)
		return nil, SourceError{ReasonInvalidSource}
	}
	return os.NewFile(uintptr(fdTool), "journalctl"), nil
}
func safeDirectory(uid uint32, mode uint32) bool {
	return uid == 0 && mode&unix.S_IFMT == unix.S_IFDIR && mode&0022 == 0
}
func safeExecutable(uid uint32, mode uint32, magic [4]byte, n int, readErr error, capBytes int, capErr error) bool {
	return uid == 0 && mode&unix.S_IFMT == unix.S_IFREG && mode&0022 == 0 && mode&(unix.S_ISUID|unix.S_ISGID) == 0 && mode&0111 != 0 && n == 4 && readErr == nil && magic == [4]byte{0x7f, 'E', 'L', 'F'} && noFileCapabilities(capBytes, capErr)
}
func noFileCapabilities(size int, err error) bool {
	if err != nil {
		return errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP)
	}
	return size == 0
}
func osFailure(err error) error {
	switch {
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return SourceError{ReasonPermissionDenied}
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR):
		return SourceError{ReasonSourceMissing}
	case errors.Is(err, unix.ELOOP):
		return SourceError{ReasonInvalidSource}
	default:
		return SourceError{ReasonReadFailed}
	}
}

// Retain only the bounded prefix before copying; reject the remainder. A runner
// error stops the command synchronously or its four-second context kills it.
type boundedBuffer struct {
	data     []byte
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Len() int       { return len(b.data) }
func (b *boundedBuffer) Bytes() []byte  { return b.data }
func (b *boundedBuffer) String() string { return string(b.data) }
func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if n > b.limit-len(b.data) {
		n = b.limit - len(b.data)
		b.exceeded = true
	}
	if n > 0 {
		// A fixed capacity prevents bytes.Buffer's geometric growth exceeding the
		// raw-output ceiling even for adversarial chunk sizes.
		if b.data == nil {
			b.data = make([]byte, 0, b.limit)
		}
		b.data = append(b.data, p[:n]...)
	}
	if b.exceeded {
		return n, ErrSourceLimit
	}
	return n, nil
}
