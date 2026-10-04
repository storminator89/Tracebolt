//go:build linux

package completeoverview

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type linuxProvider struct {
	proc, self  *os.File
	sourceBytes int
}

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK

// resolveCached is RESOLVE_CACHED from Linux UAPI linux/openat2.h.
// The pinned x/sys release exposes OpenHow but omits this constant.
const resolveCached = 0x20

const readFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK

// This factory is deliberately never called by fixture tests.
func newProvider() (Provider, error) {
	if os.Geteuid() == 0 {
		return nil, SourceError{ReasonPermissionDenied}
	}
	return &linuxProvider{}, nil
}
func (p *linuxProvider) initProc() error {
	if p.proc != nil && p.self != nil {
		return nil
	}
	proc, e := openProcDir(-1, "/proc")
	if e != nil {
		return e
	}
	pid, e := resolveProcSelf(func(dst []byte) (int, error) { return unix.Readlinkat(int(proc.Fd()), "self", dst) })
	if e != nil {
		proc.Close()
		return e
	}
	self, e := openProcDir(int(proc.Fd()), pid)
	if e != nil {
		proc.Close()
		return e
	}
	p.proc, p.self = proc, self
	return nil
}

// Only a canonical numeric self link from the pinned proc mount is admitted.
// os.Getpid is never a fallback: the proc mount may name another PID namespace.
func resolveProcSelf(readlink func([]byte) (int, error)) (string, error) {
	if readlink == nil {
		return "", ErrInvalidInput
	}
	var b [64]byte
	n, e := readlink(b[:])
	if e != nil {
		return "", osFailure(e)
	}
	if n <= 0 || n >= len(b) {
		return "", ErrInvalidSource
	}
	s := string(b[:n])
	if _, ok := numericPID(s); !ok {
		return "", ErrInvalidSource
	}
	return s, nil
}
func openProcDir(parent int, name string) (*os.File, error)  { return openProc(parent, name, true) }
func openProcFile(parent int, name string) (*os.File, error) { return openProc(parent, name, false) }
func openProc(parent int, name string, dir bool) (*os.File, error) {
	flags := readFlags
	if dir {
		flags = dirFlags
	}
	var fd int
	var e error
	if parent < 0 {
		fd, e = unix.Open(name, flags, 0)
	} else {
		fd, e = unix.Openat(parent, name, flags, 0)
	}
	if e != nil {
		return nil, osFailure(e)
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	mode := uint32(unix.S_IFREG)
	if dir {
		mode = unix.S_IFDIR
	}
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != mode || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		unix.Close(fd)
		return nil, ErrInvalidSource
	}
	return os.NewFile(uintptr(fd), "complete-overview-proc"), nil
}
func (p *linuxProvider) Close() error {
	var e1, e2 error
	if p.self != nil {
		e1 = p.self.Close()
		p.self = nil
	}
	if p.proc != nil {
		e2 = p.proc.Close()
		p.proc = nil
	}
	if e1 != nil || e2 != nil {
		return SourceError{ReasonReadFailed}
	}
	return nil
}
func (p *linuxProvider) EnumeratePIDs(ctx context.Context, visit func(uint32) error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if visit == nil {
		return ErrInvalidInput
	}
	if e := p.initProc(); e != nil {
		return e
	}
	entries := 0
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		names, e := p.proc.Readdirnames(256)
		entries += len(names)
		if entries > MaxDirectoryEntries {
			return ErrItemLimit
		}
		for _, name := range names {
			if pid, ok := numericPID(name); ok {
				if e := visit(pid); e != nil {
					return e
				}
			}
		}
		if errors.Is(e, io.EOF) {
			return nil
		}
		if e != nil {
			return osFailure(e)
		}
	}
}
func (p *linuxProvider) ProcessUnits(ctx context.Context) (uint64, uint64, error) {
	if ctx.Err() != nil {
		return 0, 0, ctx.Err()
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return 0, 0, SourceError{ReasonNotSupported}
	}
	return uint64(os.Getpagesize()), 100, nil
}
func (p *linuxProvider) OpenProcessStat(ctx context.Context, pid uint32) (io.ReadCloser, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if pid == 0 || pid > 2147483647 {
		return nil, ErrInvalidInput
	}
	if e := p.initProc(); e != nil {
		return nil, e
	}
	dir, e := openProcDir(int(p.proc.Fd()), strconv.FormatUint(uint64(pid), 10))
	if e != nil {
		return nil, processFailure(e)
	}
	defer dir.Close()
	f, e := openProcFile(int(dir.Fd()), "stat")
	if e != nil {
		return nil, processFailure(e)
	}
	return &countedReader{ReadCloser: f, owner: p}, nil
}
func processFailure(e error) error {
	var se SourceError
	if errors.As(e, &se) && se.Reason == ReasonSourceMissing {
		return SourceError{ReasonProcessGone}
	}
	return e
}
func (p *linuxProvider) OpenMountInfo(ctx context.Context) (io.ReadCloser, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if e := p.initProc(); e != nil {
		return nil, e
	}
	f, e := openProcFile(int(p.self.Fd()), "mountinfo")
	if e != nil {
		return nil, e
	}
	return &countedReader{ReadCloser: f, owner: p}, nil
}
func (p *linuxProvider) currentMounts(ctx context.Context) ([]MountRecord, error) {
	r, e := p.OpenMountInfo(ctx)
	if e != nil {
		return nil, e
	}
	raw, e := readBounded(ctx, r, MaxMountInfoBytes)
	ce := r.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return nil, e
	}
	return parseMountBytes(ctx, raw)
}

// descriptorBudget leaves a fixed reserve below the existing soft limit. It
// never raises any process limit. Unrelated existing descriptors can still make
// open fail; that rejects the whole measurement operation, never a prefix.
func descriptorBudget(soft uint64) int {
	if soft <= DescriptorReserve {
		return 0
	}
	return int(min(uint64(MaxPinnedMounts), soft-DescriptorReserve))
}
func blockedMountPaths(mounts []MountRecord) map[string]bool {
	blocked := map[string]bool{}
	for _, m := range mounts {
		if k := mountKind(m.Filesystem); k == "remote" || k == "unknown" || m.Filesystem == "autofs" {
			blocked[m.MountPoint] = true
		}
	}
	return blocked
}
func safeMountPath(point string, blocked map[string]bool) bool {
	for {
		if blocked[point] {
			return false
		}
		if point == "/" {
			return true
		}
		i := strings.LastIndexByte(point, '/')
		if i <= 0 {
			point = "/"
		} else {
			point = point[:i]
		}
	}
}
func sameMounts(a, b []MountRecord) bool {
	if len(a) != len(b) {
		return false
	}
	index := make(map[uint32]MountRecord, len(a))
	for _, m := range a {
		index[m.MountID] = m
	}
	for _, m := range b {
		if index[m.MountID] != m {
			return false
		}
	}
	return true
}
func statxMatches(st unix.Statx_t, m MountRecord) bool {
	return st.Mask&unix.STATX_MNT_ID != 0 && st.Mnt_id == uint64(m.MountID) && st.Dev_major == m.Major && st.Dev_minor == m.Minor && (st.Mode&unix.S_IFMT == unix.S_IFDIR || st.Mode&unix.S_IFMT == unix.S_IFREG)
}
func pinMount(root int, m MountRecord) (int, error) {
	name := strings.TrimPrefix(m.MountPoint, "/")
	if name == "" {
		name = "."
	}
	// RESOLVE_CACHED forbids network/filesystem lookup I/O, including a mount-race
	// substitution during traversal. No fallback removes this guard. NO_SYMLINKS
	// excludes every component, not just the final target; no autofs traversal.
	fd, e := unix.Openat2(root, name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | resolveCached})
	if e != nil {
		if errors.Is(e, unix.ENOSYS) || errors.Is(e, unix.EINVAL) {
			return -1, SourceError{ReasonNotSupported}
		}
		return -1, osFailure(e)
	}
	var st unix.Statx_t
	e = unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT|unix.AT_STATX_DONT_SYNC, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID, &st)
	if e != nil {
		unix.Close(fd)
		return -1, osFailure(e)
	}
	if !statxMatches(st, m) {
		unix.Close(fd)
		return -1, SourceError{ReasonMountChanged}
	}
	return fd, nil
}
func (p *linuxProvider) MeasureMounts(ctx context.Context, mounts []MountRecord) ([]MountMeasurement, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(mounts) > MaxVolumeRows {
		return nil, ErrItemLimit
	}
	count := 0
	for _, m := range mounts {
		if k := mountKind(m.Filesystem); k == "local" || k == "memory" {
			count++
		}
	}
	var lim unix.Rlimit
	if e := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); e != nil {
		return nil, osFailure(e)
	}
	if count > descriptorBudget(lim.Cur) {
		return nil, ErrItemLimit
	}
	root, e := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, osFailure(e)
	}
	defer unix.Close(root)
	type pinned struct {
		index int
		fd    int
	}
	pins := []pinned{}
	defer func() {
		for _, p := range pins {
			unix.Close(p.fd)
		}
	}()
	rows := make([]MountMeasurement, 0, count)
	blocked := blockedMountPaths(mounts)
	for _, m := range mounts {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		k := mountKind(m.Filesystem)
		if k != "local" && k != "memory" {
			continue
		}
		row := MountMeasurement{MountID: m.MountID}
		if !safeMountPath(m.MountPoint, blocked) {
			row.Observation = Observation{Unsupported, ReasonNotSupported}
			rows = append(rows, row)
			continue
		}
		fd, e := pinMount(root, m)
		if errors.Is(e, ErrItemLimit) {
			return nil, ErrItemLimit
		}
		if e != nil {
			row.Observation = missingObservation(e, false)
		} else {
			pins = append(pins, pinned{len(rows), fd})
		}
		rows = append(rows, row)
	}
	current, e := p.currentMounts(ctx)
	if e != nil {
		return nil, e
	}
	if !sameMounts(mounts, current) {
		return nil, SourceError{ReasonMountChanged}
	}
	for _, pin := range pins {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var st unix.Statfs_t
		e := unix.Fstatfs(pin.fd, &st)
		row := &rows[pin.index]
		if e != nil {
			row.Observation = missingObservation(osFailure(e), false)
			continue
		}
		if st.Bsize <= 0 || st.Blocks > MaxSafeInteger/uint64(st.Bsize) || st.Bavail > st.Blocks {
			row.Observation = Observation{Invalid, ReasonInvalidSource}
			continue
		}
		row.Capacity = &Capacity{st.Blocks * uint64(st.Bsize), st.Bavail * uint64(st.Bsize)}
		row.Observation = Observation{Observed, ReasonNone}
	}
	final, e := p.currentMounts(ctx)
	if e != nil {
		return nil, e
	}
	if !sameMounts(mounts, final) {
		return nil, SourceError{ReasonMountChanged}
	}
	return rows, nil
}
func osFailure(e error) error {
	if e == nil {
		return nil
	}
	switch {
	case errors.Is(e, os.ErrPermission):
		return SourceError{ReasonPermissionDenied}
	case errors.Is(e, os.ErrNotExist), errors.Is(e, unix.ESRCH):
		return SourceError{ReasonSourceMissing}
	case errors.Is(e, unix.ELOOP), errors.Is(e, unix.ENOTDIR):
		return ErrInvalidSource
	case errors.Is(e, unix.EMFILE), errors.Is(e, unix.ENFILE):
		return ErrItemLimit
	default:
		return SourceError{ReasonReadFailed}
	}
}

// Every production proc read, including both coherence rechecks, shares one
// capture-local byte budget. The collector also bounds each individual source.
type countedReader struct {
	io.ReadCloser
	owner *linuxProvider
}

func (r *countedReader) Read(b []byte) (int, error) {
	if r.owner.sourceBytes >= MaxSourceBytes {
		var probe [1]byte
		n, e := r.ReadCloser.Read(probe[:])
		if n != 0 {
			return 0, ErrSourceLimit
		}
		return 0, e
	}
	b = b[:min(len(b), MaxSourceBytes-r.owner.sourceBytes+1)]
	n, e := r.ReadCloser.Read(b)
	r.owner.sourceBytes += n
	if r.owner.sourceBytes > MaxSourceBytes {
		return n, ErrSourceLimit
	}
	return n, e
}
