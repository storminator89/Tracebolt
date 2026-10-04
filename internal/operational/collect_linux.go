//go:build linux

package operational

import (
	"bytes"
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"localrmm/internal/assessment"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func collectPlatform(ctx context.Context, now time.Time) Snapshot {
	s := Empty(now, ReasonNotImplemented)
	s.Sections.Volumes = collectVolumes(ctx, now)
	s.Sections.Network = collectNetwork(ctx, now)
	s.Sections.Processes = collectProcesses(ctx, now)
	s.Sections.Software = collectSoftware(ctx, now)
	s.Sections.Services = collectServices(ctx, now)
	s.Sections.Events = collectEvents(ctx, now)
	return s
}
func reasonFor(err error) Reason {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return ReasonTimeout
	case errors.Is(err, os.ErrPermission):
		return ReasonPermissionDenied
	case errors.Is(err, os.ErrNotExist):
		return ReasonSourceMissing
	case errors.Is(err, errByteLimit):
		return ReasonByteLimit
	default:
		return ReasonReadFailed
	}
}

var errByteLimit = errors.New("operational_byte_limit")
var errSource = errors.New("operational_invalid_source")

// O_NONBLOCK rejects a replaced FIFO without waiting. O_NOFOLLOW excludes a final
// symlink. Each caller supplies a fixed source or a kernel-discovered identifier.
func readBounded(path string, max int) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "operational-source")
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errSource
	}
	// procfs/sysfs advertised st_size need not equal their short textual value.
	// Bound the actual read instead of mistaking sysfs's 4096-byte size for data.
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if len(b) > max {
		return nil, errByteLimit
	}
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errSource
	}
	return b, nil
}
func failSection[T any](now time.Time, limit int, err error) Section[T] {
	reason := reasonFor(err)
	if errors.Is(err, errSource) {
		reason = ReasonInvalidSource
	}
	s := unavailable[T](now, limit, reason)
	if reason == ReasonByteLimit {
		s.Meta.Truncated = true
	}
	return s
}
func collectVolumes(ctx context.Context, now time.Time) VolumeSection {
	if ctx.Err() != nil {
		return failSection[Volume](now, VolumeLimit, ctx.Err())
	}
	data, err := readBounded("/proc/self/mountinfo", maxMountBytes)
	if err != nil {
		return failSection[Volume](now, VolumeLimit, err)
	}
	s, records := parseMounts(data, now)
	allowMeasurements := s.Meta.Complete
	for _, r := range records {
		v := r.item
		if ctx.Err() != nil {
			v.MeasurementReason = ReasonTimeout
			partial(&s.Meta, ReasonTimeout, false)
		} else if v.Kind == "local" && !allowMeasurements {
			v.MeasurementReason = s.Meta.Reason
		} else if v.Kind == "local" {
			total, avail, err := measureMount(r, records)
			if err != nil {
				v.MeasurementReason = reasonFor(err)
				if errors.Is(err, errSource) {
					v.MeasurementReason = ReasonInvalidSource
				}
				if v.MeasurementReason == ReasonPermissionDenied {
					v.MeasurementQuality = Denied
				}
			} else {
				v.TotalBytes = &total
				v.AvailableBytes = &avail
				v.MeasurementQuality = Healthy
				v.MeasurementReason = ReasonNone
				if total > 0 {
					v.UsedPercent = pointer(float64(total-avail) * 100 / float64(total))
				}
			}
		}
		if v.MeasurementQuality != Healthy {
			partial(&s.Meta, v.MeasurementReason, false)
		}
		s.Items = append(s.Items, v)
	}
	sortVolumes(&s)
	if len(s.Items) == 0 && s.Meta.Reason != ReasonNone {
		s.Meta.Quality = Unknown
	}
	return s
}
func measureMount(r mountRecord, records []mountRecord) (uint64, uint64, error) {
	if r.item.Kind != "local" || mountKind(r.item.Filesystem) != "local" {
		return 0, 0, errSource
	}
	// Never traverse through an explicitly remote/FUSE/automount ancestor.
	for _, parent := range records {
		if parent.path != r.path && (parent.path == "/" || strings.HasPrefix(r.path, parent.path+"/")) && (parent.item.Kind == "remote" || parent.item.Filesystem == "autofs") {
			return 0, 0, errSource
		}
	}
	fd, err := unix.Open(r.path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return 0, 0, err
	}
	defer unix.Close(fd)
	// Pin the mounted filesystem and compare the kernel mount ID before Fstatfs.
	// A replaced mount or final symlink is rejected without statfs on that target.
	info, err := readBounded("/proc/self/fdinfo/"+strconv.Itoa(fd), 4096)
	if err != nil {
		return 0, 0, err
	}
	found := false
	for _, line := range strings.Split(string(info), "\n") {
		if rest, ok := strings.CutPrefix(line, "mnt_id:"); ok {
			id, e := strconv.ParseUint(strings.TrimSpace(rest), 10, 64)
			found = e == nil && id == r.mountID
		}
	}
	if !found {
		return 0, 0, errSource
	}
	// Re-read mount metadata after the descriptor pins its superblock. This closes
	// numeric mount-ID reuse between the initial enumeration and O_PATH open.
	current, err := readBounded("/proc/self/mountinfo", maxMountBytes)
	if err != nil {
		return 0, 0, err
	}
	meta, mounts := parseMounts(current, time.Now().UTC())
	if !meta.Meta.Complete {
		return 0, 0, errSource
	}
	verified := false
	for _, mount := range mounts {
		if mount.mountID == r.mountID && mount.path == r.path && mount.item.Filesystem == r.item.Filesystem && mount.item.Kind == "local" {
			verified = true
			break
		}
	}
	if !verified {
		return 0, 0, errSource
	}
	var st unix.Statfs_t
	if err = unix.Fstatfs(fd, &st); err != nil {
		return 0, 0, err
	}
	if st.Bsize <= 0 || st.Blocks > MaxSafeInteger/uint64(st.Bsize) || st.Bavail > st.Blocks {
		return 0, 0, errSource
	}
	return st.Blocks * uint64(st.Bsize), st.Bavail * uint64(st.Bsize), nil
}
func collectNetwork(ctx context.Context, now time.Time) NetworkSection {
	if ctx.Err() != nil {
		return failSection[NetworkInterface](now, NetworkLimit, ctx.Err())
	}
	data, err := readBounded("/proc/net/dev", maxNetworkBytes)
	if err != nil {
		return failSection[NetworkInterface](now, NetworkLimit, err)
	}
	s := parseNetwork(data, now)
	for i := range s.Items {
		x := &s.Items[i]
		if ctx.Err() != nil {
			partial(&s.Meta, ReasonTimeout, false)
			break
		}
		mtu, err := readBounded("/sys/class/net/"+x.Name+"/mtu", 64)
		if err == nil {
			if n, ok := number(strings.TrimSpace(string(mtu))); ok {
				x.MTU = n
			} else {
				partial(&s.Meta, ReasonInvalidSource, false)
			}
		} else {
			partial(&s.Meta, reasonFor(err), false)
		}
		state, err := readBounded("/sys/class/net/"+x.Name+"/operstate", 64)
		if err == nil {
			switch strings.TrimSpace(string(state)) {
			case "up":
				x.State = "up"
			case "down", "lowerlayerdown", "notpresent":
				x.State = "down"
			case "unknown", "dormant", "testing":
				x.State = "unknown"
			default:
				partial(&s.Meta, ReasonInvalidSource, false)
			}
		} else {
			partial(&s.Meta, reasonFor(err), false)
		}
	}
	// Address counts are deliberately unknown: no address enumeration or socket is
	// used by this provider. This missing coverage must remain visible.
	partial(&s.Meta, ReasonNotImplemented, false)
	if len(s.Items) == 0 && s.Meta.Reason != ReasonNone {
		s.Meta.Quality = Unknown
	}
	return s
}
func collectProcesses(ctx context.Context, now time.Time) ProcessSection {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return unavailable[Process](now, ProcessLimit, ReasonNotSupported)
	}
	if ctx.Err() != nil {
		return failSection[Process](now, ProcessLimit, ctx.Err())
	}
	dir, err := os.Open("/proc")
	if err != nil {
		return failSection[Process](now, ProcessLimit, err)
	}
	defer dir.Close()
	names, err := dir.Readdirnames(maxProcessDirectoryEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return failSection[Process](now, ProcessLimit, err)
	}
	s := available[Process](now, ProcessLimit)
	if len(names) > maxProcessDirectoryEntries {
		names = names[:maxProcessDirectoryEntries]
		setScanFailure(&s.Meta, ReasonItemLimit)
	}
	pids := []uint64{}
	for _, name := range names {
		p, ok := number(name)
		if ok && *p > 0 && strconv.FormatUint(*p, 10) == name {
			pids = append(pids, *p)
		}
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	s.Meta.ObservedCount = uint64(len(pids))
	if len(pids) > maxProcessRecords {
		pids = pids[:maxProcessRecords]
		setScanFailure(&s.Meta, ReasonItemLimit)
	}
	for _, pid := range pids {
		if ctx.Err() != nil {
			partial(&s.Meta, ReasonTimeout, false)
			break
		}
		data, err := readBounded("/proc/"+strconv.FormatUint(pid, 10)+"/stat", 16<<10)
		if err != nil {
			partial(&s.Meta, reasonFor(err), false)
			continue
		}
		p, ok := parseProcessStat(data, pid, uint64(os.Getpagesize()))
		if !ok {
			partial(&s.Meta, ReasonInvalidSource, false)
			continue
		}
		if p.State == "unknown" {
			partial(&s.Meta, ReasonInvalidSource, false)
		}
		s.Items = append(s.Items, p)
	}
	sortProcesses(&s)
	if len(s.Items) == 0 && s.Meta.Reason != ReasonNone {
		s.Meta.Quality = Unknown
		if s.Meta.Reason == ReasonPermissionDenied {
			s.Meta.Quality = Denied
		}
	}
	return s
}
func collectSoftware(ctx context.Context, now time.Time) SoftwareSection {
	if ctx.Err() != nil {
		return failSection[Software](now, SoftwareLimit, ctx.Err())
	}
	data, err := readBounded("/var/lib/dpkg/status", assessment.MaxInventoryBytes)
	if err != nil {
		return failSection[Software](now, SoftwareLimit, err)
	}
	return parseSoftware(ctx, bytes.NewReader(data), now)
}
func systemdAvailable() bool {
	st, err := os.Stat("/run/systemd/system")
	return err == nil && st.IsDir()
}
func serviceArgs() []string {
	return []string{"--system", "--no-pager", "--no-ask-password", "--all", "--property=Id,LoadState,ActiveState,SubState", "show", "*.service"}
}
func journalAccessArgs() []string { return []string{"--system", "--no-pager", "--disk-usage"} }
func journalArgs(now time.Time) []string {
	return []string{"--system", "--no-pager", "--output=json", "--output-fields=__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,PRIORITY,MESSAGE_ID", "--since=@" + strconv.FormatInt(now.Add(-15*time.Minute).Unix(), 10), "--until=@" + strconv.FormatInt(now.Unix(), 10), "--lines=2049", "--reverse"}
}
func collectServices(ctx context.Context, now time.Time) ServiceSection {
	if !systemdAvailable() {
		return unavailable[Service](now, ServiceLimit, ReasonToolUnavailable)
	}
	data, reason := runTool(ctx, "/usr/bin/systemctl", serviceArgs())
	if reason != ReasonNone {
		s := unavailable[Service](now, ServiceLimit, reason)
		if reason == ReasonByteLimit {
			s.Meta.Truncated = true
		}
		return s
	}
	return parseServices(data, now)
}
func collectEvents(ctx context.Context, now time.Time) EventSection {
	if !systemdAvailable() {
		return unavailable[Event](now, EventLimit, ReasonToolUnavailable)
	}
	// JSON output implicitly enables journalctl quiet mode. The first fixed,
	// metadata-only query keeps access warnings visible, including partial denial.
	if _, reason := runTool(ctx, "/usr/bin/journalctl", journalAccessArgs()); reason != ReasonNone {
		return unavailable[Event](now, EventLimit, reason)
	}
	data, reason := runTool(ctx, "/usr/bin/journalctl", journalArgs(now))
	if reason != ReasonNone {
		s := unavailable[Event](now, EventLimit, reason)
		if reason == ReasonByteLimit {
			s.Meta.Truncated = true
		}
		return s
	}
	return journalCoverage(parseEvents(data, now))
}

// The only permitted programs are fixed root-owned regular executables beneath
// root-owned, non-writable ancestors. Never search PATH or trust ambient env.
func journalCoverage(s EventSection) EventSection {
	// Even the access preflight can suppress partial-access warnings for root or
	// journal-group/ACL members. journalctl cannot prove complete journal coverage.
	partial(&s.Meta, ReasonNotSupported, false)
	s.Meta.CountExact = false
	if len(s.Items) == 0 {
		s.Meta.Quality = Unknown
	}
	return s
}
func trustedTool(path string) bool {
	if path != "/usr/bin/systemctl" && path != "/usr/bin/journalctl" {
		return false
	}
	for p := path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return false
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != 0 {
			return false
		}
		if p == path {
			if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
				return false
			}
		} else if !st.IsDir() {
			return false
		}
		if p == "/" {
			break
		}
	}
	return true
}

type cappedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		n := b.limit - b.Len()
		if n > 0 {
			_, _ = b.Buffer.Write(p[:n])
		}
		b.exceeded = true
		return n, errByteLimit
	}
	return b.Buffer.Write(p)
}
func runTool(parent context.Context, path string, args []string) ([]byte, Reason) {
	if parent.Err() != nil {
		return nil, ReasonTimeout
	}
	if !trustedTool(path) {
		return nil, ReasonToolUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/", "TERM=dumb", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat", "SYSTEMD_PAGERSECURE=1", "SYSTEMD_URLIFY=0"}
	cmd.Dir = "/"
	cmd.Stdin = nil
	cmd.WaitDelay = 200 * time.Millisecond
	out := &cappedBuffer{limit: maxToolBytes}
	stderr := &cappedBuffer{limit: 4096}
	cmd.Stdout = out
	cmd.Stderr = stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ReasonTimeout
	}
	if out.exceeded || stderr.exceeded {
		return nil, ReasonByteLimit
	}
	// Never preserve subprocess diagnostics. Only fixed classifications escape.
	lower := bytes.ToLower(stderr.Bytes())
	if bytes.Contains(lower, []byte("permission denied")) || bytes.Contains(lower, []byte("insufficient permissions")) || bytes.Contains(lower, []byte("not seeing messages")) {
		return nil, ReasonPermissionDenied
	}
	if bytes.Contains(lower, []byte("no journal files were found")) {
		return nil, ReasonSourceMissing
	}
	if err != nil {
		return nil, ReasonReadFailed
	}
	if stderr.Len() > 0 {
		return nil, ReasonReadFailed
	}
	return out.Bytes(), ReasonNone
}
