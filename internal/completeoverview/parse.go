package completeoverview

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"path"
	"strconv"
	"strings"
)

// MountRecord is transient kernel-source identity, never a retained/wire row.
// Root and unredacted MountPoint are only used to pin and compare mounts; mount
// options and source labels are discarded immediately by ParseMountInfo.
type MountRecord struct {
	MountID    uint32
	ParentID   uint32
	Major      uint32
	Minor      uint32
	Root       string
	MountPoint string
	Filesystem string
}

type Capacity struct {
	TotalBytes     uint64
	AvailableBytes uint64
}
type MountMeasurement struct {
	MountID     uint32
	Capacity    *Capacity
	Observation Observation
}

func numericPID(s string) (uint32, bool) {
	n, e := strconv.ParseUint(s, 10, 31)
	return uint32(n), e == nil && n > 0 && strconv.FormatUint(n, 10) == s
}
func canonicalUint32(s string) (uint32, bool) {
	n, e := strconv.ParseUint(s, 10, 32)
	return uint32(n), e == nil && strconv.FormatUint(n, 10) == s
}

// ParseProcessStat accepts only allowed fields from a single PID stat record.
// Linux USER_HZ is 100 on the supported amd64/arm64 implementations; ticks is
// explicit for synthetic tests and never inferred from process-global PID state.
func ParseProcessStat(data []byte, pid uint32, pageBytes, ticks uint64) (Process, error) {
	if len(data) > MaxProcessStatBytes {
		return Process{}, ErrSourceLimit
	}
	if pid == 0 || pid > 2147483647 || pageBytes == 0 || pageBytes > 1<<30 || ticks == 0 || ticks > 1<<20 {
		return Process{}, ErrInvalidSource
	}
	text := strings.TrimSuffix(string(data), "\n")
	left, right := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if left < 1 || right <= left || strings.TrimSpace(text[:left]) != strconv.FormatUint(uint64(pid), 10) {
		return Process{}, ErrInvalidSource
	}
	name := text[left+1 : right]
	// Linux comm is a display label, not a path. Kernel threads routinely
	// contain slashes (for example kworker/0:0); preserve the bounded text.
	if !validText(name, MaxProcessNameBytes) {
		return Process{}, ErrInvalidSource
	}
	f := strings.Fields(text[right+1:])
	if len(f) < 22 {
		return Process{}, ErrInvalidSource
	}
	ppid, e1 := strconv.ParseUint(f[1], 10, 31)
	utime, e2 := strconv.ParseUint(f[11], 10, 64)
	stime, e3 := strconv.ParseUint(f[12], 10, 64)
	threads, e4 := strconv.ParseUint(f[17], 10, 31)
	rss, e5 := strconv.ParseUint(f[21], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || threads == 0 || rss > MaxSafeInteger/pageBytes || utime > MaxSafeInteger || stime > MaxSafeInteger-utime {
		return Process{}, ErrInvalidSource
	}
	state := ""
	switch f[0] {
	case "R":
		state = "running"
	case "S":
		state = "sleeping"
	case "D":
		state = "disk_sleep"
	case "T":
		state = "stopped"
	case "t":
		state = "tracing_stop"
	case "Z":
		state = "zombie"
	case "X", "x":
		state = "dead"
	case "I":
		state = "idle"
	case "P":
		state = "parked"
	default:
		return Process{}, SourceError{ReasonNotSupported}
	}
	return Process{PID: pid, ParentPID: ptr(uint32(ppid)), Name: &name, State: &state, RSSBytes: ptr(rss * pageBytes), CPUTimeSeconds: ptr(float64(utime+stime) / float64(ticks)), Threads: ptr(uint32(threads)), Observation: Observation{Observed, ReasonNone}}, nil
}

func ParseMountInfo(ctx context.Context, r io.Reader) ([]MountRecord, error) {
	if ctx == nil || r == nil {
		return nil, ErrInvalidInput
	}
	// max+1 ensures exact ceilings distinguish EOF from a complete prefix.
	raw, e := readBounded(ctx, r, MaxMountInfoBytes)
	if e != nil {
		return nil, e
	}
	return parseMountBytes(ctx, raw)
}
func parseMountBytes(ctx context.Context, raw []byte) ([]MountRecord, error) {
	if len(raw) > MaxMountInfoBytes {
		return nil, ErrSourceLimit
	}
	rows := []MountRecord{}
	seen := map[uint32]bool{}
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 4096), MaxMountLineBytes)
	for scan.Scan() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if len(rows) >= MaxVolumeRows {
			return nil, ErrItemLimit
		}
		f := strings.Fields(scan.Text())
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(f) != sep+4 {
			return nil, ErrInvalidSource
		}
		id, a := canonicalUint32(f[0])
		parent, b := canonicalUint32(f[1])
		dev := strings.Split(f[2], ":")
		if !a || !b || id == 0 || parent == 0 || seen[id] || len(dev) != 2 {
			return nil, ErrInvalidSource
		}
		major, c := canonicalUint32(dev[0])
		minor, d := canonicalUint32(dev[1])
		root, ok1 := decodeMountPath(f[3])
		point, ok2 := decodeMountPath(f[4])
		if !c || !d || !ok1 || !ok2 || !filesystemPattern.MatchString(f[sep+1]) {
			return nil, ErrInvalidSource
		}
		seen[id] = true
		rows = append(rows, MountRecord{id, parent, major, minor, root, point, f[sep+1]})
	}
	if scan.Err() != nil {
		return nil, ErrSourceLimit
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return rows, nil
}
func decodeMountPath(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", false
		}
		switch s[i : i+4] {
		case `\040`:
			b.WriteByte(' ')
		case `\011`:
			b.WriteByte('\t')
		case `\012`:
			b.WriteByte('\n')
		case `\134`:
			b.WriteByte('\\')
		default:
			return "", false
		}
		i += 3
	}
	v := b.String()
	return v, validText(v, MaxMountPathBytes) && strings.HasPrefix(v, "/") && path.Clean(v) == v
}
func mountKind(fs string) string {
	switch fs {
	case "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs", "vfat", "exfat", "ntfs3", "zfs", "bcachefs", "erofs", "squashfs":
		return "local"
	case "tmpfs", "devtmpfs", "hugetlbfs", "ramfs":
		return "memory"
	case "nfs", "nfs4", "cifs", "smb3", "9p", "ceph", "afs", "coda", "glusterfs":
		return "remote"
	case "proc", "sysfs", "devpts", "cgroup", "cgroup2", "overlay", "nsfs", "mqueue", "securityfs", "debugfs", "tracefs", "pstore", "configfs", "efivarfs", "autofs", "binfmt_misc", "fusectl":
		return "virtual"
	default:
		if strings.HasPrefix(fs, "fuse") {
			return "remote"
		}
		return "unknown"
	}
}
func volumeFor(m MountRecord) Volume {
	kind := mountKind(m.Filesystem)
	o := Observation{Unsupported, ReasonNotSupported}
	switch kind {
	case "virtual":
		o = Observation{NotApplicable, ReasonNotApplicable}
	case "remote":
		o = Observation{Unsupported, ReasonRemoteFilesystemSkipped}
	case "local", "memory":
		o = Observation{Unavailable, ReasonReadFailed}
	}
	return Volume{ID: "mount_" + strconv.FormatUint(uint64(m.MountID), 10), MountPoint: redactMount(m.MountPoint), Filesystem: m.Filesystem, Kind: kind, FilesystemGroup: "fs_" + strconv.FormatUint(uint64(m.Major), 10) + "_" + strconv.FormatUint(uint64(m.Minor), 10), CapacityScope: "agent-mount-namespace", Measurement: o}
}
