package operational

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/assessment"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxMountBytes              = 2 << 20
	maxMountRecords            = 4096
	maxProcessRecords          = 4096
	maxProcessDirectoryEntries = 8192
	maxNetworkBytes            = 256 << 10
	maxToolBytes               = 1 << 20
	maxServiceRecords          = 4096
	maxEventRecords            = 2048
)

func pointer[T any](v T) *T { return &v }
func number(s string) (*uint64, bool) {
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil || n > MaxSafeInteger {
		return nil, false
	}
	return &n, true
}
func cleanName(s string, max int) (string, bool) {
	if !validString(s, max, false) || strings.ContainsAny(s, "/\\") {
		return "", false
	}
	return s, true
}
func setScanFailure(m *SectionMeta, reason Reason) {
	partial(m, reason, reason == ReasonByteLimit || reason == ReasonItemLimit)
	m.CountExact = false
}

type mountRecord struct {
	item    Volume
	path    string
	mountID uint64
}

func mountKind(fs string) string {
	switch fs {
	case "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs", "vfat", "exfat", "ntfs3", "zfs", "bcachefs", "erofs", "squashfs":
		return "local"
	case "nfs", "nfs4", "cifs", "smb3", "9p", "ceph", "afs", "coda", "glusterfs":
		return "remote"
	case "proc", "sysfs", "tmpfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "overlay", "nsfs", "mqueue", "hugetlbfs", "securityfs", "debugfs", "tracefs", "pstore", "configfs", "efivarfs", "ramfs", "autofs", "binfmt_misc", "fusectl":
		return "virtual"
	default:
		if strings.HasPrefix(fs, "fuse") {
			return "remote"
		}
		return "unknown"
	}
}
func decodeMount(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", false
		}
		seq := s[i : i+4]
		switch seq {
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
	p := b.String()
	return p, validString(p, 4096, false) && strings.HasPrefix(p, "/") && path.Clean(p) == p
}
func parseMounts(data []byte, now time.Time) (VolumeSection, []mountRecord) {
	s := available[Volume](now, VolumeLimit)
	rows := []mountRecord{}
	scan := bufio.NewScanner(bytes.NewReader(data))
	scan.Buffer(make([]byte, 4096), 64<<10)
	seen := map[string]bool{}
	for scan.Scan() {
		if s.Meta.ObservedCount >= maxMountRecords {
			setScanFailure(&s.Meta, ReasonItemLimit)
			break
		}
		s.Meta.ObservedCount++
		f := strings.Fields(scan.Text())
		sep := -1
		for i, v := range f {
			if v == "-" {
				sep = i
				break
			}
		}
		if len(f) < 10 || sep < 6 || sep+3 >= len(f) {
			partial(&s.Meta, ReasonInvalidSource, false)
			continue
		}
		id, ok := number(f[0])
		if !ok || *id == 0 || *id > 4294967295 || seen[f[0]] {
			partial(&s.Meta, ReasonInvalidSource, false)
			continue
		}
		seen[f[0]] = true
		path, ok := decodeMount(f[4])
		if !ok || !validString(redactMount(path), 160, false) || !validString(f[sep+1], 32, false) {
			partial(&s.Meta, ReasonInvalidSource, false)
			continue
		}
		kind := mountKind(f[sep+1])
		reason := ReasonNotSupported
		if kind == "remote" {
			reason = ReasonRemoteFilesystemSkipped
		}
		v := Volume{ID: "mount_" + f[0], MountPoint: redactMount(path), Filesystem: f[sep+1], Kind: kind, MeasurementQuality: Unknown, MeasurementReason: reason}
		rows = append(rows, mountRecord{v, path, *id})
	}
	if scan.Err() != nil {
		setScanFailure(&s.Meta, ReasonByteLimit)
	}
	return s, rows
}
func sortVolumes(s *VolumeSection) {
	sort.Slice(s.Items, func(i, j int) bool {
		a, b := s.Items[i], s.Items[j]
		if (a.MeasurementQuality != Healthy) != (b.MeasurementQuality != Healthy) {
			return a.MeasurementQuality != Healthy
		}
		if a.UsedPercent != nil && b.UsedPercent != nil && *a.UsedPercent != *b.UsedPercent {
			return *a.UsedPercent > *b.UsedPercent
		}
		return a.ID < b.ID
	})
	limitItems(s)
}

func parseProcessStat(data []byte, pid uint64, pageBytes uint64) (Process, bool) {
	text := strings.TrimSuffix(string(data), "\n")
	left := strings.IndexByte(text, '(')
	right := strings.LastIndexByte(text, ')')
	if left < 1 || right <= left || strings.TrimSpace(text[:left]) != strconv.FormatUint(pid, 10) {
		return Process{}, false
	}
	name, ok := cleanName(text[left+1:right], 64)
	if !ok {
		return Process{}, false
	}
	f := strings.Fields(text[right+1:])
	if len(f) < 22 {
		return Process{}, false
	}
	ppid, ok1 := number(f[1])
	utime, ok2 := number(f[11])
	stime, ok3 := number(f[12])
	threads, ok4 := number(f[17])
	rss, ok5 := number(f[21])
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || pageBytes == 0 || *rss > MaxSafeInteger/pageBytes || *utime > MaxSafeInteger-*stime {
		return Process{}, false
	}
	state := "unknown"
	switch f[0] {
	case "R":
		state = "running"
	case "S", "D":
		state = "sleeping"
	case "T", "t":
		state = "stopped"
	case "Z":
		state = "zombie"
	case "I":
		state = "idle"
	}
	// Linux procfs exposes USER_HZ units: 100 on supported amd64/arm64.
	return Process{PID: pid, ParentPID: ppid, Name: name, State: state, RSSBytes: pointer(*rss * pageBytes), CPUTimeSeconds: pointer(float64(*utime+*stime) / 100), Threads: threads}, true
}
func sortProcesses(s *ProcessSection) {
	sort.Slice(s.Items, func(i, j int) bool {
		a, b := s.Items[i], s.Items[j]
		if a.RSSBytes != nil && b.RSSBytes != nil && *a.RSSBytes != *b.RSSBytes {
			return *a.RSSBytes > *b.RSSBytes
		}
		return a.PID < b.PID
	})
	limitItems(s)
}
func parseNetwork(data []byte, now time.Time) NetworkSection {
	s := available[NetworkInterface](now, NetworkLimit)
	scan := bufio.NewScanner(bytes.NewReader(data))
	seen := map[string]bool{}
	line := 0
	for scan.Scan() {
		line++
		if line <= 2 {
			continue
		}
		name, values, ok := strings.Cut(scan.Text(), ":")
		name = strings.TrimSpace(name)
		f := strings.Fields(values)
		if !ok || !validString(name, 64, false) || !interfacePattern.MatchString(name) || name == "." || name == ".." || len(f) != 16 || seen[name] {
			partial(&s.Meta, ReasonInvalidSource, false)
			continue
		}
		seen[name] = true
		s.Meta.ObservedCount++
		if s.Meta.ObservedCount > 1024 {
			setScanFailure(&s.Meta, ReasonItemLimit)
			break
		}
		rx, a := number(f[0])
		tx, b := number(f[8])
		rxerr, c := number(f[2])
		txerr, d := number(f[10])
		if !a || !b || !c || !d {
			partial(&s.Meta, ReasonInvalidSource, false)
			continue
		}
		s.Items = append(s.Items, NetworkInterface{Name: name, State: "unknown", RXBytes: rx, TXBytes: tx, RXErrors: rxerr, TXErrors: txerr})
	}
	if scan.Err() != nil {
		setScanFailure(&s.Meta, ReasonByteLimit)
	}
	if line < 2 {
		return unavailable[NetworkInterface](now, NetworkLimit, ReasonInvalidSource)
	}
	sort.Slice(s.Items, func(i, j int) bool {
		a, b := s.Items[i], s.Items[j]
		ae, be := *a.RXErrors+*a.TXErrors, *b.RXErrors+*b.TXErrors
		if ae != be {
			return ae > be
		}
		return a.Name < b.Name
	})
	limitItems(&s)
	if len(s.Items) == 0 && s.Meta.Reason != ReasonNone {
		s.Meta.Quality = Unknown
	}
	return s
}
func parseServices(data []byte, now time.Time) ServiceSection {
	s := available[Service](now, ServiceLimit)
	scan := bufio.NewScanner(bytes.NewReader(data))
	scan.Buffer(make([]byte, 4096), 4096)
	fields := map[string]string{}
	seen := map[string]bool{}
	bad := false
	flush := func() {
		if len(fields) == 0 {
			if bad {
				partial(&s.Meta, ReasonInvalidSource, false)
				bad = false
			}
			return
		}
		s.Meta.ObservedCount++
		if s.Meta.ObservedCount > maxServiceRecords {
			setScanFailure(&s.Meta, ReasonItemLimit)
			fields = map[string]string{}
			return
		}
		name := fields["Id"]
		if bad || !unitPattern.MatchString(name) || !validString(name, 128, false) || seen[name] || len(fields) != 4 {
			partial(&s.Meta, ReasonInvalidSource, false)
			fields = map[string]string{}
			bad = false
			return
		}
		seen[name] = true
		load := fields["LoadState"]
		if load == "not-found" {
			load = "not_found"
		}
		if !oneOf(load, "loaded", "not_found", "masked") {
			load = "unknown"
			partial(&s.Meta, ReasonInvalidSource, false)
		}
		active := fields["ActiveState"]
		if !oneOf(active, "active", "inactive", "failed", "activating", "deactivating", "reloading") {
			active = "unknown"
			partial(&s.Meta, ReasonInvalidSource, false)
		}
		sub := fields["SubState"]
		if !oneOf(sub, "running", "exited", "dead", "failed") {
			sub = "other"
		}
		s.Items = append(s.Items, Service{Name: name, LoadState: load, ActiveState: active, SubState: sub})
		fields = map[string]string{}
		bad = false
	}
	for scan.Scan() {
		line := scan.Text()
		if line == "" {
			flush()
			if s.Meta.ObservedCount > maxServiceRecords {
				break
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !oneOf(key, "Id", "LoadState", "ActiveState", "SubState") {
			bad = true
			continue
		}
		if _, exists := fields[key]; exists {
			bad = true
		}
		fields[key] = value
	}
	flush()
	if scan.Err() != nil {
		setScanFailure(&s.Meta, ReasonByteLimit)
	}
	sort.Slice(s.Items, func(i, j int) bool {
		a, b := s.Items[i], s.Items[j]
		if (a.ActiveState == "failed") != (b.ActiveState == "failed") {
			return a.ActiveState == "failed"
		}
		return a.Name < b.Name
	})
	limitItems(&s)
	if len(s.Items) == 0 && s.Meta.Reason != ReasonNone {
		s.Meta.Quality = Unknown
	}
	return s
}
func parseSoftware(ctx context.Context, r io.Reader, now time.Time) SoftwareSection {
	pkgs, _, err := assessment.ParseDpkgStatus(ctx, r)
	if err != nil {
		reason := ReasonInvalidSource
		if errors.Is(err, assessment.ErrInventoryLimit) {
			reason = ReasonByteLimit
		}
		if ctx.Err() != nil {
			reason = ReasonTimeout
		}
		s := unavailable[Software](now, SoftwareLimit, reason)
		if reason == ReasonByteLimit {
			s.Meta.Truncated = true
		}
		return s
	}
	s := available[Software](now, SoftwareLimit)
	for _, p := range pkgs {
		if p.InstallState != "installed" {
			continue
		}
		s.Meta.ObservedCount++
		if !validString(p.Name, 128, false) || !validString(p.Version, 192, false) || !validString(p.Architecture, 32, false) {
			partial(&s.Meta, ReasonInvalidSource, false)
			continue
		}
		s.Items = append(s.Items, Software{Name: p.Name, Version: p.Version, Architecture: p.Architecture, Manager: "dpkg"})
	}
	sort.Slice(s.Items, func(i, j int) bool {
		a, b := s.Items[i], s.Items[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Architecture < b.Architecture
	})
	limitItems(&s)
	if len(s.Items) == 0 && s.Meta.Reason != ReasonNone {
		s.Meta.Quality = Unknown
	}
	return s
}
func parseEvents(data []byte, now time.Time) EventSection {
	s := available[Event](now, EventLimit)
	scan := bufio.NewScanner(bytes.NewReader(data))
	scan.Buffer(make([]byte, 4096), 64<<10)
	groups := map[string]*Event{}
	scanned := 0
	for scan.Scan() {
		if scanned >= maxEventRecords {
			setScanFailure(&s.Meta, ReasonItemLimit)
			break
		}
		scanned++
		// Explicit output fields exclude MESSAGE. Mandatory journal identity metadata
		// is accepted only to discard it; unexpected fields invalidate the record.
		fields, decodeErr := journalFields(scan.Bytes())
		if decodeErr != nil {
			partial(&s.Meta, ReasonInvalidSource, false)
			continue
		}
		bad := false
		for k := range fields {
			if !oneOf(k, "__CURSOR", "__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP", "_BOOT_ID", "__SEQNUM", "__SEQNUM_ID", "_SYSTEMD_UNIT", "PRIORITY", "MESSAGE_ID") {
				bad = true
			}
		}
		val := func(k string) (string, bool) {
			v, ok := fields[k]
			if !ok {
				return "", true
			}
			var x string
			raw := bytes.TrimSpace(v)
			if len(raw) == 0 || raw[0] != '"' {
				return "", false
			}
			e := json.Unmarshal(v, &x)
			return x, e == nil
		}
		ts, a := val("__REALTIME_TIMESTAMP")
		unit, b := val("_SYSTEMD_UNIT")
		priority, c := val("PRIORITY")
		message, d := val("MESSAGE_ID")
		micros, e := strconv.ParseInt(ts, 10, 64)
		prio, f := strconv.Atoi(priority)
		if bad || !a || !b || !c || !d || e != nil || f != nil || micros < 0 || prio < 0 || prio > 7 || !validString(unit, 128, true) || unit != "" && !eventUnitPattern.MatchString(unit) || message != "" && !messagePattern.MatchString(message) {
			partial(&s.Meta, ReasonInvalidSource, false)
			continue
		}
		at := time.UnixMicro(micros).UTC()
		if at.Before(now.Add(-15*time.Minute)) || at.After(now) {
			partial(&s.Meta, ReasonInvalidSource, false)
			continue
		}
		s.Meta.ObservedCount++
		key := unit + ":" + priority + ":" + message
		if group, ok := groups[key]; ok {
			group.Count++
			if at.Before(group.FirstSeen) {
				group.FirstSeen = at
			}
			if at.After(group.LastSeen) {
				group.LastSeen = at
			}
		} else {
			groups[key] = &Event{Source: "systemd-journal", Unit: unit, Priority: prio, MessageID: message, Count: 1, FirstSeen: at, LastSeen: at}
		}
	}
	if scan.Err() != nil {
		setScanFailure(&s.Meta, ReasonByteLimit)
	}
	for _, v := range groups {
		s.Items = append(s.Items, *v)
	}
	sort.Slice(s.Items, func(i, j int) bool {
		a, b := s.Items[i], s.Items[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		if a.Unit != b.Unit {
			return a.Unit < b.Unit
		}
		return a.MessageID < b.MessageID
	})
	limitItems(&s)
	if len(s.Items) == 0 && s.Meta.Reason != ReasonNone {
		s.Meta.Quality = Unknown
	}
	return s
}

// Strict source-object decoding rejects duplicate keys instead of silently
// accepting a later value. Only selected fields and mandatory metadata are used.
func journalFields(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("journal_metadata_invalid")
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok {
			return nil, errors.New("journal_metadata_invalid")
		}
		if _, exists := fields[name]; exists {
			return nil, errors.New("journal_metadata_duplicate")
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, err
		}
		fields[name] = value
	}
	if _, err = d.Token(); err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("journal_metadata_trailing")
	}
	return fields, nil
}
