package completeoverview

import (
	"encoding/json"
	"math"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var generationPattern = regexp.MustCompile(`^sample_[0-9a-f]{32}$`)
var filesystemPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
var groupPattern = regexp.MustCompile(`^fs_([0-9]+)_([0-9]+)$`)

func Validate(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.Scope != SnapshotScope || !generationPattern.MatchString(s.GenerationID) || !validTime(s.CaptureStartedAt) || !validTime(s.CaptureFinishedAt) || s.CaptureFinishedAt.Before(s.CaptureStartedAt) {
		return ErrInvalidSnapshot
	}
	if !validMeta(s.Processes.Meta, s.GenerationID, len(s.Processes.Items)) || !validMeta(s.Volumes.Meta, s.GenerationID, len(s.Volumes.Items)) || s.Processes.Items == nil || s.Volumes.Items == nil {
		return ErrInvalidSnapshot
	}
	if len(s.Processes.Items) > MaxProcessRows || len(s.Volumes.Items) > MaxVolumeRows {
		return ErrSnapshotLimit
	}
	pc, vc := FieldCoverage{}, FieldCoverage{}
	for i, p := range s.Processes.Items {
		pc.add(p.Observation.Status)
		if !validProcess(p) || i > 0 && s.Processes.Items[i-1].PID >= p.PID {
			return ErrInvalidSnapshot
		}
	}
	ids := map[string]bool{}
	for i, v := range s.Volumes.Items {
		vc.add(v.Measurement.Status)
		if !validVolume(v) || ids[v.ID] || i > 0 && volumeLess(v, s.Volumes.Items[i-1]) {
			return ErrInvalidSnapshot
		}
		ids[v.ID] = true
	}
	if pc != s.Processes.Meta.FieldCoverage || vc != s.Volumes.Meta.FieldCoverage {
		return ErrInvalidSnapshot
	}
	for _, sec := range []any{s.Processes, s.Volumes} {
		b, e := json.Marshal(sec)
		if e != nil {
			return ErrInvalidSnapshot
		}
		if len(b) > MaxSectionBytes {
			return ErrSnapshotLimit
		}
	}
	b, e := json.Marshal(s)
	if e != nil {
		return ErrInvalidSnapshot
	}
	if len(b) > MaxSnapshotBytes {
		return ErrSnapshotLimit
	}
	return nil
}
func Encode(s Snapshot) ([]byte, error) {
	if e := Validate(s); e != nil {
		return nil, e
	}
	return json.Marshal(s)
}
func ValidateProcess(p Process) error {
	if !validProcess(p) {
		return ErrInvalidSnapshot
	}
	return nil
}
func ValidateVolume(v Volume) error {
	if !validVolume(v) {
		return ErrInvalidSnapshot
	}
	return nil
}
func ValidateSectionMeta(m SectionMeta, n int) error {
	if n < 0 || n > MaxProcessRows || !generationPattern.MatchString(m.GenerationID) || !validMeta(m, m.GenerationID, n) {
		return ErrInvalidSnapshot
	}
	return nil
}
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Location() == time.UTC
}
func validMeta(m SectionMeta, id string, n int) bool {
	if m.GenerationID != id {
		return false
	}
	switch m.Coverage {
	case Complete:
		return m.Reason == ReasonNone && m.CountExact && m.ObservedCount != nil && *m.ObservedCount == uint64(n) && m.FieldCoverage.valid(uint64(n))
	case Failed:
		return validFailureReason(m.Reason) && !m.CountExact && m.ObservedCount == nil && n == 0 && m.FieldCoverage == (FieldCoverage{})
	}
	return false
}
func validFailureReason(r Reason) bool {
	switch r {
	case ReasonSourceMissing, ReasonPermissionDenied, ReasonNotSupported, ReasonTimeout, ReasonInvalidSource, ReasonReadFailed, ReasonItemLimit, ReasonByteLimit, ReasonCollectorBusy, ReasonNotCollected, ReasonMountChanged:
		return true
	}
	return false
}
func validText(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}
func validProcess(p Process) bool {
	if p.PID == 0 || p.PID > 2147483647 {
		return false
	}
	if p.Observation.Status != Observed {
		if p.ParentPID != nil || p.Name != nil || p.State != nil || p.RSSBytes != nil || p.CPUTimeSeconds != nil || p.Threads != nil {
			return false
		}
		return validMissing(p.Observation, true)
	}
	if p.Observation.Reason != ReasonNone || p.ParentPID == nil || *p.ParentPID > 2147483647 || p.Name == nil || !validText(*p.Name, MaxProcessNameBytes) || strings.ContainsAny(*p.Name, "/\\") || p.State == nil || p.RSSBytes == nil || *p.RSSBytes > MaxSafeInteger || p.CPUTimeSeconds == nil || math.IsNaN(*p.CPUTimeSeconds) || math.IsInf(*p.CPUTimeSeconds, 0) || *p.CPUTimeSeconds < 0 || *p.CPUTimeSeconds > float64(MaxSafeInteger) || p.Threads == nil || *p.Threads == 0 || *p.Threads > 2147483647 {
		return false
	}
	switch *p.State {
	case "running", "sleeping", "disk_sleep", "stopped", "tracing_stop", "zombie", "dead", "idle", "parked":
		return true
	}
	return false
}
func validMissing(o Observation, process bool) bool {
	switch o.Status {
	case Denied:
		return o.Reason == ReasonPermissionDenied
	case Exited:
		return process && o.Reason == ReasonProcessGone
	case Invalid:
		return o.Reason == ReasonInvalidSource || !process && o.Reason == ReasonMountChanged
	case Unsupported:
		return o.Reason == ReasonNotSupported || !process && o.Reason == ReasonRemoteFilesystemSkipped
	case Unavailable:
		return o.Reason == ReasonReadFailed || o.Reason == ReasonSourceMissing
	case NotApplicable:
		return !process && o.Reason == ReasonNotApplicable
	}
	return false
}
func validVolume(v Volume) bool {
	id, ok := strings.CutPrefix(v.ID, "mount_")
	if !ok {
		return false
	}
	n, e := strconv.ParseUint(id, 10, 32)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != id {
		return false
	}
	if !validText(v.MountPoint, MaxMountPathBytes) || !strings.HasPrefix(v.MountPoint, "/") || path.Clean(v.MountPoint) != v.MountPoint || redactMount(v.MountPoint) != v.MountPoint || !filesystemPattern.MatchString(v.Filesystem) || v.Kind != mountKind(v.Filesystem) || v.CapacityScope != "agent-mount-namespace" {
		return false
	}
	parts := groupPattern.FindStringSubmatch(v.FilesystemGroup)
	if len(parts) != 3 {
		return false
	}
	for _, x := range parts[1:] {
		n, e := strconv.ParseUint(x, 10, 32)
		if e != nil || strconv.FormatUint(n, 10) != x {
			return false
		}
	}
	if v.Measurement.Status != Observed {
		return v.TotalBytes == nil && v.AvailableBytes == nil && v.UsedPercent == nil && validMissing(v.Measurement, false) && validVolumeStatus(v)
	}
	if v.Kind != "local" && v.Kind != "memory" || v.Measurement.Reason != ReasonNone || v.TotalBytes == nil || *v.TotalBytes > MaxSafeInteger || v.AvailableBytes == nil || *v.AvailableBytes > *v.TotalBytes {
		return false
	}
	if *v.TotalBytes == 0 {
		return v.UsedPercent == nil
	}
	return v.UsedPercent != nil && !math.IsNaN(*v.UsedPercent) && !math.IsInf(*v.UsedPercent, 0) && *v.UsedPercent >= 0 && *v.UsedPercent <= 100 && math.Abs(*v.UsedPercent-float64(*v.TotalBytes-*v.AvailableBytes)*100/float64(*v.TotalBytes)) < 1e-9
}
func validVolumeStatus(v Volume) bool {
	switch v.Kind {
	case "virtual":
		return v.Measurement == Observation{NotApplicable, ReasonNotApplicable}
	case "remote":
		return v.Measurement == Observation{Unsupported, ReasonRemoteFilesystemSkipped}
	case "unknown":
		return v.Measurement == Observation{Unsupported, ReasonNotSupported}
	case "local", "memory":
		return v.Measurement.Status != NotApplicable
	}
	return false
}
func volumeRank(v Volume) int {
	if v.Kind == "local" && v.Measurement.Status == Observed {
		return 0
	}
	switch v.Kind {
	case "local":
		return 1
	case "memory":
		return 2
	case "remote":
		return 3
	case "unknown":
		return 4
	}
	return 5
}
func volumeLess(a, b Volume) bool {
	if volumeRank(a) != volumeRank(b) {
		return volumeRank(a) < volumeRank(b)
	}
	if (a.MountPoint == "/") != (b.MountPoint == "/") {
		return a.MountPoint == "/"
	}
	if a.MountPoint != b.MountPoint {
		return a.MountPoint < b.MountPoint
	}
	return a.ID < b.ID
}
func redactMount(s string) string {
	for _, prefix := range []string{"/home/", "/run/user/"} {
		if strings.HasPrefix(s, prefix) {
			rest := strings.TrimPrefix(s, prefix)
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				return prefix + "[redacted]" + rest[i:]
			}
			return prefix + "[redacted]"
		}
	}
	return s
}
