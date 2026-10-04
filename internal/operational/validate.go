package operational

import (
	"encoding/json"
	"errors"
	"localrmm/internal/assessment"
	"math"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrInvalidSnapshot = errors.New("operational_snapshot_invalid")
var generationPattern = regexp.MustCompile(`^sample_[0-9a-f]{32}$`)
var mountPattern = regexp.MustCompile(`^mount_[1-9][0-9]{0,9}$`)
var messagePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var packagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
var architecturePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
var unitPattern = regexp.MustCompile(`^[A-Za-z0-9:_.@\\-]+\.service$`)
var eventUnitPattern = regexp.MustCompile(`^[A-Za-z0-9:_.@\\-]+\.(service|scope|socket|target|mount|automount|slice|timer|path|device|swap)$`)
var interfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

func validString(s string, max int, empty bool) bool {
	if (!empty && s == "") || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func oneOf[T ~string](s T, choices ...T) bool {
	for _, c := range choices {
		if s == c {
			return true
		}
	}
	return false
}
func validReason(r Reason) bool {
	return oneOf(r, ReasonNone, ReasonSourceMissing, ReasonPermissionDenied, ReasonNotSupported, ReasonTimeout, ReasonInvalidSource, ReasonReadFailed, ReasonItemLimit, ReasonByteLimit, ReasonRemoteFilesystemSkipped, ReasonToolUnavailable, ReasonNotImplemented)
}
func utc(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && t.Location() == time.UTC
}
func uintOK(p *uint64) bool { return p == nil || *p <= MaxSafeInteger }
func floatOK(p *float64, max float64) bool {
	return p == nil || !math.IsNaN(*p) && !math.IsInf(*p, 0) && *p >= 0 && *p <= max
}
func sectionOK[T any](s Section[T], limit int, now time.Time) bool {
	m := s.Meta
	if !generationPattern.MatchString(m.GenerationID) || s.Items == nil || len(s.Items) > limit || m.ItemLimit != limit || !m.ObservedAt.Equal(now) || !utc(m.ObservedAt) || m.ObservedCount > MaxSafeInteger || m.ObservedCount < uint64(len(s.Items)) || !validReason(m.Reason) || !oneOf(m.Quality, Healthy, Unknown, Denied) {
		return false
	}
	if m.Complete && (m.Quality != Healthy || m.Reason != ReasonNone || m.Truncated || !m.CountExact) {
		return false
	}
	if m.Truncated && m.Complete || m.Reason == ReasonNone && !m.Complete {
		return false
	}
	if m.Quality != Healthy && (m.Complete || len(s.Items) != 0 || m.Reason == ReasonNone) {
		return false
	}
	if m.Quality == Healthy && len(s.Items) == 0 && !m.Complete {
		return false
	}
	if m.Quality == Denied && m.Reason != ReasonPermissionDenied {
		return false
	}
	if (m.Reason == ReasonItemLimit || m.Reason == ReasonByteLimit) && !m.Truncated {
		return false
	}
	return true
}

// Validate is a strict typed contract boundary. Callers decoding untrusted JSON
// must additionally reject unknown/duplicate JSON keys before calling Validate.
// Only collector qualities are accepted; stale is an API view state.
func Validate(s Snapshot) error {
	if s.SchemaVersion != SchemaVersion || s.CollectionProfile != CollectionProfile || !generationPattern.MatchString(s.GenerationID) || !utc(s.CollectedAt) || s.DurationMS < 0 || uint64(s.DurationMS) > MaxSafeInteger {
		return ErrInvalidSnapshot
	}
	v := s.Sections
	for _, m := range []SectionMeta{v.Volumes.Meta, v.Network.Meta, v.Services.Meta, v.Processes.Meta, v.Software.Meta, v.Events.Meta} {
		if m.GenerationID != s.GenerationID || !m.ObservedAt.Equal(s.CollectedAt) {
			return ErrInvalidSnapshot
		}
	}

	if ValidateVolumeSection(v.Volumes) != nil || ValidateNetworkSection(v.Network) != nil || ValidateServiceSection(v.Services) != nil || ValidateProcessSection(v.Processes) != nil || ValidateSoftwareSection(v.Software) != nil || ValidateEventSection(v.Events) != nil {
		return ErrInvalidSnapshot
	}
	b, err := json.Marshal(s)
	if err != nil || len(b) > MaxSnapshotBytes {
		return ErrInvalidSnapshot
	}
	return nil
}

func ordinarySectionOK[T any](s Section[T], limit int) bool {
	return sectionOK(s, limit, s.Meta.ObservedAt) && (!s.Meta.Complete || s.Meta.ObservedCount == uint64(len(s.Items)))
}

// ValidateVolumeSection checks original section provenance independently, without
// refreshing timestamps, generating IDs or requiring other sections.
func ValidateVolumeSection(s VolumeSection) error {
	if !ordinarySectionOK(s, VolumeLimit) {
		return ErrInvalidSnapshot
	}
	seen := map[string]bool{}
	for _, x := range s.Items {
		id, err := strconv.ParseUint(strings.TrimPrefix(x.ID, "mount_"), 10, 32)
		if seen[x.ID] || !mountPattern.MatchString(x.ID) || err != nil || id == 0 || !validString(x.MountPoint, 160, false) || !strings.HasPrefix(x.MountPoint, "/") || path.Clean(x.MountPoint) != x.MountPoint || !validString(x.Filesystem, 32, false) || mountKind(x.Filesystem) != x.Kind || !uintOK(x.TotalBytes) || !uintOK(x.AvailableBytes) || !floatOK(x.UsedPercent, 100) || !oneOf(x.MeasurementQuality, Healthy, Unknown, Denied) || !validReason(x.MeasurementReason) {
			return ErrInvalidSnapshot
		}
		seen[x.ID] = true
		if x.MeasurementQuality == Healthy {
			if x.MeasurementReason != ReasonNone || x.Kind != "local" || x.TotalBytes == nil || x.AvailableBytes == nil || *x.AvailableBytes > *x.TotalBytes {
				return ErrInvalidSnapshot
			}
			if *x.TotalBytes == 0 {
				if x.UsedPercent != nil {
					return ErrInvalidSnapshot
				}
			} else {
				if x.UsedPercent == nil || math.Abs(*x.UsedPercent-float64(*x.TotalBytes-*x.AvailableBytes)*100/float64(*x.TotalBytes)) > 0.000001 {
					return ErrInvalidSnapshot
				}
			}
		} else if x.MeasurementReason == ReasonNone || x.TotalBytes != nil || x.AvailableBytes != nil || x.UsedPercent != nil || s.Meta.Complete {
			return ErrInvalidSnapshot
		}
		if x.MeasurementQuality == Denied && x.MeasurementReason != ReasonPermissionDenied || redactMount(x.MountPoint) != x.MountPoint {
			return ErrInvalidSnapshot
		}
	}
	return validateSectionBytes(s)
}

// ValidateNetworkSection validates a standalone original interface section.
func ValidateNetworkSection(s NetworkSection) error {
	if !ordinarySectionOK(s, NetworkLimit) {
		return ErrInvalidSnapshot
	}
	seen := map[string]bool{}
	for _, x := range s.Items {
		if seen[x.Name] || !validString(x.Name, 64, false) || !interfacePattern.MatchString(x.Name) || x.Name == "." || x.Name == ".." || !oneOf(x.State, "up", "down", "unknown") || !uintOK(x.MTU) || !uintOK(x.RXBytes) || !uintOK(x.TXBytes) || !uintOK(x.RXErrors) || !uintOK(x.TXErrors) || !uintOK(x.IPv4Count) || !uintOK(x.IPv6Count) {
			return ErrInvalidSnapshot
		}
		seen[x.Name] = true
		if s.Meta.Complete && (x.State == "unknown" || x.MTU == nil || x.RXBytes == nil || x.TXBytes == nil || x.RXErrors == nil || x.TXErrors == nil || x.IPv4Count == nil || x.IPv6Count == nil) {
			return ErrInvalidSnapshot
		}
	}
	return validateSectionBytes(s)
}

// ValidateServiceSection validates a standalone original service section.
func ValidateServiceSection(s ServiceSection) error {
	if !ordinarySectionOK(s, ServiceLimit) {
		return ErrInvalidSnapshot
	}
	seen := map[string]bool{}
	for _, x := range s.Items {
		if seen[x.Name] || !validString(x.Name, 128, false) || !unitPattern.MatchString(x.Name) || !oneOf(x.LoadState, "loaded", "not_found", "masked", "unknown") || !oneOf(x.ActiveState, "active", "inactive", "failed", "activating", "deactivating", "reloading", "unknown") || !oneOf(x.SubState, "running", "exited", "dead", "failed", "other", "unknown") {
			return ErrInvalidSnapshot
		}
		seen[x.Name] = true
		if s.Meta.Complete && (x.LoadState == "unknown" || x.ActiveState == "unknown" || x.SubState == "unknown") {
			return ErrInvalidSnapshot
		}
	}
	return validateSectionBytes(s)
}

// ValidateProcessSection validates a standalone original process section.
func ValidateProcessSection(s ProcessSection) error {
	if !ordinarySectionOK(s, ProcessLimit) {
		return ErrInvalidSnapshot
	}
	seen := map[uint64]bool{}
	for _, x := range s.Items {
		if seen[x.PID] || x.PID == 0 || x.PID > MaxSafeInteger || !uintOK(x.ParentPID) || !validString(x.Name, 64, false) || strings.ContainsAny(x.Name, "/\\") || !oneOf(x.State, "running", "sleeping", "stopped", "zombie", "idle", "unknown") || !uintOK(x.RSSBytes) || !floatOK(x.CPUTimeSeconds, float64(MaxSafeInteger)) || !uintOK(x.Threads) {
			return ErrInvalidSnapshot
		}
		seen[x.PID] = true
		if s.Meta.Complete && (x.ParentPID == nil || x.State == "unknown" || x.RSSBytes == nil || x.CPUTimeSeconds == nil || x.Threads == nil) {
			return ErrInvalidSnapshot
		}
	}
	return validateSectionBytes(s)
}

// ValidateSoftwareSection validates a standalone original dpkg sample.
func ValidateSoftwareSection(s SoftwareSection) error {
	if !ordinarySectionOK(s, SoftwareLimit) {
		return ErrInvalidSnapshot
	}
	seen := map[string]bool{}
	for _, x := range s.Items {
		key := x.Name + ":" + x.Architecture
		if seen[key] || !validString(x.Name, 128, false) || !packagePattern.MatchString(x.Name) || !validString(x.Version, 192, false) || !assessment.ValidDebianVersion(x.Version) || !validString(x.Architecture, 32, false) || !architecturePattern.MatchString(x.Architecture) || x.Manager != "dpkg" {
			return ErrInvalidSnapshot
		}
		seen[key] = true
	}
	return validateSectionBytes(s)
}

// ValidateEventSection validates original metadata groups against their own
// original collection window. observedCount is the total source-event count.
func ValidateEventSection(s EventSection) error {
	if !sectionOK(s, EventLimit, s.Meta.ObservedAt) {
		return ErrInvalidSnapshot
	}
	seen := map[string]bool{}
	var count uint64
	for _, x := range s.Items {
		key := x.Source + ":" + x.Unit + ":" + string(rune(x.Priority)) + ":" + x.MessageID
		if seen[key] || !oneOf(x.Source, "systemd-journal", "agent") || !validString(x.Unit, 128, true) || x.Unit != "" && !eventUnitPattern.MatchString(x.Unit) || x.Priority < 0 || x.Priority > 7 || x.MessageID != "" && !messagePattern.MatchString(x.MessageID) || x.Count == 0 || x.Count > MaxSafeInteger || !utc(x.FirstSeen) || !utc(x.LastSeen) || x.FirstSeen.After(x.LastSeen) || x.FirstSeen.Before(s.Meta.ObservedAt.Add(-15*time.Minute)) || x.LastSeen.After(s.Meta.ObservedAt) {
			return ErrInvalidSnapshot
		}
		seen[key] = true
		if count > MaxSafeInteger-x.Count {
			return ErrInvalidSnapshot
		}
		count += x.Count
	}
	if count > s.Meta.ObservedCount || s.Meta.Complete && count != s.Meta.ObservedCount {
		return ErrInvalidSnapshot
	}
	return validateSectionBytes(s)
}

func validateSectionBytes[T any](s Section[T]) error {
	b, err := json.Marshal(s)
	if err != nil || len(b) > MaxSnapshotBytes {
		return ErrInvalidSnapshot
	}
	return nil
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
