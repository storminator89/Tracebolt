// Package completeoverview defines complete-enumeration, namespace-scoped Linux
// process and mounted-filesystem observations. It is inert until explicitly
// invoked and does not grant consent, transmit data or alter the host.
package completeoverview

import (
	"errors"
	"time"
)

const (
	SchemaVersion              = "tracebolt.linux-complete-overview.v1"
	SnapshotScope              = "agent-visible-linux-namespaces"
	MaxProcessRows             = 32768
	MaxVolumeRows              = 16384
	MaxDirectoryEntries        = 65536
	MaxPinnedMounts            = 1024
	DescriptorReserve          = 128
	MaxSectionBytes            = 16 << 20
	MaxSnapshotBytes           = 24 << 20
	MaxMountInfoBytes          = 16 << 20
	MaxMountLineBytes          = 64 << 10
	MaxProcessStatBytes        = 16 << 10
	MaxSourceBytes             = 128 << 20
	MaxProcessNameBytes        = 64
	MaxMountPathBytes          = 4096
	MaxSafeInteger      uint64 = 1<<53 - 1
	CollectionTimeout          = 15 * time.Second
)

var (
	ErrInvalidSnapshot = errors.New("complete_overview_invalid")
	ErrSnapshotLimit   = errors.New("complete_overview_limit")
	ErrInvalidInput    = errors.New("complete_overview_invalid_input")
	ErrInvalidSource   = errors.New("complete_overview_invalid_source")
	ErrSourceLimit     = errors.New("complete_overview_source_limit")
	ErrItemLimit       = errors.New("complete_overview_item_limit")
)

type Reason string

const (
	ReasonNone                    Reason = "none"
	ReasonSourceMissing           Reason = "source_missing"
	ReasonPermissionDenied        Reason = "permission_denied"
	ReasonNotSupported            Reason = "not_supported"
	ReasonTimeout                 Reason = "timeout"
	ReasonInvalidSource           Reason = "invalid_source"
	ReasonReadFailed              Reason = "read_failed"
	ReasonItemLimit               Reason = "item_limit"
	ReasonByteLimit               Reason = "byte_limit"
	ReasonCollectorBusy           Reason = "collector_busy"
	ReasonNotCollected            Reason = "not_collected"
	ReasonProcessGone             Reason = "process_gone"
	ReasonMountChanged            Reason = "mount_changed"
	ReasonRemoteFilesystemSkipped Reason = "remote_filesystem_skipped"
	ReasonNotApplicable           Reason = "not_applicable"
)

type Coverage string

const (
	Complete Coverage = "complete"
	Failed   Coverage = "failed"
)

type Status string

const (
	Observed      Status = "observed"
	Denied        Status = "denied"
	Exited        Status = "exited"
	Invalid       Status = "invalid"
	Unsupported   Status = "unsupported"
	Unavailable   Status = "unavailable"
	NotApplicable Status = "not_applicable"
)

type Observation struct {
	Status Status `json:"status"`
	Reason Reason `json:"reason"`
}
type Snapshot struct {
	SchemaVersion     string         `json:"schemaVersion"`
	GenerationID      string         `json:"generationId"`
	CaptureStartedAt  time.Time      `json:"captureStartedAt"`
	CaptureFinishedAt time.Time      `json:"captureFinishedAt"`
	Scope             string         `json:"scope"`
	Processes         ProcessSection `json:"processes"`
	Volumes           VolumeSection  `json:"volumes"`
}
type SectionMeta struct {
	GenerationID  string        `json:"generationId"`
	Coverage      Coverage      `json:"coverage"`
	Reason        Reason        `json:"reason"`
	ObservedCount *uint64       `json:"observedCount"`
	CountExact    bool          `json:"countExact"`
	FieldCoverage FieldCoverage `json:"fieldCoverage"`
}

// FieldCoverage counts every row outcome separately from enumeration coverage.
// Complete enumeration does not assert that details/capacities were readable.
type FieldCoverage struct {
	Observed      uint64 `json:"observed"`
	Denied        uint64 `json:"denied"`
	Exited        uint64 `json:"exited"`
	Invalid       uint64 `json:"invalid"`
	Unsupported   uint64 `json:"unsupported"`
	Unavailable   uint64 `json:"unavailable"`
	NotApplicable uint64 `json:"notApplicable"`
}
type Section[T any] struct {
	Meta  SectionMeta `json:"meta"`
	Items []T         `json:"items"`
}
type ProcessSection = Section[Process]
type VolumeSection = Section[Volume]

// Observation applies to all nullable metrics. Missing rows are never substituted
// for permission-denied or exited processes; PID remains the enumerated identity.
type Process struct {
	PID            uint32      `json:"pid"`
	ParentPID      *uint32     `json:"parentPid"`
	Name           *string     `json:"name"`
	State          *string     `json:"state"`
	RSSBytes       *uint64     `json:"rssBytes"`
	CPUTimeSeconds *float64    `json:"cpuTimeSeconds"`
	Threads        *uint32     `json:"threads"`
	Observation    Observation `json:"observation"`
}

// FilesystemGroup is a namespace-local major:minor grouping hint. Equal groups
// must never be summed. Unequal groups still do not establish physical disks or
// independent capacity (subvolumes, layered filesystems and pools may overlap).
type Volume struct {
	ID              string      `json:"id"`
	MountPoint      string      `json:"mountPoint"`
	Filesystem      string      `json:"filesystem"`
	Kind            string      `json:"kind"`
	FilesystemGroup string      `json:"filesystemGroup"`
	CapacityScope   string      `json:"capacityScope"`
	TotalBytes      *uint64     `json:"totalBytes"`
	AvailableBytes  *uint64     `json:"availableBytes"`
	UsedPercent     *float64    `json:"usedPercent"`
	Measurement     Observation `json:"measurement"`
}

func Empty(id string, at time.Time, reason Reason) Snapshot {
	if !validFailureReason(reason) {
		reason = ReasonReadFailed
	}
	return Snapshot{SchemaVersion: SchemaVersion, GenerationID: id, CaptureStartedAt: at, CaptureFinishedAt: at, Scope: SnapshotScope,
		Processes: failedSection[Process](id, reason), Volumes: failedSection[Volume](id, reason)}
}
func failedSection[T any](id string, r Reason) Section[T] {
	return Section[T]{Meta: SectionMeta{GenerationID: id, Coverage: Failed, Reason: r}, Items: []T{}}
}
func completeSection[T any](id string, rows []T) Section[T] {
	if rows == nil {
		rows = []T{}
	}
	n := uint64(len(rows))
	counts := FieldCoverage{}
	for _, row := range rows {
		var o Observation
		switch v := any(row).(type) {
		case Process:
			o = v.Observation
		case Volume:
			o = v.Measurement
		}
		counts.add(o.Status)
	}
	return Section[T]{Meta: SectionMeta{GenerationID: id, Coverage: Complete, Reason: ReasonNone, ObservedCount: &n, CountExact: true, FieldCoverage: counts}, Items: rows}
}
func ptr[T any](v T) *T { return &v }

func (c *FieldCoverage) add(s Status) {
	switch s {
	case Observed:
		c.Observed++
	case Denied:
		c.Denied++
	case Exited:
		c.Exited++
	case Invalid:
		c.Invalid++
	case Unsupported:
		c.Unsupported++
	case Unavailable:
		c.Unavailable++
	case NotApplicable:
		c.NotApplicable++
	}
}
func (c FieldCoverage) valid(n uint64) bool {
	left := n
	for _, x := range []uint64{c.Observed, c.Denied, c.Exited, c.Invalid, c.Unsupported, c.Unavailable, c.NotApplicable} {
		if x > left {
			return false
		}
		left -= x
	}
	return left == 0
}
