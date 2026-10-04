// Package operational collects bounded, read-only Linux operational metadata.
// It does not execute operator input or send any observations over a network.
package operational

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

const (
	SchemaVersion            = "tracebolt.linux-operational.v1"
	CollectionProfile        = "managed-operations-v1"
	MaxSnapshotBytes         = 48 << 10
	MaxSafeInteger    uint64 = 1<<53 - 1
	VolumeLimit              = 32
	NetworkLimit             = 32
	ServiceLimit             = 128
	ProcessLimit             = 64
	SoftwareLimit            = 256
	EventLimit               = 64
)

type Quality string

const (
	Healthy Quality = "healthy"
	Unknown Quality = "unknown"
	Denied  Quality = "denied"
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
	ReasonRemoteFilesystemSkipped Reason = "remote_filesystem_skipped"
	ReasonToolUnavailable         Reason = "tool_unavailable"
	ReasonNotImplemented          Reason = "not_implemented"
)

type SectionMeta struct {
	GenerationID  string    `json:"generationId"`
	Quality       Quality   `json:"quality"`
	Reason        Reason    `json:"reason"`
	ObservedAt    time.Time `json:"observedAt"`
	Complete      bool      `json:"complete"`
	Truncated     bool      `json:"truncated"`
	ObservedCount uint64    `json:"observedCount"`
	CountExact    bool      `json:"countExact"`
	ItemLimit     int       `json:"itemLimit"`
}
type Section[T any] struct {
	Meta  SectionMeta `json:"meta"`
	Items []T         `json:"items"`
}
type VolumeSection = Section[Volume]
type NetworkSection = Section[NetworkInterface]
type ServiceSection = Section[Service]
type ProcessSection = Section[Process]
type SoftwareSection = Section[Software]
type EventSection = Section[Event]
type Snapshot struct {
	SchemaVersion     string    `json:"schemaVersion"`
	CollectionProfile string    `json:"collectionProfile"`
	GenerationID      string    `json:"generationId"`
	CollectedAt       time.Time `json:"collectedAt"`
	DurationMS        int64     `json:"durationMs"`
	Sections          Sections  `json:"sections"`
}
type Sections struct {
	Volumes   VolumeSection   `json:"volumes"`
	Network   NetworkSection  `json:"network"`
	Services  ServiceSection  `json:"services"`
	Processes ProcessSection  `json:"processes"`
	Software  SoftwareSection `json:"software"`
	Events    EventSection    `json:"events"`
}
type Volume struct {
	ID                 string   `json:"id"`
	MountPoint         string   `json:"mountPoint"`
	Filesystem         string   `json:"filesystem"`
	Kind               string   `json:"kind"`
	TotalBytes         *uint64  `json:"totalBytes"`
	AvailableBytes     *uint64  `json:"availableBytes"`
	UsedPercent        *float64 `json:"usedPercent"`
	MeasurementQuality Quality  `json:"measurementQuality"`
	MeasurementReason  Reason   `json:"measurementReason"`
}
type NetworkInterface struct {
	Name      string  `json:"name"`
	State     string  `json:"state"`
	MTU       *uint64 `json:"mtu"`
	RXBytes   *uint64 `json:"rxBytes"`
	TXBytes   *uint64 `json:"txBytes"`
	RXErrors  *uint64 `json:"rxErrors"`
	TXErrors  *uint64 `json:"txErrors"`
	IPv4Count *uint64 `json:"ipv4Count"`
	IPv6Count *uint64 `json:"ipv6Count"`
}
type Service struct {
	Name        string `json:"name"`
	LoadState   string `json:"loadState"`
	ActiveState string `json:"activeState"`
	SubState    string `json:"subState"`
}
type Process struct {
	PID            uint64   `json:"pid"`
	ParentPID      *uint64  `json:"parentPid"`
	Name           string   `json:"name"`
	State          string   `json:"state"`
	RSSBytes       *uint64  `json:"rssBytes"`
	CPUTimeSeconds *float64 `json:"cpuTimeSeconds"`
	Threads        *uint64  `json:"threads"`
}
type Software struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Manager      string `json:"manager"`
}
type Event struct {
	Source    string    `json:"source"`
	Unit      string    `json:"unit"`
	Priority  int       `json:"priority"`
	MessageID string    `json:"messageId"`
	Count     uint64    `json:"count"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// Empty returns an explicitly unavailable snapshot. It never represents an empty
// successful collection. Crypto/rand.Read either fills the observation label or
// terminates on entropy failure, avoiding a fabricated or reused generation ID.
func Empty(now time.Time, reason Reason) Snapshot {
	if !validReason(reason) || reason == ReasonNone {
		reason = ReasonReadFailed
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	s := Snapshot{SchemaVersion: SchemaVersion, CollectionProfile: CollectionProfile, GenerationID: "sample_" + hex.EncodeToString(b), CollectedAt: now.UTC()}
	s.Sections.Volumes = unavailable[Volume](now, VolumeLimit, reason)
	s.Sections.Network = unavailable[NetworkInterface](now, NetworkLimit, reason)
	s.Sections.Services = unavailable[Service](now, ServiceLimit, reason)
	s.Sections.Processes = unavailable[Process](now, ProcessLimit, reason)
	s.Sections.Software = unavailable[Software](now, SoftwareLimit, reason)
	s.Sections.Events = unavailable[Event](now, EventLimit, reason)
	stampGeneration(&s)
	return s
}
func unavailable[T any](now time.Time, limit int, reason Reason) Section[T] {
	q := Unknown
	if reason == ReasonPermissionDenied {
		q = Denied
	}
	return Section[T]{Meta: SectionMeta{Quality: q, Reason: reason, ObservedAt: now.UTC(), ItemLimit: limit, Truncated: reason == ReasonByteLimit || reason == ReasonItemLimit}, Items: []T{}}
}
func available[T any](now time.Time, limit int) Section[T] {
	return Section[T]{Meta: SectionMeta{Quality: Healthy, Reason: ReasonNone, ObservedAt: now.UTC(), Complete: true, CountExact: true, ItemLimit: limit}, Items: []T{}}
}
func partial(m *SectionMeta, r Reason, truncated bool) {
	m.Complete = false
	if m.Reason == ReasonNone || r == ReasonByteLimit || r == ReasonTimeout || r == ReasonPermissionDenied {
		m.Reason = r
	}
	m.Truncated = m.Truncated || truncated || r == ReasonItemLimit || r == ReasonByteLimit
}

func stampGeneration(s *Snapshot) {
	for _, m := range []*SectionMeta{&s.Sections.Volumes.Meta, &s.Sections.Network.Meta, &s.Sections.Services.Meta, &s.Sections.Processes.Meta, &s.Sections.Software.Meta, &s.Sections.Events.Meta} {
		m.GenerationID = s.GenerationID
	}
}
