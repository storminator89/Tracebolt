// Package systeminventory defines bounded operator-only service and socket
// observations. It is independent of runtime consent, transport and retention.
package systeminventory

import (
	"errors"
	"time"
)

const (
	SchemaVersion                = "tracebolt.linux-system-inventory.v1"
	SnapshotScope                = "agent-visible-linux-system"
	MaxServiceRows               = 8192
	MaxSocketRows                = 16384
	MaxSectionBytes              = 512 << 10
	MaxSnapshotBytes             = 1 << 20
	MaxRawSourceBytes            = 8 << 20
	MaxOwnersPerSocket           = 16
	MaxProcessEntries            = 32768
	MaxFDEntriesPerProcess       = 4096
	MaxTotalFDEntries            = 262144
	MaxDirectoryEntries          = 65536
	MaxProcessNameBytes          = 64
	MaxSafeInteger         int64 = 1<<53 - 1
	CollectionTimeout            = 15 * time.Second
	CommandTimeout               = 4 * time.Second
	AttributionTimeout           = 5 * time.Second
)

var (
	ErrInvalidSnapshot = errors.New("system_inventory_invalid")
	ErrSnapshotLimit   = errors.New("system_inventory_limit")
	ErrInvalidInput    = errors.New("system_inventory_invalid_input")
	ErrInvalidSource   = errors.New("system_inventory_invalid_source")
	ErrSourceLimit     = errors.New("system_inventory_source_limit")
	ErrItemLimit       = errors.New("system_inventory_item_limit")
)

type Reason string

const (
	ReasonNone             Reason = "none"
	ReasonSourceMissing    Reason = "source_missing"
	ReasonPermissionDenied Reason = "permission_denied"
	ReasonNotSupported     Reason = "not_supported"
	ReasonTimeout          Reason = "timeout"
	ReasonInvalidSource    Reason = "invalid_source"
	ReasonReadFailed       Reason = "read_failed"
	ReasonItemLimit        Reason = "item_limit"
	ReasonByteLimit        Reason = "byte_limit"
	ReasonCollectorBusy    Reason = "collector_busy"
	ReasonNotCollected     Reason = "not_collected"
	ReasonNoMatch          Reason = "no_match"
	ReasonProcessGone      Reason = "process_gone"
	ReasonWorkLimit        Reason = "work_limit"
	ReasonOwnerLimit       Reason = "owner_limit"
)

type Coverage string

const (
	Complete Coverage = "complete"
	Failed   Coverage = "failed"
)

type AttributionCoverage string

const (
	AttributionObserved    AttributionCoverage = "observed"
	AttributionPartial     AttributionCoverage = "partial"
	AttributionUnavailable AttributionCoverage = "unavailable"
)

type Snapshot struct {
	SchemaVersion string         `json:"schemaVersion"`
	GenerationID  string         `json:"generationId"`
	CollectedAt   time.Time      `json:"collectedAt"`
	DurationMS    int64          `json:"durationMs"`
	Scope         string         `json:"scope"`
	Services      ServiceSection `json:"services"`
	Sockets       SocketSection  `json:"sockets"`
}
type SectionMeta struct {
	GenerationID  string    `json:"generationId"`
	ObservedAt    time.Time `json:"observedAt"`
	Coverage      Coverage  `json:"coverage"`
	Reason        Reason    `json:"reason"`
	ObservedCount *uint64   `json:"observedCount"`
	CountExact    bool      `json:"countExact"`
}
type Section[T any] struct {
	Meta  SectionMeta `json:"meta"`
	Items []T         `json:"items"`
}
type ServiceSection = Section[Service]
type SocketSection = Section[Socket]
type Service struct {
	Name       string          `json:"name"`
	Runtime    *ServiceRuntime `json:"runtime"`
	Enablement *string         `json:"enablement"`
	MainPID    *uint32         `json:"mainPid"`
}
type ServiceRuntime struct {
	LoadState   string `json:"loadState"`
	ActiveState string `json:"activeState"`
	SubState    string `json:"subState"`
}
type Endpoint struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}
type Socket struct {
	Protocol    string      `json:"protocol"`
	Family      string      `json:"family"`
	Kind        string      `json:"kind"`
	Local       Endpoint    `json:"local"`
	Remote      Endpoint    `json:"remote"`
	State       string      `json:"state"`
	Owners      []Owner     `json:"owners"`
	Attribution Attribution `json:"attribution"`
}
type Owner struct {
	PID         uint32  `json:"pid"`
	ProcessName *string `json:"processName"`
	NameReason  Reason  `json:"nameReason"`
}
type Attribution struct {
	Coverage AttributionCoverage `json:"coverage"`
	Reason   Reason              `json:"reason"`
}

// ObservedSocket's inode is transient source correlation, never a wire member.
type ObservedSocket struct {
	Row   Socket
	Inode uint64
}
type AttributionResult struct {
	Owners      []Owner
	Attribution Attribution
}

// Empty is a failed attempt, never a successful zero-row observation. Identity
// and time are checked by Validate/Encode; no source is accessed here.
func Empty(generationID string, at time.Time, reason Reason) Snapshot {
	if !validFailureReason(reason) {
		reason = ReasonReadFailed
	}
	return Snapshot{SchemaVersion: SchemaVersion, GenerationID: generationID, CollectedAt: at, Scope: SnapshotScope,
		Services: failedSection[Service](generationID, at, reason), Sockets: failedSection[Socket](generationID, at, reason)}
}
func failedSection[T any](id string, at time.Time, reason Reason) Section[T] {
	return Section[T]{Meta: SectionMeta{GenerationID: id, ObservedAt: at, Coverage: Failed, Reason: reason}, Items: []T{}}
}
func completeSection[T any](id string, at time.Time, rows []T) Section[T] {
	n := uint64(len(rows))
	if rows == nil {
		rows = []T{}
	}
	return Section[T]{Meta: SectionMeta{GenerationID: id, ObservedAt: at, Coverage: Complete, Reason: ReasonNone, ObservedCount: &n, CountExact: true}, Items: rows}
}
