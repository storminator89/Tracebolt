package linuxpackages

import "time"

const (
	SchemaVersion    = "tracebolt.linux-packages.v1"
	SnapshotScope    = "agent-visible-dpkg"
	MaxSnapshotBytes = 16 << 10
	MaxExportRows    = 128
	MaxSafeInteger   = 1<<53 - 1
)

type Quality string

const (
	Healthy Quality = "healthy"
	Unknown Quality = "unknown"
	Denied  Quality = "denied"
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
	ReasonSourceChanged    Reason = "source_changed"
	ReasonItemLimit        Reason = "item_limit"
	ReasonByteLimit        Reason = "byte_limit"
	ReasonNotImplemented   Reason = "not_implemented"
	ReasonCollectorBusy    Reason = "collector_busy"
)

// Snapshot is a standalone component contract. Its enclosing profile-bound
// frame independently binds generation/time/profile and applies age/replay
// checks; this pure type does not grant provenance or assessment authority.
type Snapshot struct {
	SchemaVersion string             `json:"schemaVersion"`
	Scope         string             `json:"scope"`
	GenerationID  string             `json:"generationId"`
	CollectedAt   time.Time          `json:"collectedAt"`
	DurationMS    int64              `json:"durationMs"`
	Release       ReleaseObservation `json:"release"`
	Inventory     Inventory          `json:"inventory"`
}

type ReleaseObservation struct {
	Quality Quality       `json:"quality"`
	Reason  Reason        `json:"reason"`
	Fields  ReleaseFields `json:"fields"`
}

// Inventory counts describe a successful full source parse, never a parsed
// prefix. Unknown/denied sources have null counts and a non-null empty item list.
// InstalledCount excludes incomplete records; ObservedCount includes both.
// Trimming changes only selected rows and completeness, never source counts.
type Inventory struct {
	Quality        Quality      `json:"quality"`
	Reason         Reason       `json:"reason"`
	Complete       bool         `json:"complete"`
	Truncated      bool         `json:"truncated"`
	CountExact     bool         `json:"countExact"`
	ObservedCount  *uint64      `json:"observedCount"`
	InstalledCount *uint64      `json:"installedCount"`
	Items          []PackageRow `json:"items"`
}
