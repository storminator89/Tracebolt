// Package windowsmanaged defines the bounded Windows inventory transport
// contract. Collection happens only through an explicit Collect call; this
// package has no enrollment, persistence, network client, or service actions.
package windowsmanaged

import (
	"errors"
	"time"

	"localrmm/internal/windowsinventory"
)

const (
	SchemaVersion     = "tracebolt.windows-inventory.v1"
	CollectionProfile = "windows-inventory-v1"
	MaxSnapshotBytes  = 48 << 10
	MaxHostnameRows   = 1
	MaxProcessRows    = 128
	MaxServiceRows    = 128
	MaxSoftwareRows   = 128
	MaxNetworkRows    = 64
	MaxTextBytes      = 256
	MaxMetadataBytes  = 512
)

const (
	QualityHealthy     = "healthy"
	QualityPartial     = "partial"
	QualityDenied      = "denied"
	QualityUnavailable = "unavailable"
)

var (
	ErrInvalidSnapshot = errors.New("windows_inventory_invalid")
	ErrSnapshotLimit   = errors.New("windows_inventory_limit")
	ErrInvalidInput    = errors.New("windows_inventory_invalid_input")
	ErrInvalidReport   = errors.New("windows_inventory_invalid_report")
)

// Row types deliberately contain no commands, executable paths, owners,
// credentials, event content, socket observations, or service-control fields.
type Hostname = windowsinventory.Hostname
type Process = windowsinventory.Process
type Service = windowsinventory.Service
type Software = windowsinventory.Software
type InterfaceAddress = windowsinventory.InterfaceAddress

// Section counts rows observed by the native report before transport trimming.
// ObservedCount is a lower bound when CountExact is false. Even CountExact does
// not imply whole-machine visibility: Source and Scope retain the native API's
// visibility and exclusion boundaries. Complete means all rows in that scoped
// observation are carried here; a transport trim always clears Complete.
type Section[T any] struct {
	Source        string `json:"source"`
	Scope         string `json:"scope"`
	Quality       string `json:"quality"`
	ObservedCount uint32 `json:"observedCount"`
	CountExact    bool   `json:"countExact"`
	Complete      bool   `json:"complete"`
	Truncated     bool   `json:"truncated"`
	Rows          []T    `json:"rows"`
}

type Snapshot struct {
	SchemaVersion     string                    `json:"schemaVersion"`
	CollectionProfile string                    `json:"collectionProfile"`
	GenerationID      string                    `json:"generationId"`
	CollectedAt       time.Time                 `json:"collectedAt"`
	Hostname          Section[Hostname]         `json:"hostname"`
	Processes         Section[Process]          `json:"processes"`
	Services          Section[Service]          `json:"services"`
	Software          Section[Software]         `json:"software"`
	Network           Section[InterfaceAddress] `json:"network"`
}
