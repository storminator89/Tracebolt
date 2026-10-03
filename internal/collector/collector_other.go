//go:build !linux

package collector

import (
	"runtime"
	"time"

	"localrmm/internal/model"
)

// Snapshot on non-Linux platforms intentionally makes no collection claims.
// Cross-compilation is supported; native telemetry collection is not.
func Snapshot() model.Device {
	at := time.Now().UTC()
	d := baseDevice(platformName(runtime.GOOS), at)
	d.Status = "unknown"
	d.OS = runtime.GOOS + " (native collection unsupported)"
	d.CPU = unknownMetric("unknown", "native collection is not implemented for this platform", at)
	d.Memory = unknownMetric("unknown", "native collection is not implemented for this platform", at)
	d.Disk = unknownMetric("unknown", "native collection is not implemented for this platform", at)
	d.Capabilities = []model.Capability{
		{ID: "native_collection", Name: "Native collection", Status: "unsupported", Detail: "This build emits an explicit unsupported observation. Only Linux sandbox collection is implemented."},
		{ID: "remote_actions", Name: "Remote actions", Status: "unsupported", Detail: "No network ingestion, remote control, or command execution."},
	}
	d.Evidence = []model.Evidence{
		{ID: "sandbox-scope", Title: "Collection scope", Source: "collector policy", Quality: "unknown", CollectedAt: at, Value: "Native telemetry unavailable", Detail: "A cross-built executable is not evidence of native monitoring support. No platform metrics were collected.", Synthetic: false},
	}
	return d
}
