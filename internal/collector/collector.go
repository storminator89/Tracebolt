// Package collector produces one read-only, bounded local observation.
// It never inventories processes, accounts, networks, or another machine.
package collector

import (
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"localrmm/internal/model"
)

const AgentVersion = "0.1.0-sandbox"

func unknownMetric(quality, source string, at time.Time) model.Metric {
	return model.Metric{Unit: "%", Quality: quality, Source: source, CollectedAt: at}
}

func percentMetric(value float64, source string, at time.Time) model.Metric {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 100 {
		return unknownMetric("unknown", source, at)
	}
	return model.Metric{Value: &value, Unit: "%", Quality: "healthy", Source: source, CollectedAt: at}
}

func capabilityStatus(quality string) string {
	switch quality {
	case "healthy":
		return "supported"
	case "denied":
		return "denied"
	default:
		return "limited"
	}
}

func platformName(goos string) string {
	if goos == "darwin" {
		return "macos"
	}
	return goos
}

func baseDevice(platform string, at time.Time) model.Device {
	return model.Device{
		ID: "sandbox-local", Name: "Local sandbox", Platform: platform,
		OS: "Unknown", Site: "Cloud sandbox", Group: "Local observations",
		Status: "unknown", Source: "sandbox", Synthetic: false,
		LastSeen: at, AgentVersion: AgentVersion, Uptime: "Unknown",
		CPU:    unknownMetric("unknown", "not collected", at),
		Memory: unknownMetric("unknown", "not collected", at),
		Disk:   unknownMetric("unknown", "not collected", at),
		Tags:   []string{"sandbox", "read-only", "local-only"},
		Trend:  []float64{}, CaseIDs: []string{},
		Capabilities: []model.Capability{}, Evidence: []model.Evidence{},
	}
}

func metricEvidence(id, title string, metric model.Metric) model.Evidence {
	value := "Unavailable"
	if metric.Value != nil {
		value = fmt.Sprintf("%.1f%%", *metric.Value)
	}
	return model.Evidence{
		ID: id, Title: title, Source: metric.Source, Quality: metric.Quality,
		CollectedAt: metric.CollectedAt, Value: value, Synthetic: false,
		Detail: "One local observation. This value does not establish device health or physical-host scope.",
	}
}

func errorQuality(err error) string {
	if errors.Is(err, os.ErrPermission) {
		return "denied"
	}
	return "unknown"
}

func diskPercent(blocks, free uint64) (float64, bool) {
	if blocks == 0 || free > blocks {
		return 0, false
	}
	return 100 * (float64(blocks-free) / float64(blocks)), true
}

func formatUptime(duration time.Duration) string {
	minutes := int64(duration / time.Minute)
	return fmt.Sprintf("%dd %dh %dm", minutes/(24*60), (minutes/60)%24, minutes%60)
}
