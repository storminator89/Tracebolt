package collector

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"localrmm/internal/model"
)

// Native implementations have been cross-built and exercised with fixtures, but
// have not passed target-OS acceptance. A later invocation on a target machine
// is still not release acceptance; keep that distinction in every observation.
const nativeAgentVersion = "0.1.0-native-preview"
const nativeVerification = "nativeVerification: target-acceptance-unverified"
const maxNativeUptime = 10 * 366 * 24 * time.Hour
const nativeCPUSource = "collector policy: CPU interval sampling not implemented"

func nativeDevice(platform, name string, at time.Time) model.Device {
	d := baseDevice(platform, at)
	d.ID = "local-" + platform
	d.Name = name
	d.Site = "Local machine"
	d.AgentVersion = nativeAgentVersion
	d.Source = "local"
	d.Tags = []string{"read-only", "local-only", "native-unverified"}
	d.CPU = unknownMetric("unknown", nativeCPUSource, at)
	return d
}

func nativeEvidence(id, title, source, quality, value, detail string, at time.Time) model.Evidence {
	return model.Evidence{ID: id, Title: title, Source: source, Quality: quality,
		CollectedAt: at, Value: value, Detail: detail + " " + nativeVerification + ".", Synthetic: false}
}

func nativeMetricEvidence(id, title, detail string, metric model.Metric) model.Evidence {
	e := metricEvidence(id, title, metric)
	e.Detail = detail + " A healthy quality means valid collection, not device health. " + nativeVerification + "."
	return e
}

func nativeCapability(id, name, quality, detail string) model.Capability {
	return model.Capability{ID: id, Name: name, Status: capabilityStatus(quality), Detail: detail + " " + nativeVerification + "."}
}

func nativeLimitations() []model.Capability {
	return []model.Capability{
		{ID: "native_verification", Name: "Native OS acceptance", Status: "limited", Detail: nativeVerification + ". Cross-compilation and injected-provider tests do not verify target-OS execution, permissions, installation, or lifecycle."},
		{ID: "cpu", Name: "CPU sample", Status: "unsupported", Detail: "CPU interval sampling is not implemented; utilization remains unknown. " + nativeVerification + "."},
		{ID: "host_inventory", Name: "Physical host inventory", Status: "limited", Detail: "Local API scope does not establish physical-host attribution or isolation boundaries. " + nativeVerification + "."},
		{ID: "services", Name: "Service inventory", Status: "unsupported", Detail: "Service managers are not queried."},
		{ID: "logs", Name: "System logs", Status: "unsupported", Detail: "System and event logs are not read."},
		{ID: "remote_actions", Name: "Remote actions", Status: "unsupported", Detail: "No shell commands, process inventory, remote control, network ingestion, installation, or persistence."},
	}
}

func nativeScopeEvidence(platform string, at time.Time) model.Evidence {
	return nativeEvidence("local-scope", "Collection scope", "collector policy", "unknown", "Local "+platform+" API observation",
		"Fixed local sources only. Device ID and name are fixed labels, not machine identifiers. No hostname, IP, serial, user identifier, process list, or logs are collected. Overall device health and physical-host attribution remain unknown.", at)
}

func validNativeUptime(value time.Duration) bool {
	return value >= 0 && value <= maxNativeUptime
}

// Parse only a short numeric dotted version. Do not copy arbitrary kernel or
// provider text (which could contain identifiers or control characters) to JSON.
func validNativeVersion(value string) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}
	major, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || major == 0 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 8 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func nativeByteCapacity(value *uint64, err error) (string, string) {
	if err == nil && value != nil && *value > 0 && *value <= math.MaxInt64 {
		return fmt.Sprintf("%d bytes", *value), "healthy"
	}
	return "Unavailable", errorQuality(err)
}

// Native API capacities have no meaningful negative or all-ones sentinel value.
// Bound them before subtraction so undefined signed fields cannot look healthy.
func nativeCapacityPercent(total, available uint64) (float64, bool) {
	if total > math.MaxInt64 || available > math.MaxInt64 {
		return 0, false
	}
	return diskPercent(total, available)
}
