package collector

import (
	"encoding/json"
	"math"
	"runtime"
	"testing"
	"time"

	"localrmm/internal/model"
)

func TestPercentMetricRejectsInvalid(t *testing.T) {
	for _, value := range []float64{-1, 101, math.NaN(), math.Inf(1), math.Inf(-1)} {
		metric := percentMetric(value, "fixture", time.Now())
		if metric.Value != nil || metric.Quality != "unknown" {
			t.Errorf("invalid value %v did not become unknown: %+v", value, metric)
		}
	}
	for _, value := range []float64{0, 0.25, 99.9, 100} {
		metric := percentMetric(value, "fixture", time.Now())
		if metric.Value == nil || *metric.Value != value || metric.Quality != "healthy" {
			t.Errorf("valid value %v lost: %+v", value, metric)
		}
	}
}

func TestSnapshotRealSample(t *testing.T) {
	start := time.Now().UTC()
	sample := Snapshot()
	wantID, wantSource := "sandbox-local", "sandbox"
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		wantID, wantSource = "local-"+platformName(runtime.GOOS), "local"
	}
	if sample.ID != wantID || sample.Source != wantSource || sample.Synthetic {
		t.Fatalf("wrong scope or provenance: %+v", sample)
	}
	if sample.Status != "unknown" || sample.IP != nil {
		t.Errorf("incomplete coverage must not claim health or collect IP addresses")
	}
	if sample.LastSeen.Before(start) || sample.LastSeen.After(time.Now().UTC()) {
		t.Errorf("last seen not from this observation: %v", sample.LastSeen)
	}
	for name, metric := range map[string]model.Metric{"cpu": sample.CPU, "memory": sample.Memory, "disk": sample.Disk} {
		if metric.Source == "" || metric.CollectedAt.IsZero() || metric.Unit != "%" {
			t.Errorf("%s missing provenance: %+v", name, metric)
		}
		if metric.Value == nil {
			if metric.Quality != "unknown" && metric.Quality != "denied" {
				t.Errorf("%s missing data must remain unknown/denied, got %q", name, metric.Quality)
			}
		} else if math.IsNaN(*metric.Value) || math.IsInf(*metric.Value, 0) || *metric.Value < 0 || *metric.Value > 100 || metric.Quality != "healthy" {
			t.Errorf("%s invalid value or quality: %+v", name, metric)
		}
	}
	if len(sample.Evidence) == 0 || len(sample.Capabilities) == 0 {
		t.Error("scope limitations must be exposed")
	}
	for _, capability := range sample.Capabilities {
		switch capability.Status {
		case "supported", "limited", "unsupported", "denied":
		default:
			t.Errorf("capability %s has invalid status: %s", capability.ID, capability.Status)
		}
	}
	if len(sample.Trend) != 0 {
		t.Error("one snapshot must not invent a trend")
	}
	if _, err := json.Marshal(sample); err != nil {
		t.Errorf("snapshot not valid JSON: %v", err)
	}
}

func TestPlatformName(t *testing.T) {
	for input, want := range map[string]string{"darwin": "macos", "linux": "linux", "windows": "windows"} {
		if got := platformName(input); got != want {
			t.Errorf("platformName(%q) = %q; want %q", input, got, want)
		}
	}
}

func TestCapabilityStatus(t *testing.T) {
	for quality, want := range map[string]string{"healthy": "supported", "unknown": "limited", "denied": "denied", "stale": "limited"} {
		if got := capabilityStatus(quality); got != want {
			t.Errorf("capabilityStatus(%q) = %q; want %q", quality, got, want)
		}
	}
}
