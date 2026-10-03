package security_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"localrmm/internal/bundle"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
)

func TestIndependentFrameValidationUsesIncomingEnvelope(t *testing.T) {
	at := time.Unix(1800000000, 0).UTC()
	metric := model.Metric{Unit: "%", Quality: "unknown", Source: "Synthetic fixture", CollectedAt: at}
	d := model.Device{ID: "sandbox-local", Name: "Local sandbox", Platform: "linux", OS: "Synthetic OS",
		Site: "Cloud sandbox", Group: "Local observations", Status: "unknown", Source: "sandbox", LastSeen: at,
		AgentVersion: "fixture", CPU: metric, Memory: metric, Disk: metric, Uptime: "unknown",
		Tags: []string{"read-only"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
	for i := 0; i < 16; i++ {
		d.Evidence = append(d.Evidence, model.Evidence{ID: fmt.Sprintf("fixture-%d", i), Title: "Synthetic evidence",
			Source: "Synthetic fixture", Quality: "unknown", CollectedAt: at, Value: "fixture"})
	}
	b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "fixture", GeneratedAt: at,
		Platform: "linux", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: d}
	// Fill legitimate bounded fields up to the actual incoming bundle limit.
	// There is no wall-clock-based sizing or regenerated exporter prose here.
	low, high := 0, 4096
	for low < high {
		mid := (low + high + 1) / 2
		for i := range b.Observation.Evidence {
			b.Observation.Evidence[i].Detail = strings.Repeat("x", mid)
		}
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) <= bundle.MaxBytes {
			low = mid
		} else {
			high = mid - 1
		}
	}
	for i := range b.Observation.Evidence {
		b.Observation.Evidence[i].Detail = strings.Repeat("x", low)
	}
	rawBundle, err := json.Marshal(b)
	if err != nil || len(rawBundle) > bundle.MaxBytes || len(rawBundle) < bundle.MaxBytes-32 {
		t.Fatal("boundary fixture did not reach the actual bundle cap")
	}
	raw, err := json.Marshal(lanstore.Frame{SchemaVersion: lanstore.FrameVersion, Sequence: 1, Observation: b})
	if err != nil || len(raw) > lanstore.MaxFrameBytes {
		t.Fatal("boundary fixture exceeded the wire cap")
	}
	if _, err := lanstore.ValidateFrame(raw, at); err != nil {
		t.Fatal("valid incoming envelope was rejected using an unrelated generated envelope")
	}
	// Exporting the same observation is a different operation with different
	// prose/pretty-print overhead. Its own actual 64 KiB cap must still hold.
	if encoded, err := bundle.Encode(b.Observation); err == nil && len(encoded) > bundle.MaxBytes {
		t.Fatal("exporter output cap was relaxed")
	}
	for i := range b.Observation.Evidence {
		b.Observation.Evidence[i].Detail = ""
	}
	b.Observation.Evidence[0].Detail = strings.Repeat("x", 4097)
	raw, _ = json.Marshal(lanstore.Frame{SchemaVersion: lanstore.FrameVersion, Sequence: 1, Observation: b})
	if _, err := lanstore.ValidateFrame(raw, at); err == nil {
		t.Fatal("per-field policy was lost while separating envelope validation")
	}
}
