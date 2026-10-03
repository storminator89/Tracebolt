package lanstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"localrmm/internal/bundle"
	"localrmm/internal/model"
)

func boundaryFrame(t *testing.T) (Frame, time.Time) {
	t.Helper()
	at := time.Unix(1800000000, 123456789).UTC()
	m := model.Metric{Unit: "%", Quality: "unknown", Source: "Disposable fixture", CollectedAt: at}
	d := model.Device{ID: "sandbox-local", Name: "Local sandbox", Platform: "linux", OS: "Fixture OS", Site: "Cloud sandbox", Group: "Local observations", Status: "unknown", Source: "sandbox", LastSeen: at, AgentVersion: "test", CPU: m, Memory: m, Disk: m, Uptime: "unknown", Tags: []string{}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
	for n := range 16 {
		d.Evidence = append(d.Evidence, model.Evidence{ID: fmt.Sprintf("evidence-%d", n), Title: "Fixture", Source: "Fixture", Quality: "unknown", CollectedAt: at, Value: "fixture"})
	}
	b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "test", GeneratedAt: at, Platform: "linux", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: d}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	remaining := bundle.MaxBytes - len(raw)
	for n := range b.Observation.Evidence {
		count := remaining
		if count > 4096 {
			count = 4096
		}
		b.Observation.Evidence[n].Detail = strings.Repeat("x", count)
		remaining -= count
	}
	if remaining != 0 {
		t.Fatal("fixture could not fill original envelope")
	}
	raw, err = json.Marshal(b)
	if err != nil || len(raw) != bundle.MaxBytes {
		t.Fatal("original envelope is not exactly at bound")
	}
	return Frame{SchemaVersion: FrameVersion, Sequence: 1, Observation: b}, at
}
func TestOriginalEnvelopeBoundaryIsDeterministic(t *testing.T) {
	frame, at := boundaryFrame(t)
	// A newly generated pretty-printed support bundle has different metadata and
	// is larger. Encoding still applies its own unchanged output-size contract.
	if _, err := bundle.Encode(frame.Observation.Observation); err == nil {
		t.Fatal("fixture must distinguish generated versus original envelopes")
	}
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		if _, err = ValidateFrame(raw, at); err != nil {
			t.Fatal("actual within-bound envelope rejected:", err)
		}
	}
	padded := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), MaxFrameBytes-len(raw))...)
	if _, err = ValidateFrame(padded, at); err != nil {
		t.Fatal("exact wire-cap frame rejected")
	}
	if _, err = ValidateFrame(append(padded, ' '), at); err == nil {
		t.Fatal("over-wire-cap frame accepted")
	}
	for n := range frame.Observation.Observation.Evidence {
		if len(frame.Observation.Observation.Evidence[n].Detail) < 4096 {
			frame.Observation.Observation.Evidence[n].Detail += "x"
			break
		}
	}
	raw, err = json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ValidateFrame(raw, at); err == nil {
		t.Fatal("over-bound original envelope accepted")
	}
}
