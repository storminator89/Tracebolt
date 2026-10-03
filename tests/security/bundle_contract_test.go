package security_test

import (
	"encoding/json"
	"localrmm/internal/bundle"
	"localrmm/internal/collector"
	"localrmm/internal/model"
	"testing"
	"time"
)

func localRoleFixture() model.Device {
	at := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	metric := model.Metric{Unit: "%", Quality: "unknown", Source: "collector policy", CollectedAt: at}
	return model.Device{ID: "sandbox-local", Name: "Local sandbox", Platform: "linux",
		OS: "Linux", Site: "Cloud sandbox", Group: "Local observations", Status: "unknown",
		Source: "sandbox", LastSeen: at, AgentVersion: "0.1.0", CPU: metric, Memory: metric,
		Disk: metric, Uptime: "Unknown", Tags: []string{"sandbox", "read-only", "local-only"},
		Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
}

func TestSupportBundleCurrentCollectorEnvelope(t *testing.T) {
	observation := collector.Snapshot()
	if observation.Platform != "linux" && observation.Platform != "windows" && observation.Platform != "macos" {
		t.Skip("This bundle contract intentionally supports only Linux, Windows and macOS")
	}
	encoded, err := bundle.Encode(observation)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > bundle.MaxBytes {
		t.Fatal("serialized byte cap exceeded")
	}
	var value map[string]any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	device := value["observation"].(map[string]any)
	if device["status"] != "unknown" || device["ip"] != nil || device["synthetic"] != false {
		t.Fatal("unexpected health, identity, or provenance")
	}
	for _, key := range []string{"tags", "capabilities", "evidence", "trend", "caseIds"} {
		if _, ok := device[key].([]any); !ok {
			t.Errorf("%s must be a JSON array", key)
		}
	}
}

func TestSupportBundleRejectsUnavailableHealthyMetric(t *testing.T) {
	observation := localRoleFixture()
	observation.CPU.Quality = "healthy"
	if _, err := bundle.Encode(observation); err == nil {
		t.Fatal("a healthy metric must contain a value")
	}
}

func TestSupportBundleDoesNotEmitNullArrays(t *testing.T) {
	observation := localRoleFixture()
	observation.Tags, observation.Capabilities, observation.Evidence = nil, nil, nil
	observation.Trend, observation.CaseIDs = nil, nil
	encoded, err := bundle.Encode(observation)
	if err != nil {
		return
	} // Rejecting incomplete observations is also valid.
	var value map[string]any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	device := value["observation"].(map[string]any)
	for _, key := range []string{"tags", "capabilities", "evidence", "trend", "caseIds"} {
		if _, ok := device[key].([]any); !ok {
			t.Errorf("%s must be a JSON array, not null", key)
		}
	}
}

func TestSupportBundleRejectsRoleMetadataReuse(t *testing.T) {
	cases := map[string]func(*model.Device){
		"hostname":          func(d *model.Device) { d.Name = "private-host.example" },
		"account":           func(d *model.Device) { d.Site = "account-123" },
		"host identifier":   func(d *model.Device) { d.ID = "host-123" },
		"address":           func(d *model.Device) { ip := "192.0.2.123"; d.IP = &ip },
		"unexpected tag":    func(d *model.Device) { d.Tags = append(d.Tags, "secret-value") },
		"platform mismatch": func(d *model.Device) { d.Platform = "windows" },
		"health claim":      func(d *model.Device) { d.Status = "healthy" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			observation := localRoleFixture()
			change(&observation)
			if _, err := bundle.Encode(observation); err == nil {
				t.Fatal("unexpected metadata accepted")
			}
		})
	}
}
