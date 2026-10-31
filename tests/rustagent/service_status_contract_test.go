package rustagent

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"localrmm/internal/windowsmanaged"
)

// The Rust unit test compares its invented API-shaped collector output exactly
// with this fixture. Go validates that section with the actual unchanged ingress
// snapshot decoder. No host API, enrollment, grant or network read is performed.
func TestRustServiceStatusSectionMatchesManagerContract(t *testing.T) {
	raw, err := os.ReadFile("fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var frame map[string]json.RawMessage
	if err := json.Unmarshal(raw, &frame); err != nil {
		t.Fatal(err)
	}
	var inventory map[string]json.RawMessage
	if err := json.Unmarshal(frame["windowsInventory"], &inventory); err != nil {
		t.Fatal(err)
	}
	section, err := os.ReadFile("service-status-section.json")
	if err != nil {
		t.Fatal(err)
	}
	inventory["services"] = section
	candidate, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := windowsmanaged.Decode(candidate)
	if err != nil {
		t.Fatal("inert Rust service section rejected:", err)
	}
	if snapshot.Services.ObservedCount != 1 || len(snapshot.Services.Rows) != 1 || snapshot.Services.Rows[0].Name != "InventedService" || !snapshot.Services.Complete {
		t.Fatal("invented source contract changed")
	}
	if snapshot.Software.Complete || snapshot.Processes.Complete || snapshot.Network.Complete || snapshot.Hostname.Complete {
		t.Fatal("service fixture widened unrelated scope")
	}
}

func TestRustServicePortRemainsOutsideBasicProductionBuild(t *testing.T) {
	lib, err := os.ReadFile("../../rust/windows-agent/src/lib.rs")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lib), "#[cfg(test)]\nmod inventory_services;") {
		t.Fatal("inert collector must not enter production without independent authority review")
	}
	for _, path := range []string{
		"rust/windows-agent/src/native.rs", "rust/windows-agent/src/main.rs",
		"rust/windows-agent/src/runtime.rs", "rust/windows-agent/src/protocol.rs",
		"rust/windows-agent/src/sender.rs", "rust/windows-agent/src/service.rs",
		"rust/windows-agent/src/config.rs", "deploy/windows-rust/Install-Tracebolt.ps1",
	} {
		raw, err := os.ReadFile("../../" + path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "inventory_services") || strings.Contains(string(raw), "AcknowledgeServiceStatus") {
			t.Fatal("Basic must not activate the candidate inventory scope:", path)
		}
	}
}
