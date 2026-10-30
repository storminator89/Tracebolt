package rustagent

import (
	"encoding/json"
	"localrmm/internal/bundle"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsmanaged"
	"os"
	"testing"
	"time"
)

// The fixture contains invented data emitted by the Rust wire_fixture example.
// This exercises the actual Go ingress validator, not a reimplementation of it.
func TestRustFrameAcceptedByManager(t *testing.T) {
	raw, err := os.ReadFile("fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	if _, err := windowsmanaged.Decode(members["windowsInventory"]); err != nil {
		t.Fatal("inventory:", err)
	}
	var observation bundle.Bundle
	if err := json.Unmarshal(members["observation"], &observation); err != nil {
		t.Fatal(err)
	}
	if err := bundle.ValidateObservation(observation.Observation); err != nil {
		t.Fatal("bundle:", err)
	}
	frame, err := lanstore.ValidateFrame(raw, at)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Sequence != 1 || frame.WindowsInventory == nil || frame.WindowsInventory.Hostname.Complete {
		t.Fatal("invalid Rust scope")
	}
	if _, err := lanstore.ValidateFrame(raw, at.Add(3*time.Minute)); err == nil {
		t.Fatal("stale Rust frame accepted")
	}
}
