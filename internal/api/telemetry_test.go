package api

import (
	"encoding/json"
	"localrmm/internal/bundle"
	"localrmm/internal/collector"
	"localrmm/internal/model"
	"localrmm/internal/telemetry"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestManagedPreviewDisabledByDefault(t *testing.T) {
	s := setup(t)
	if s.managedPreviewEnabled() {
		t.Fatal("preview enabled by default")
	}
	if w := request(s, "GET", "/api/dev/telemetry/status", "", nil); w.Code != 404 {
		t.Fatal("disabled status route available")
	}
	if w := request(s, "POST", "/api/dev/telemetry", `{}`, nil); w.Code != 404 {
		t.Fatal("disabled ingestion available")
	}
}
func TestManagedPreviewDoesNotFallBackToManagerSample(t *testing.T) {
	s := setup(t)
	s.EnableManagedPreview(telemetry.NewState())
	s.SetSample(model.Device{ID: "unexpected-manager-direct-sample", Status: "healthy"})
	d := s.sampleDevice()
	if d.ID != "sandbox-local" || d.CPU.Value != nil || d.Memory.Value != nil || d.Disk.Value != nil || d.Status == "healthy" {
		t.Fatal("unreceived telemetry was replaced by manager observations")
	}
}
func TestManagedPreviewHTTPGuardsAndRealSample(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fixed Linux developer transport")
	}
	s := setup(t)
	state := telemetry.NewState()
	s.EnableManagedPreview(state)
	raw, err := bundle.Encode(collector.Snapshot())
	if err != nil {
		t.Fatal("local bundle could not encode")
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }, func(r *http.Request) { r.Host = "other.invalid" }} {
		if w := request(s, "POST", "/api/dev/telemetry", string(raw), change); w.Code != 403 {
			t.Fatal("ingestion bypassed local guard")
		}
	}
	response := request(s, "POST", "/api/dev/telemetry", string(raw), nil)
	if response.Code != 200 {
		t.Fatal("valid real local telemetry rejected", response.Code)
	}
	var receipt telemetry.Receipt
	if json.Unmarshal(response.Body.Bytes(), &receipt) != nil || receipt.Sequence != 1 || receipt.DeviceID != "sandbox-local" {
		t.Fatal("invalid receipt")
	}
	if status := state.Status(time.Now().UTC()); status.State != "fresh" || status.AcceptedSamples != 1 {
		t.Fatal("accepted sample did not become fresh")
	}
	d := s.sampleDevice()
	if !d.LastSeen.Equal(receipt.CollectedAt) || d.Synthetic || d.CPU.Value == nil {
		t.Fatal("UI device did not reflect separate sample")
	}
	s.SetSample(model.Device{ID: "fallback-forbidden", Status: "healthy"})
	if got := s.sampleDevice(); got.ID != "sandbox-local" || !got.LastSeen.Equal(receipt.CollectedAt) {
		t.Fatal("manager direct collection replaced imported sample")
	}
	if w := request(s, "POST", "/api/dev/telemetry", string(raw), nil); w.Code != 409 {
		t.Fatal("replay accepted")
	}
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		t.Fatal("test JSON invalid")
	}
	object["observation"].(map[string]any)["id"] = "unapproved-device-identity"
	bad, _ := json.Marshal(object)
	for _, body := range []string{string(bad), `{"schemaVersion":"tracebolt.support.v1","schemaVersion":"tracebolt.support.v1"}`, `{"unexpected":true}`} {
		if w := request(s, "POST", "/api/dev/telemetry", body, nil); w.Code != 400 {
			t.Fatal("invalid telemetry accepted", w.Code)
		}
	}
	if w := request(s, "POST", "/api/dev/telemetry", strings.Repeat(" ", telemetry.MaxBodyBytes+1), nil); w.Code != 413 {
		t.Fatal("body cap not enforced")
	}
	if state.Status(time.Now().UTC()).AcceptedSamples != 1 {
		t.Fatal("rejected telemetry changed state")
	}
	statusResponse := request(s, "GET", "/api/dev/telemetry/status", "", nil)
	if statusResponse.Code != 200 {
		t.Fatal("enabled transport status unavailable")
	}
}
