package security_test

import (
	"context"
	"encoding/json"
	"localrmm/internal/collector"
	"localrmm/internal/telemetry"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagedPreviewAwaitsWithoutFallback(t *testing.T) {
	state := telemetry.NewState()
	now := time.Now().UTC()
	if status := state.Status(now); status.State != "awaiting" || status.AcceptedSamples != 0 || status.ReceivedAt != nil {
		t.Fatal("empty manager pretended to have received telemetry")
	}
	device := state.Device(now)
	if device.Status != "unknown" || !device.LastSeen.IsZero() || device.CPU.Value != nil || device.Memory.Value != nil || device.Disk.Value != nil {
		t.Fatal("empty manager fabricated local telemetry")
	}
}

func TestManagedPreviewRejectsReplayWithoutRefreshing(t *testing.T) {
	raw, err := telemetry.EncodeForTransport(collector.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	state := telemetry.NewState()
	receipt, err := state.Accept(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Sequence != 1 {
		t.Fatal("first receipt sequence")
	}
	if _, err = state.Accept(raw, now.Add(time.Second)); err == nil {
		t.Fatal("replayed bundle accepted")
	}
	status := state.Status(now.Add(time.Second))
	if status.AcceptedSamples != 1 || !status.ReceivedAt.Equal(receipt.ReceivedAt) {
		t.Fatal("rejection refreshed state")
	}
	var modified map[string]any
	if err = json.Unmarshal(raw, &modified); err != nil {
		t.Fatal(err)
	}
	modified["observation"].(map[string]any)["name"] = "untrusted-hostname"
	bad, _ := json.Marshal(modified)
	if _, err = state.Accept(bad, now.Add(2*time.Second)); err == nil {
		t.Fatal("arbitrary identity accepted")
	}
	if state.Status(now).AcceptedSamples != 1 {
		t.Fatal("invalid identity changed state")
	}
}

func TestManagedPreviewOldestObservationAgesOut(t *testing.T) {
	device := collector.Snapshot()
	now := time.Now().UTC()
	device.CPU.CollectedAt = now.Add(-119 * time.Second)
	raw, err := telemetry.EncodeForTransport(device)
	if err != nil {
		t.Fatal(err)
	}
	state := telemetry.NewState()
	if _, err = state.Accept(raw, now); err != nil {
		t.Fatal(err)
	}
	if state.Status(now).State != "fresh" {
		t.Fatal("valid sample unexpectedly stale")
	}
	later := now.Add(2 * time.Second)
	if state.Status(later).State != "stale" {
		t.Fatal("oldest field stayed fresh past its age limit")
	}
	aged := state.Device(later)
	if aged.Status != "unknown" {
		t.Fatal("sample age asserted device health")
	}
	for _, metric := range []string{aged.CPU.Quality, aged.Memory.Quality, aged.Disk.Quality} {
		if metric == "healthy" {
			t.Fatal("aged sample retained a fresh quality claim")
		}
	}
}

func TestManagedPreviewReturnsIndependentCopies(t *testing.T) {
	raw, err := telemetry.EncodeForTransport(collector.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	state := telemetry.NewState()
	if _, err = state.Accept(raw, now); err != nil {
		t.Fatal(err)
	}
	first := state.Device(now)
	original := first.Evidence[0].Detail
	first.Evidence[0].Detail = "changed by consumer"
	if first.Memory.Value != nil {
		*first.Memory.Value = -1
	}
	second := state.Device(now)
	if second.Evidence[0].Detail != original || second.Memory.Value != nil && *second.Memory.Value < 0 {
		t.Fatal("consumer mutated stored state")
	}
}

func TestManagedClientLiteralTargetAndNoRedirect(t *testing.T) {
	for _, endpoint := range []string{"http://localhost:8787", "http://169.254.169.254:80", "http://192.168.1.1:8787", "http://127.0.0.1:8787/api", "http://user:pass@127.0.0.1:8787", "http://127.0.0.1:8787?secret=value"} {
		if _, err := telemetry.NewClient(endpoint, time.Second); err == nil {
			t.Errorf("noncanonical target accepted: %s", endpoint)
		}
	}
	var targetCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1); w.WriteHeader(500) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer redirect.Close()
	client, err := telemetry.NewClient(redirect.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := telemetry.EncodeForTransport(collector.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Send(context.Background(), raw); err == nil {
		t.Fatal("redirect was accepted")
	}
	if targetCalls.Load() != 0 {
		t.Fatal("redirect target was contacted")
	}
}
