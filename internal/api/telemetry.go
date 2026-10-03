package api

import (
	"errors"
	"fmt"
	"io"
	"localrmm/internal/model"
	"localrmm/internal/telemetry"
	"net/http"
	"time"
)

// EnableManagedPreview is an explicit developer-only, in-memory transport mode.
// It is not enrollment or endpoint authentication. Its source never falls back
// to the manager's own collector when a sample is absent, stale or rejected.
func (s *Server) EnableManagedPreview(state *telemetry.State) {
	if state == nil {
		return
	}
	s.mu.Lock()
	s.managedPreview = state
	s.sample = model.Device{}
	s.mu.Unlock()
}
func (s *Server) previewState() *telemetry.State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.managedPreview
}
func (s *Server) managedPreviewEnabled() bool { return s.previewState() != nil }
func (s *Server) telemetryStatus(w http.ResponseWriter) {
	state := s.previewState()
	if state == nil {
		fail(w, 404, "managed_preview_disabled", "Managed preview is disabled. Start the manager with --managed-preview to test the local developer transport.")
		return
	}
	write(w, 200, state.Status(time.Now().UTC()))
}
func (s *Server) receiveTelemetry(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeJSONMutation(w, r) {
		return
	}
	state := s.previewState()
	if state == nil {
		fail(w, 404, "managed_preview_disabled", "Managed preview is disabled. No telemetry was accepted.")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, telemetry.MaxBodyBytes))
	if err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			fail(w, 413, "payload_too_large", "Telemetry exceeds the 64 KiB limit.")
		} else {
			fail(w, 400, "invalid_bundle", "Telemetry body could not be read.")
		}
		return
	}
	receipt, err := state.Accept(raw, time.Now().UTC())
	if err != nil {
		var invalid *telemetry.Error
		if errors.As(err, &invalid) {
			status := 400
			switch invalid.Code {
			case "payload_too_large":
				status = 413
			case "stale_sample", "replayed_sample":
				status = 409
			}
			fail(w, status, invalid.Code, invalid.Message)
		} else {
			fail(w, 400, "invalid_bundle", "Telemetry did not match the fixed Linux developer contract.")
		}
		return
	}
	write(w, 200, receipt)
}

func (s *Server) collectorDescription() string {
	if state := s.previewState(); state != nil {
		return "Linux developer transport: " + state.Status(time.Now().UTC()).State + "; no manager-side collector or fallback"
	}
	sample := s.sampleDevice()
	return fmt.Sprintf("%s local read-only observations; scope=%s; see per-field capability details", sample.Platform, sample.Source)
}
