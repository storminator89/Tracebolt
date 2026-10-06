package api

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"net/http"
	"time"
)

const fleetEndpointIdentityResponseBytes = 256 * 1024

// This separate operator-only response never enters model.Device, AI packets,
// CSV exports, routing or collection consent. No per-row HTTP/database fanout.
func (h *operatorHandler) fleetEndpointIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_query", "This endpoint does not accept query parameters.")
		return
	}
	var validate func(time.Time) error
	view := enrollmentstore.FleetEndpointIdentityView{SchemaVersion: "tracebolt.fleet-endpoint-identity.v1", ServerNow: time.Now().UTC(), Items: []enrollmentstore.EndpointIdentityView{}}
	if h.enrollment != nil && h.enrollment.Binding().CollectionProfile == enrollmentcrypto.CollectionProfileComplete {
		var err error
		view, err = h.enrollment.FleetEndpointIdentityView(r.Context(), h.enrollment.Now().UTC())
		if err != nil {
			systemInventoryError(w, err)
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		view, err = view.RecheckAt(h.enrollment.Now().UTC())
		if err != nil {
			systemInventoryError(w, err)
			return
		}
		validate = view.ValidateAt
	}
	h.writeFleetEndpointIdentityResponse(w, r, view, validate)
}

// Match the existing overview/system-page output boundary: encode once, then
// check that the same bounded bytes remain authorized immediately before output.
func (h *operatorHandler) writeFleetEndpointIdentityResponse(w http.ResponseWriter, r *http.Request, value any, validate func(time.Time) error) {
	raw, err := json.Marshal(value)
	// Reserve the newline while keeping the entire wire body strictly below
	// the existing protected reader's 256 KiB ceiling.
	if err != nil || len(raw) >= fleetEndpointIdentityResponseBytes-1 {
		fail(w, 503, "inventory_unavailable", "Stored endpoint display metadata is unavailable.")
		return
	}
	raw = append(raw, '\n')
	defer clear(raw)
	if !operatorStillActive(w, r) {
		return
	}
	if validate != nil {
		if h.enrollment == nil {
			systemInventoryError(w, enrollmentstore.ErrStorage)
			return
		}
		if err = validate(h.enrollment.Now().UTC()); err != nil {
			systemInventoryError(w, err)
			return
		}
	}
	// Clock/validation work can also observe cancellation or session revocation.
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
