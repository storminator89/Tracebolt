package api

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsmanaged"
	"net/http"
	"sort"
	"time"
)

const fleetEndpointIdentityResponseBytes = 256 * 1024
const fleetIdentitiesResponseBytes = 2 * fleetEndpointIdentityResponseBytes

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

// v2 adds a distinct Windows projection while keeping the Linux v1 route stable.
func (h *operatorHandler) fleetIdentities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_query", "This endpoint does not accept query parameters.")
		return
	}
	sources := []*enrollmentservice.Service{}
	if h.enrollment != nil && (h.enrollment.Binding().CollectionProfile == enrollmentcrypto.CollectionProfileComplete || h.enrollment.Binding().CollectionProfile == windowsmanaged.CollectionProfile) {
		sources = append(sources, h.enrollment)
	}
	if h.windowsEnrollment != nil && h.windowsEnrollment.enrollment != nil && h.windowsEnrollment.enrollment != h.enrollment {
		sources = append(sources, h.windowsEnrollment.enrollment)
	}
	view := enrollmentstore.FleetIdentitiesView{SchemaVersion: "tracebolt.fleet-identities.v2", Items: []enrollmentstore.FleetIdentityItem{}}
	for _, source := range sources {
		part, err := source.FleetIdentitiesView(r.Context(), source.Now().UTC())
		if err != nil {
			systemInventoryError(w, err)
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		if part.ServerNow.After(view.ServerNow) {
			view.ServerNow = part.ServerNow
		}
		view.Items = append(view.Items, part.Items...)
	}
	if len(sources) == 0 {
		view.ServerNow = time.Now().UTC()
	}
	deviceID := func(item enrollmentstore.FleetIdentityItem) string {
		if item.Linux != nil {
			return item.Linux.DeviceID
		}
		return item.Windows.DeviceID
	}
	sort.Slice(view.Items, func(i, j int) bool { return deviceID(view.Items[i]) < deviceID(view.Items[j]) })
	for i := 1; i < len(view.Items); i++ {
		if deviceID(view.Items[i-1]) == deviceID(view.Items[i]) {
			systemInventoryError(w, enrollmentstore.ErrStorage)
			return
		}
	}
	var err error
	// Normalize both authorities to one monotonic response clock. Each authority
	// keeps its own original certificate and capture/receipt boundaries.
	for _, source := range sources {
		view, err = view.RecheckAt(source.Now().UTC())
		if err != nil {
			systemInventoryError(w, err)
			return
		}
	}
	h.writeFleetIdentityBytes(w, r, view, fleetIdentitiesResponseBytes, func() error {
		for _, source := range sources {
			if err := view.ValidateAt(source.Now().UTC()); err != nil {
				return err
			}
		}
		return nil
	})
}

// Match the existing overview/system-page output boundary: encode once, then
// check that the same bounded bytes remain authorized immediately before output.
func (h *operatorHandler) writeFleetEndpointIdentityResponse(w http.ResponseWriter, r *http.Request, value any, validate func(time.Time) error) {
	h.writeFleetIdentityBytes(w, r, value, fleetEndpointIdentityResponseBytes, func() error {
		if validate == nil {
			return nil
		}
		if h.enrollment == nil {
			return enrollmentstore.ErrStorage
		}
		return validate(h.enrollment.Now().UTC())
	})
}

func (h *operatorHandler) writeFleetIdentityBytes(w http.ResponseWriter, r *http.Request, value any, byteLimit int, validate func() error) {
	raw, err := json.Marshal(value)
	// Reserve the newline while keeping the entire wire body strictly below
	// the selected version's bounded protected-reader ceiling.
	if err != nil || len(raw) >= byteLimit-1 {
		fail(w, 503, "inventory_unavailable", "Stored endpoint display metadata is unavailable.")
		return
	}
	raw = append(raw, '\n')
	defer clear(raw)
	if !operatorStillActive(w, r) {
		return
	}
	if validate != nil {
		if err = validate(); err != nil {
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
