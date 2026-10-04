package api

import (
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"net/http"
	"strings"
	"time"
)

type systemInventoryPage struct {
	SchemaVersion     string    `json:"schemaVersion"`
	DeviceID          string    `json:"deviceId"`
	CollectionProfile string    `json:"collectionProfile"`
	ServerNow         time.Time `json:"serverNow"`
	enrollmentstore.SystemPageResult
}

func (h *operatorHandler) systemInventory(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	query := len(parts) == 7 && parts[6] == "query"
	if (len(parts) != 6 && !query) || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "inventory" || parts[5] != "system" {
		fail(w, 404, "not_found", "Device inventory is unavailable.")
		return
	}
	if query && r.Method != "POST" || !query && r.Method != "GET" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if h.enrollment == nil || h.enrollment.Binding().CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		if query {
			fail(w, 409, "inventory_not_configured", "System inventory is not configured.")
			return
		}
		devices, e := h.app.devices()
		if e != nil {
			h.app.internal(w)
			return
		}
		for _, device := range devices {
			if device.ID == parts[3] {
				write(w, 200, enrollmentstore.SystemView{SchemaVersion: "tracebolt.system-inventory-view.v1", DeviceID: device.ID, CollectionProfile: "", Status: "not_configured", ServerNow: time.Now().UTC(), MaxAgeSeconds: 120})
				return
			}
		}
		fail(w, 404, "not_found", "Device inventory is unavailable.")
		return
	}
	if !query {
		view, e := h.enrollment.SystemInventoryView(r.Context(), parts[3], h.enrollment.Now().UTC())
		if e != nil {
			systemInventoryError(w, e)
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		write(w, 200, view)
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	var input enrollmentstore.SystemPageRequest
	if !readObject(w, r, 8192, []string{"section", "generationId", "search", "cursor", "limit", "filter"}, &input) {
		return
	}
	if !enrollmentcrypto.ValidID(input.GenerationID, "sample_") || len(input.Search) > enrollmentstore.SystemMaxSearchBytes || len(input.Cursor) > enrollmentstore.SystemMaxCursorBytes || input.Limit < 1 || input.Limit > enrollmentstore.SystemMaxPageRows {
		fail(w, 400, "invalid_inventory_query", "The inventory query is invalid.")
		return
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	now := h.enrollment.Now().UTC()
	page, e := h.enrollment.SystemInventoryPage(r.Context(), parts[3], input, now)
	release()
	if e != nil {
		systemInventoryError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	dto := systemInventoryPage{SchemaVersion: "tracebolt.system-inventory-page.v1", DeviceID: parts[3], CollectionProfile: enrollmentcrypto.CollectionProfileComplete, ServerNow: now, SystemPageResult: page}
	raw, e := json.Marshal(dto)
	if e != nil {
		h.app.internal(w)
		return
	}
	if len(raw) > 256*1024-1 {
		fail(w, 409, "inventory_page_limit", "Reduce the page size before continuing.")
		return
	}
	write(w, 200, dto)
}
func systemInventoryError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, enrollmentstate.ErrNotFound):
		fail(w, 404, "not_found", "Device inventory is unavailable.")
	case errors.Is(e, enrollmentstore.ErrInventoryBusy), errors.Is(e, enrollmentstore.ErrBusy), errors.Is(e, enrollmentstore.ErrOperationalBusy):
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "storage_busy", "Stored inventory is busy; retry shortly.")
	case errors.Is(e, enrollmentstore.ErrSystemCursor), errors.Is(e, enrollmentstore.ErrSystemCursorExpired), errors.Is(e, enrollmentstore.ErrSystemConflict):
		fail(w, 409, "inventory_generation_expired", "Refresh the inventory before continuing.")
	case errors.Is(e, enrollmentstate.ErrExpired), errors.Is(e, enrollmentstate.ErrState), errors.Is(e, enrollmentstate.ErrProof):
		fail(w, 409, "inventory_unavailable", "A current system inventory is unavailable.")
	case errors.Is(e, enrollmentstate.ErrInvalid):
		fail(w, 400, "invalid_inventory_query", "The inventory query is invalid.")
	default:
		fail(w, 503, "inventory_unavailable", "Stored inventory is unavailable.")
	}
}
