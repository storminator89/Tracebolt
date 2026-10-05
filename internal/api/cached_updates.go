package api

import (
	"encoding/json"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"net/http"
	"strings"
	"time"
)

// cachedUpdates exposes only authenticated retained endpoint observations. A
// manager-side GET never runs APT or enables collection on an endpoint.
func (h *operatorHandler) cachedUpdates(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 6 || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "inventory" || parts[5] != "cached-updates" {
		fail(w, 404, "not_found", "Cached update observations are unavailable.")
		return
	}
	if r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_query", "This endpoint does not accept query parameters.")
		return
	}
	if h.enrollment == nil || h.enrollment.Binding().CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		devices, e := h.app.devices()
		if e != nil {
			h.app.internal(w)
			return
		}
		for _, d := range devices {
			if d.ID == parts[3] {
				if !operatorStillActive(w, r) {
					return
				}
				write(w, 200, enrollmentstore.CachedUpdatesView{SchemaVersion: "tracebolt.cached-updates-view.v1", DeviceID: d.ID, Status: "unknown", ServerNow: time.Now().UTC(), MaxAgeSeconds: 120})
				return
			}
		}
		fail(w, 404, "not_found", "Cached update observations are unavailable.")
		return
	}
	view, e := h.enrollment.CachedUpdatesView(r.Context(), parts[3], h.enrollment.Now().UTC())
	if e != nil {
		systemInventoryError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	raw, e := json.Marshal(view)
	if e != nil || len(raw) > cachedupdates.MaxSnapshotBytes+2048 {
		fail(w, 503, "inventory_unavailable", "Stored cached update observations are unavailable.")
		return
	}
	write(w, 200, view)
}
