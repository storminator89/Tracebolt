package api

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"net/http"
	"strings"
	"time"
)

// Resource history is only reachable after the LAN operator boundary. Agent
// certificates and public/development routes never authorize this read.
func (h *operatorHandler) resourceHistory(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 || parts[1] != "api" || parts[2] != "devices" || parts[4] != "resource-history" || !enrollmentcrypto.ValidID(parts[3], "agent_") {
		fail(w, 404, "not_found", "Resource history is unavailable.")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	after, validQuery := resourceHistoryAfter(r.URL)
	if !validQuery {
		fail(w, 400, "invalid_query", "History cursor must be canonical.")
		return
	}
	if h.enrollment == nil {
		ds, e := h.app.devices()
		if e != nil {
			h.app.internal(w)
			return
		}
		for _, d := range ds {
			if d.ID == parts[3] {
				if operatorStillActive(w, r) {
					write(w, 200, enrollmentstore.EmptyResourceHistory(d.ID, h.auth.Now(), "not_configured"))
				}
				return
			}
		}
		fail(w, 404, "not_found", "Resource history is unavailable.")
		return
	}
	view, e := h.enrollment.ResourceHistory(r.Context(), parts[3], h.enrollment.Now())
	if e != nil {
		systemInventoryError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	view, e = view.RecheckAt(h.enrollment.Now())
	if e != nil {
		systemInventoryError(w, e)
		return
	}
	payload, e := resourceHistoryPayload(view, after)
	if e != nil {
		systemInventoryError(w, e)
		return
	}
	// Recheck the complete authorized view, including points omitted by a delta.
	h.writeResourceHistoryResponse(w, r, payload, view.ValidateAt)
}

// Encode once, then validate the original source lifetime and session before
// emitting those same bounded bytes. Encoding must not carry points past expiry.
func (h *operatorHandler) writeResourceHistoryResponse(w http.ResponseWriter, r *http.Request, value any, validate func(time.Time) error) {
	raw, e := json.Marshal(value)
	if e != nil || len(raw) > 1536*1024-1 {
		fail(w, 503, "history_unavailable", "Resource history is unavailable.")
		return
	}
	raw = append(raw, '\n')
	defer clear(raw)
	if !operatorStillActive(w, r) {
		return
	}
	if e = validate(h.enrollment.Now().UTC()); e != nil {
		systemInventoryError(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
