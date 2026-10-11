package api

import (
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsfullservices"
	"net/http"
	"strings"
)

func (h *operatorHandler) windowsFullServicesQuery(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 6 || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "windows-full-services" || parts[5] != "query" || r.URL.RawQuery != "" {
		fail(w, 404, "not_found", "Windows service inventory is unavailable.")
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if h.windowsEnrollment == nil || h.windowsEnrollment.enrollment == nil {
		fail(w, 404, "not_found", "Windows service inventory is not configured.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) || !operatorStillActive(w, r) {
		return
	}
	var q windowsfullservices.Query
	if !readObject(w, r, 8192, []string{"search", "sort", "limit", "cursor"}, &q) {
		return
	}
	if windowsfullservices.ValidateQuery(q) != nil {
		windowsFullServicesError(w, windowsfullservices.ErrInvalid)
		return
	}
	owner, ok := operatorContext(r)
	if !ok {
		fail(w, 401, "authentication_required", "Operator session is required.")
		return
	}
	source := h.windowsEnrollment.enrollment
	ctx := enrollmentstore.WithWindowsFullServicesSession(r.Context(), owner.session.ID, owner.session.ExpiresAt, owner.active)
	p, e := source.WindowsFullServicesPage(ctx, parts[3], q, source.Now().UTC())
	if e != nil {
		windowsFullServicesError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	if e = source.RecheckWindowsFullServicesPage(ctx, p, source.Now().UTC()); e != nil {
		windowsFullServicesError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, p)
}
func windowsFullServicesError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, windowsfullservices.ErrInvalid), errors.Is(e, enrollmentstate.ErrInvalid):
		fail(w, 400, "windows_full_services_invalid", "The inventory query is invalid.")
	case errors.Is(e, windowsfullservices.ErrConflict), errors.Is(e, windowsfullservices.ErrExpired):
		fail(w, 409, "windows_full_services_restart_required", "The original generation or cursor expired or changed. Restart browsing.")
	case errors.Is(e, enrollmentstate.ErrProof), errors.Is(e, enrollmentstate.ErrState), errors.Is(e, enrollmentstate.ErrExpired):
		fail(w, 403, "agent_unauthorized", "Current Windows identity authority is unavailable.")
	case errors.Is(e, enrollmentstate.ErrNotFound):
		fail(w, 404, "not_found", "Device not found.")
	case errors.Is(e, enrollmentstore.ErrInventoryBusy), errors.Is(e, enrollmentstore.ErrBusy), errors.Is(e, enrollmentstore.ErrOperationalBusy):
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "inventory_busy", "Inventory is busy; retry shortly.")
	default:
		fail(w, 503, "storage_unavailable", "Windows service inventory storage is unavailable.")
	}
}
