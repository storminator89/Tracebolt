package api

import (
	"encoding/json"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsfullsoftware"
	"net/http"
)

func (h *operatorHandler) windowsFleetSoftwareQuery(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/fleet/windows-software/query" || r.URL.RawQuery != "" {
		fail(w, 404, "not_found", "Fleet software lookup is unavailable.")
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if h.windowsEnrollment == nil || h.windowsEnrollment.enrollment == nil {
		fail(w, 404, "not_found", "Windows software lookup is not configured.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) || !operatorStillActive(w, r) {
		return
	}
	var q windowsfullsoftware.FleetQuery
	if !readObject(w, r, 8192, []string{"name", "version", "cursor"}, &q) {
		return
	}
	if windowsfullsoftware.ValidateFleetQuery(q) != nil {
		windowsFullSoftwareError(w, windowsfullsoftware.ErrInvalid)
		return
	}
	owner, ok := operatorContext(r)
	if !ok {
		fail(w, 401, "authentication_required", "Operator session is required.")
		return
	}
	source := h.windowsEnrollment.enrollment
	ctx := enrollmentstore.WithWindowsFullSoftwareSession(r.Context(), owner.session.ID, owner.session.ExpiresAt, owner.active)
	p, e := source.WindowsFleetSoftwarePage(ctx, q, source.Now().UTC())
	if e != nil {
		windowsFullSoftwareError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	body, e := json.Marshal(p)
	if e != nil || len(body) > windowsfullsoftware.MaxPageBytes {
		windowsFullSoftwareError(w, enrollmentstore.ErrStorage)
		return
	}
	if e = source.RecheckWindowsFleetSoftwarePage(ctx, p, source.Now().UTC()); e != nil {
		windowsFullSoftwareError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
