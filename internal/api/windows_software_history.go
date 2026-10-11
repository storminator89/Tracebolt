package api

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsfullsoftware"
	"net/http"
	"strings"
)

func (h *operatorHandler) windowsSoftwareHistoryQuery(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 6 || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "windows-software-history" || parts[5] != "query" || r.URL.RawQuery != "" {
		fail(w, 404, "not_found", "Windows machine software change history is unavailable.")
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if h.windowsEnrollment == nil || h.windowsEnrollment.enrollment == nil {
		fail(w, 404, "not_found", "Windows machine software change history is not configured.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) || !operatorStillActive(w, r) {
		return
	}
	var q windowsfullsoftware.Query
	if !readObject(w, r, 8192, []string{"search", "sort", "limit", "cursor"}, &q) {
		return
	}
	if windowsfullsoftware.ValidateHistoryQuery(q) != nil {
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
	p, e := source.WindowsSoftwareHistoryPage(ctx, parts[3], q, source.Now().UTC())
	if e != nil {
		windowsFullSoftwareError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	// Prepare bounded response bytes before the final live authority and expiry check.
	body, e := json.Marshal(p)
	if e != nil || len(body) > windowsfullsoftware.MaxPageBytes {
		windowsFullSoftwareError(w, enrollmentstore.ErrStorage)
		return
	}
	if e = source.RecheckWindowsSoftwareHistoryPage(ctx, p, source.Now().UTC()); e != nil {
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
