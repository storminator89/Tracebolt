package api

import (
	"localrmm/internal/operatorauth"
	"net/http"
)

func (h *operatorHandler) managerStatusAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if h.managerStatus == nil {
		fail(w, 404, "manager_status_unavailable", "Manager operational status is not configured.")
		return
	}
	operator, ok := operatorContext(r)
	if !ok {
		fail(w, 401, "authentication_required", "Sign in to continue.")
		return
	}
	release, err := operator.session.BeginCapability(r.Context(), operatorauth.Read)
	if err != nil {
		fail(w, 401, "authentication_required", "Operator session expired or was revoked.")
		return
	}
	if r.URL.Path == "/api/manager/readiness" {
		view := h.managerStatus.Snapshot()
		release()
		if !operatorStillActive(w, r) {
			return
		}
		status := http.StatusOK
		if !view.Ready {
			status = http.StatusServiceUnavailable
		}
		write(w, status, view)
		return
	}
	view := h.managerStatus.Metrics()
	release()
	if !operatorStillActive(w, r) {
		return
	}
	write(w, http.StatusOK, view)
}
