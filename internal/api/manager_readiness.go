package api

import (
	"context"
	"localrmm/internal/managerreadiness"
	"net/http"
	"time"
)

// ManagerReadinessSource supplies only current, bounded core runtime evidence.
// The production source is synchronous and owned by the existing request drain.
type ManagerReadinessSource func(context.Context) managerreadiness.View

func (h *operatorHandler) managerReadinessAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		fail(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET for manager readiness.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	v := managerreadiness.NewView(time.Now().UTC(), []managerreadiness.Component{{Component: "runtime", State: "unknown"}})
	if h.managerReadiness != nil {
		v = h.managerReadiness(r.Context())
	}
	// A session revoked/expired during a slow read must not receive its result.
	if !operatorStillActive(w, r) {
		return
	}
	status := http.StatusServiceUnavailable
	if v.Status == "ready" {
		status = http.StatusOK
	}
	write(w, status, v)
}
