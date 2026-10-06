package api

import "net/http"

// Startup configuration is the only check authority. Reading this in-memory
// snapshot never resolves a name, probes a target, or changes manager health.
func (h *operatorHandler) applicationCheckStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	status := h.applicationChecks.Status()
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, status)
}
