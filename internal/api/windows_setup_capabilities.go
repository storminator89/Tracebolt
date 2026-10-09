package api

import (
	"encoding/json"
	"localrmm/internal/windowssetup"
	"net/http"
)

// This static compatibility advertisement is not a download, trust
// grant, enrollment capability or claim of native/released Setup acceptance.
func (h *operatorHandler) windowsSetupCapabilities(w http.ResponseWriter, r *http.Request) {
	if h.windowsEnrollment == nil || h.windowsEnrollment.enrollment == nil {
		fail(w, 404, "windows_setup_unavailable", "A compatible Windows enrollment manager is required.")
		return
	}
	if r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if !admitPublicMetadata(w, r, &h.bootstrapAdmission) {
		return
	}
	b := h.windowsEnrollment.enrollmentBootstrap
	raw, err := json.Marshal(windowssetup.Expected(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin))
	if err != nil || len(raw) > 2048 {
		fail(w, 503, "capabilities_unavailable", "Capabilities are unavailable.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
