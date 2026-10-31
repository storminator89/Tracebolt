package api

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/rustcompat"
	"net/http"
)

// Compatibility is public metadata, never enrollment, trust, or collection authority.
func (h *operatorHandler) rustBasicCapabilities(w http.ResponseWriter, r *http.Request) {
	windows := h.windowsEnrollment
	if h.insecureHTTPTest || windows == nil || windows.enrollment == nil {
		fail(w, 404, "rust_basic_unavailable", "Compatible Windows HTTPS enrollment is unavailable.")
		return
	}
	service, b := windows.enrollment, windows.enrollmentBootstrap
	if service.AutomaticRenewal() || b.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		fail(w, 404, "rust_basic_unavailable", "Compatible Windows HTTPS enrollment is unavailable.")
		return
	}
	if r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if !admitPublicMetadata(w, r, &h.bootstrapAdmission) {
		return
	}
	// Reject framing/credentials and enforce the public budget before parsing
	// certificates or verifying issuer signatures from the immutable config.
	if !validEnrollmentBootstrap(service, b, h.origin, false) {
		fail(w, 404, "rust_basic_unavailable", "Compatible Windows HTTPS enrollment is unavailable.")
		return
	}
	raw, err := json.Marshal(rustcompat.Expected(b.EnrollmentOrigin, b.AgentOrigin, service.SelfClaimAvailable() && service.SelfClaimPlatform() == "windows"))
	if err != nil || len(raw) > 2048 {
		fail(w, 503, "capabilities_unavailable", "Capabilities are unavailable.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
