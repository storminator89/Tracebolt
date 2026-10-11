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
	expected := windowssetup.Expected(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
	if r.URL.Path == windowssetup.ReadAdminCapabilitiesPath {
		expected = windowssetup.ExpectedReadAdmin(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
	} else if r.URL.Path == windowssetup.ReadAdminCapabilitiesPathV10 {
		expected = windowssetup.ExpectedReadAdminV10(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
	} else if r.URL.Path == windowssetup.ReadAdminCapabilitiesPathV9 {
		expected = windowssetup.ExpectedReadAdminV9(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
	} else if r.URL.Path == windowssetup.ReadAdminCapabilitiesPathV8 {
		expected = windowssetup.ExpectedReadAdminV8(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
	} else if r.URL.Path == windowssetup.ReadAdminCapabilitiesPathV7 {
		expected = windowssetup.ExpectedReadAdminV7(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
	} else if r.URL.Path == windowssetup.ReadAdminCapabilitiesPathV6 {
		expected = windowssetup.ExpectedReadAdminV6(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
	} else if r.URL.Path == windowssetup.ReadAdminCapabilitiesPathV5 {
		expected = windowssetup.ExpectedReadAdminV5(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
	} else if r.URL.Path == windowssetup.ReadAdminCapabilitiesPathV4 {
		expected = windowssetup.ExpectedReadAdminV4(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
	} else if r.URL.Path == windowssetup.ReadAdminCapabilitiesPathV3 {
		expected = windowssetup.ExpectedReadAdminV3(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
	} else if r.URL.Path == windowssetup.ReadAdminCapabilitiesPathV2 {
		expected = windowssetup.ExpectedReadAdminV2(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)
	}
	raw, err := json.Marshal(expected)
	if err != nil || len(raw) > 2048 {
		fail(w, 503, "capabilities_unavailable", "Capabilities are unavailable.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
