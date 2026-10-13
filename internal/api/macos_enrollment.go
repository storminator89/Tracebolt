package api

import (
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"net/http"
	"strings"
)

const macosEnrollmentPrefix = "/v2/macos/enrollment/"

func (h *operatorHandler) macosEnrollmentClient(w http.ResponseWriter, r *http.Request) {
	if h.macosEnrollment == nil {
		fail(w, 404, "enrollment_unavailable", "macOS enrollment is not configured.")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, macosEnrollmentPrefix)
	switch path {
	case "challenge", "claim", "status", "credential", "activate", "renewal/challenge", "renewal/status", "renewal/issue", "renewal/activate":
	default:
		fail(w, 404, "not_found", "Enrollment route is unavailable.")
		return
	}
	h.macosEnrollment.enrollmentClient(w, windowsRequestPath(r, "/v2/enrollment/"+path))
}
func (h *operatorHandler) macosEnrollmentOperator(w http.ResponseWriter, r *http.Request) {
	if h.macosEnrollment == nil {
		if r.URL.Path == "/api/macos/enrollment" && r.Method == http.MethodGet {
			write(w, 200, map[string]any{"schemaVersion": "tracebolt.enrollment-operator.v2", "serverNow": h.auth.Now(), "enabled": false, "platforms": []string{"darwin"}, "recordLimit": enrollmentservice.MaxRecords, "items": []enrollmentstate.Snapshot{}, "collectionProfile": enrollmentcrypto.CollectionProfile})
			return
		}
		fail(w, 404, "enrollment_unavailable", "macOS enrollment is not configured.")
		return
	}
	h.macosEnrollment.enrollmentOperator(w, windowsRequestPath(r, "/api"+strings.TrimPrefix(r.URL.Path, "/api/macos")))
}
