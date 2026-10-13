package api

import (
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"net/http"
	"strings"
)

const macosInventoryEnrollmentPrefix = "/v2/macos-inventory/enrollment/"

func (h *operatorHandler) macosInventoryEnrollmentClient(w http.ResponseWriter, r *http.Request) {
	if h.macosInventoryEnrollment == nil {
		fail(w, 404, "enrollment_unavailable", "macOS inventory enrollment is not configured.")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, macosInventoryEnrollmentPrefix)
	switch path {
	case "challenge", "claim", "status", "credential", "activate", "renewal/challenge", "renewal/status", "renewal/issue", "renewal/activate":
	default:
		fail(w, 404, "not_found", "Enrollment route is unavailable.")
		return
	}
	h.macosInventoryEnrollment.enrollmentClient(w, windowsRequestPath(r, "/v2/enrollment/"+path))
}
func (h *operatorHandler) macosInventoryEnrollmentOperator(w http.ResponseWriter, r *http.Request) {
	if h.macosInventoryEnrollment == nil {
		if r.URL.Path == "/api/macos-inventory/enrollment" && r.Method == http.MethodGet {
			write(w, 200, map[string]any{"schemaVersion": "tracebolt.enrollment-operator.v2", "serverNow": h.auth.Now(), "enabled": false, "platforms": []string{"darwin"}, "recordLimit": enrollmentservice.MaxRecords, "items": []enrollmentstate.Snapshot{}, "collectionProfile": enrollmentcrypto.CollectionProfileMacOSInventory, "collectionPrivacy": "macos_inventory_metadata_may_be_sensitive"})
			return
		}
		fail(w, 404, "enrollment_unavailable", "macOS inventory enrollment is not configured.")
		return
	}
	h.macosInventoryEnrollment.enrollmentOperator(w, windowsRequestPath(r, "/api"+strings.TrimPrefix(r.URL.Path, "/api/macos-inventory")))
}
