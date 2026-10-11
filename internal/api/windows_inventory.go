package api

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"net/http"
	"strings"
	"time"
)

const windowsEnrollmentPrefix = "/v2/windows/enrollment/"

func windowsRequestPath(r *http.Request, path string) *http.Request {
	copy := r.Clone(r.Context())
	u := *r.URL
	u.Path = path
	copy.URL = &u
	copy.RequestURI = u.RequestURI()
	return copy
}
func (h *operatorHandler) windowsEnrollmentClient(w http.ResponseWriter, r *http.Request) {
	if h.windowsEnrollment == nil {
		fail(w, 404, "enrollment_unavailable", "Windows enrollment is not configured.")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, windowsEnrollmentPrefix)
	switch path {
	case "challenge", "claim", "status", "credential", "activate", "renewal/challenge", "renewal/status", "renewal/issue", "renewal/activate":
	default:
		fail(w, 404, "not_found", "Enrollment route is unavailable.")
		return
	}
	h.windowsEnrollment.enrollmentClient(w, windowsRequestPath(r, "/v2/enrollment/"+path))
}
func (h *operatorHandler) windowsEnrollmentOperator(w http.ResponseWriter, r *http.Request) {
	if h.windowsEnrollment == nil {
		if r.URL.Path == "/api/windows/enrollment" && r.Method == http.MethodGet {
			write(w, 200, map[string]any{"schemaVersion": "tracebolt.enrollment-operator.v2", "serverNow": h.auth.Now(), "enabled": false, "platforms": []string{"windows"}, "recordLimit": enrollmentservice.MaxRecords, "items": []enrollmentstate.Snapshot{}, "collectionProfile": enrollmentcrypto.CollectionProfileWindowsInventory, "collectionPrivacy": "windows_inventory_metadata_may_be_sensitive"})
			return
		}
		fail(w, 404, "enrollment_unavailable", "Windows enrollment is not configured.")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/windows")
	h.windowsEnrollment.enrollmentOperator(w, windowsRequestPath(r, "/api"+path))
}
func (h *operatorHandler) windowsInventoryView(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 || parts[1] != "api" || parts[2] != "devices" || parts[4] != "windows-inventory" || !enrollmentcrypto.ValidID(parts[3], "agent_") || r.URL.RawQuery != "" {
		fail(w, 404, "not_found", "Windows inventory is unavailable.")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if h.windowsEnrollment == nil || h.windowsEnrollment.enrollment == nil {
		fail(w, 404, "not_found", "Windows inventory is not configured.")
		return
	}
	h.writeWindowsInventoryView(w, r, h.windowsEnrollment.enrollment, parts[3])
}

// This read-only projection seam keeps response-time expiry/session checks
// testable with invented retained snapshots; it never invokes an endpoint source.
type windowsInventorySource interface {
	Now() time.Time
	WindowsInventoryView(context.Context, string, time.Time) (enrollmentstore.WindowsInventoryView, error)
}

func (h *operatorHandler) writeWindowsInventoryView(w http.ResponseWriter, r *http.Request, source windowsInventorySource, deviceID string) {
	view, err := source.WindowsInventoryView(r.Context(), deviceID, source.Now())
	if errors.Is(err, enrollmentstate.ErrNotFound) {
		fail(w, 404, "not_found", "Device not found.")
		return
	}
	if errors.Is(err, enrollmentstore.ErrBusy) || errors.Is(err, enrollmentstore.ErrOperationalBusy) {
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "inventory_busy", "Inventory is busy; retry shortly.")
		return
	}
	if err != nil {
		h.app.internal(w)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	view, err = view.RecheckAt(source.Now())
	if err != nil {
		h.app.internal(w)
		return
	}
	write(w, 200, view)
}
