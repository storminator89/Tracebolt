package api

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/macosinventorywire"
	"net/http"
	"strings"
	"time"
)

// Private source seam permits deterministic response-time revocation tests; it
// never reads an endpoint or creates a collection request.
type macosInventorySource interface {
	Now() time.Time
	MacOSInventoryPage(context.Context, string, enrollmentstore.MacOSInventoryQuery, time.Time) (enrollmentstore.MacOSInventoryPage, error)
	RecheckMacOSInventoryPage(context.Context, enrollmentstore.MacOSInventoryPage, time.Time) error
}

func (h *operatorHandler) macosInventoryQuery(w http.ResponseWriter, r *http.Request) {
	var source macosInventorySource
	if h.macosInventoryEnrollment != nil && h.macosInventoryEnrollment.enrollment != nil {
		source = h.macosInventoryEnrollment.enrollment
	}
	h.writeMacOSInventoryQuery(w, r, source)
}

func (h *operatorHandler) writeMacOSInventoryQuery(w http.ResponseWriter, r *http.Request, source macosInventorySource) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 6 || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "macos-inventory" || parts[5] != "query" || r.URL.RawQuery != "" || r.URL.ForceQuery || strings.Contains(r.URL.EscapedPath(), "%") {
		fail(w, 404, "not_found", "macOS inventory is unavailable.")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if source == nil {
		fail(w, 404, "not_found", "macOS inventory is not configured.")
		return
	}
	if len(r.TransferEncoding) != 0 || len(r.Header.Values("Content-Encoding")) != 0 {
		fail(w, 400, "invalid_framing", "Use a bounded uncompressed JSON request.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) || !operatorStillActive(w, r) {
		return
	}
	owner, ok := operatorContext(r)
	if !ok {
		fail(w, 401, "authentication_required", "Operator session is required.")
		return
	}
	var q enrollmentstore.MacOSInventoryQuery
	if !readObject(w, r, 1024, []string{"section", "generationId", "offset", "limit"}, &q) {
		return
	}
	if enrollmentstore.ValidateMacOSInventoryQuery(q) != nil {
		macosInventoryError(w, macosinventorywire.ErrInvalid)
		return
	}
	ctx := enrollmentstore.WithMacOSInventorySession(r.Context(), owner.session.ID, owner.session.ExpiresAt, owner.active)
	page, err := source.MacOSInventoryPage(ctx, parts[3], q, source.Now().UTC())
	if err != nil {
		macosInventoryError(w, err)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	// Marshal before the final live session, original identity, grant, generation
	// and original-expiry checks. No private body bytes are written on failure.
	body, err := json.Marshal(page)
	if err != nil || len(body) > enrollmentstore.MacOSInventoryMaxPageBytes {
		macosInventoryError(w, enrollmentstore.ErrStorage)
		return
	}
	if err = source.RecheckMacOSInventoryPage(ctx, page, source.Now().UTC()); err != nil {
		macosInventoryError(w, err)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func macosInventoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, macosinventorywire.ErrInvalid), errors.Is(err, enrollmentstate.ErrInvalid):
		fail(w, 400, "macos_inventory_invalid", "The inventory query is invalid.")
	case errors.Is(err, macosinventorywire.ErrConflict), errors.Is(err, macosinventorywire.ErrExpired), errors.Is(err, macosinventorywire.ErrDisabled):
		fail(w, 409, "macos_inventory_restart_required", "The original inventory generation changed or expired. Refresh the summary.")
	case errors.Is(err, enrollmentstate.ErrProof), errors.Is(err, enrollmentstate.ErrState), errors.Is(err, enrollmentstate.ErrExpired):
		fail(w, 403, "agent_unauthorized", "Current macOS inventory authority is unavailable.")
	case errors.Is(err, enrollmentstate.ErrNotFound):
		fail(w, 404, "not_found", "Device not found.")
	case errors.Is(err, enrollmentstore.ErrBusy), errors.Is(err, enrollmentstore.ErrInventoryBusy), errors.Is(err, enrollmentstore.ErrOperationalBusy):
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "inventory_busy", "Inventory is busy; retry shortly.")
	default:
		fail(w, 503, "storage_unavailable", "macOS inventory storage is unavailable.")
	}
}
