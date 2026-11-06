package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsfullsoftware"
	"net/http"
	"time"
)

func (h *operatorHandler) windowsFleetSoftwareQuery(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/fleet/windows-software/query" || r.URL.RawQuery != "" {
		fail(w, 404, "not_found", "Fleet software lookup is unavailable.")
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if h.windowsEnrollment == nil || h.windowsEnrollment.enrollment == nil {
		fail(w, 404, "not_found", "Windows software lookup is not configured.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) || !operatorStillActive(w, r) {
		return
	}
	var q windowsfullsoftware.FleetQuery
	if !readFleetSoftwareQuery(w, r, &q) {
		return
	}
	if windowsfullsoftware.ValidateFleetQuery(q) != nil {
		windowsFullSoftwareError(w, windowsfullsoftware.ErrInvalid)
		return
	}
	owner, ok := operatorContext(r)
	if !ok {
		fail(w, 401, "authentication_required", "Operator session is required.")
		return
	}
	source := h.windowsEnrollment.enrollment
	ctx := enrollmentstore.WithWindowsFullSoftwareSession(r.Context(), owner.session.ID, owner.session.ExpiresAt, owner.active)
	if q.View == "history" {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		p, e := source.WindowsFleetSoftwareHistoryPage(ctx, q, source.Now().UTC())
		if e != nil {
			windowsFullSoftwareError(w, e)
			return
		}
		body, e := json.Marshal(p)
		if e != nil || len(body) > windowsfullsoftware.MaxPageBytes {
			windowsFullSoftwareError(w, enrollmentstore.ErrStorage)
			return
		}
		if e = source.RecheckWindowsFleetSoftwareHistoryPage(ctx, p, source.Now().UTC()); e != nil {
			windowsFullSoftwareError(w, e)
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		if e = ctx.Err(); e != nil {
			windowsFullSoftwareError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}
	p, e := source.WindowsFleetSoftwarePage(ctx, q, source.Now().UTC())
	if e != nil {
		windowsFullSoftwareError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	body, e := json.Marshal(p)
	if e != nil || len(body) > windowsfullsoftware.MaxPageBytes {
		windowsFullSoftwareError(w, enrollmentstore.ErrStorage)
		return
	}
	if e = source.RecheckWindowsFleetSoftwarePage(ctx, p, source.Now().UTC()); e != nil {
		windowsFullSoftwareError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// Preserve the exact three-field legacy request. The only added shape has the
// explicit history discriminator; both shapes still use the strict duplicate,
// unknown-field, null and typed-value checks of readObject.
func readFleetSoftwareQuery(w http.ResponseWriter, r *http.Request, q *windowsfullsoftware.FleetQuery) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			fail(w, 413, "body_too_large", "Request body exceeds this endpoint's byte limit.")
		} else {
			fail(w, 400, "invalid_body", "Request body could not be read.")
		}
		return false
	}
	var shape map[string]json.RawMessage
	_ = json.Unmarshal(raw, &shape)
	fields := []string{"name", "version", "cursor"}
	_, historyShape := shape["view"]
	if historyShape {
		fields = append(fields, "view")
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if !readObject(w, r, 8192, fields, q) {
		return false
	}
	if historyShape && q.View != "history" {
		windowsFullSoftwareError(w, windowsfullsoftware.ErrInvalid)
		return false
	}
	return true
}
