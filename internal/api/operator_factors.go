package api

import (
	"errors"
	"localrmm/internal/operatorauth"
	"net"
	"net/http"
)

// Enrollment deliberately does not accept an ambient session as authority. The
// current password, a separately protected exact-revision factor proposal and
// possession of that factor must all be proved. Like login, this pre-session
// route requires the configured exact Origin and never issues a session cookie.
func (h *operatorHandler) enrollFactorAPI(w http.ResponseWriter, r *http.Request) {
	if !h.auth.LiveAccounts() || h.insecureHTTPTest {
		fail(w, http.StatusNotFound, "not_found", "Live TLS factor authority is not configured.")
		return
	}
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.Header.Get("Origin") != h.origin {
		fail(w, http.StatusForbidden, "origin_required", "Same-origin enrollment is required.")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		fail(w, http.StatusUnsupportedMediaType, "json_required", "JSON is required.")
		return
	}
	var input struct {
		Username         string `json:"username"`
		Password         string `json:"password"`
		OTP              string `json:"otp"`
		ExpectedRevision uint64 `json:"expectedRevision"`
	}
	if !readObject(w, r, 4096, []string{"username", "password", "otp", "expectedRevision"}, &input) {
		return
	}
	defer func() { input.Password, input.OTP = "", "" }()
	if input.ExpectedRevision == 0 {
		fail(w, http.StatusBadRequest, "invalid_factor_enrollment", "An exact reviewed account revision is required.")
		return
	}
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		fail(w, http.StatusUnauthorized, "invalid_credentials", "Factor enrollment failed.")
		return
	}
	err = h.auth.EnrollFactor(r.Context(), peer, input.Username, input.Password, input.OTP, input.ExpectedRevision)
	switch {
	case err == nil:
		write(w, http.StatusOK, map[string]any{"enrolled": true, "revision": input.ExpectedRevision + 1, "nextStep": "sign_in_with_fresh_factor"})
	case errors.Is(err, operatorauth.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusTooManyRequests, "login_rate_limited", "Too many authentication attempts. Try again later.")
	case errors.Is(err, operatorauth.ErrBusy):
		fail(w, http.StatusServiceUnavailable, "authentication_busy", "Authentication is temporarily unavailable.")
	case errors.Is(err, operatorauth.ErrAccountConflict):
		fail(w, http.StatusConflict, "account_revision_conflict", "Review the current account and protected factor proposal before another attempt.")
	case errors.Is(err, operatorauth.ErrAuthorityUncertain):
		fail(w, http.StatusServiceUnavailable, "account_authority_uncertain", "Preserve protected authority and audit; do not retry an uncertain operation.")
	default:
		fail(w, http.StatusUnauthorized, "invalid_credentials", "Factor enrollment failed.")
	}
}

// A factor reset is a new strongly authenticated operation, not a session reset
// flag. The current session supplies the actual requester; input credentials
// reauthenticate that requester, never the request-supplied target identity.
func (h *operatorHandler) resetFactorAPI(w http.ResponseWriter, r *http.Request, session operatorauth.Session) {
	if h.insecureHTTPTest || !h.auth.LiveAccounts() {
		fail(w, http.StatusNotFound, "not_found", "Live TLS factor authority is not configured.")
		return
	}
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method is unsupported.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	var input struct {
		ActorID          string `json:"actorId"`
		ExpectedRevision uint64 `json:"expectedRevision"`
		Password         string `json:"password"`
		OTP              string `json:"otp"`
	}
	if !readObject(w, r, 4096, []string{"actorId", "expectedRevision", "password", "otp"}, &input) {
		return
	}
	defer func() { input.Password, input.OTP = "", "" }()
	if input.ExpectedRevision == 0 {
		fail(w, http.StatusBadRequest, "invalid_factor_reset", "An exact reviewed account revision is required.")
		return
	}
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		fail(w, http.StatusForbidden, "fresh_factor_authentication_required", "Current account-management permission and fresh authentication are required.")
		return
	}
	err = h.auth.ResetFactor(r.Context(), session, peer, input.ActorID, input.ExpectedRevision, input.Password, input.OTP)
	switch {
	case err == nil:
		if session.ActorID() == input.ActorID {
			clearNamedOperatorCookie(w, h.cookieName, !h.insecureHTTPTest)
		}
		write(w, http.StatusOK, map[string]any{"updated": true, "revision": input.ExpectedRevision + 1, "factorState": "enrollment_required"})
	case errors.Is(err, operatorauth.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusTooManyRequests, "login_rate_limited", "Too many authentication attempts. Try again later.")
	case errors.Is(err, operatorauth.ErrBusy):
		fail(w, http.StatusServiceUnavailable, "authentication_busy", "Authentication is temporarily unavailable.")
	case errors.Is(err, operatorauth.ErrAccountConflict):
		fail(w, http.StatusConflict, "account_revision_conflict", "Read the current account revision before another explicit review.")
	case errors.Is(err, operatorauth.ErrAuthorityUncertain):
		fail(w, http.StatusServiceUnavailable, "account_authority_uncertain", "The account is fenced. Preserve protected authority and audit; do not retry.")
	case errors.Is(err, operatorauth.ErrConfiguration):
		fail(w, http.StatusBadRequest, "invalid_factor_reset", "Review the target factor and remaining usable administrator.")
	default:
		fail(w, http.StatusForbidden, "fresh_factor_authentication_required", "Current account-management permission and fresh authentication are required.")
	}
}
