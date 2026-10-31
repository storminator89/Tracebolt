package api

import (
	"errors"
	"localrmm/internal/operatorauth"
	"net/http"
)

func (h *operatorHandler) sessionsAPI(w http.ResponseWriter, r *http.Request, session operatorauth.Session) {
	if r.URL.Path == "/api/auth/sessions" && r.Method == http.MethodGet {
		view, err := h.auth.Sessions(r.Context(), session)
		if err != nil {
			fail(w, 401, "authentication_required", "Operator session expired or was revoked.")
			return
		}
		write(w, 200, view)
		return
	}
	if r.URL.Path != "/api/auth/sessions/revoke" || r.Method != http.MethodPost {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	var input struct {
		SessionID string `json:"sessionId"`
	}
	if !readObject(w, r, 256, []string{"sessionId"}, &input) {
		return
	}
	revoked, err := h.auth.RevokeSession(r.Context(), session, input.SessionID)
	if err != nil {
		if errors.Is(err, operatorauth.ErrConfiguration) {
			fail(w, 400, "invalid_session_id", "Use one canonical session identifier from the session view.")
		} else {
			fail(w, 401, "authentication_required", "Operator session expired or was revoked.")
		}
		return
	}
	if revoked {
		h.app.cancelSessionAnalysis(input.SessionID)
		if input.SessionID == session.ID {
			clearNamedOperatorCookie(w, h.cookieName, !h.insecureHTTPTest)
		}
	}
	write(w, 200, map[string]bool{"revoked": revoked})
}
