package api

import (
	"errors"
	"localrmm/internal/operatorauth"
	"net/http"
)

func (h *operatorHandler) accountsAPI(w http.ResponseWriter, r *http.Request, session operatorauth.Session) {
	if !h.auth.LiveAccounts() {
		fail(w, 404, "not_found", "Live account authority is not configured.")
		return
	}
	if r.URL.Path == "/api/auth/accounts" && r.Method == http.MethodGet {
		views, err := h.auth.AccountViews(r.Context(), session)
		if err != nil {
			fail(w, 403, "operator_capability_required", "Current account-management authority is required.")
			return
		}
		write(w, 200, map[string]any{"items": views})
		return
	}
	if r.URL.Path != "/api/auth/accounts/update" || r.Method != http.MethodPost {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	var input struct {
		ActorID          string                    `json:"actorId"`
		ExpectedRevision uint64                    `json:"expectedRevision"`
		Disabled         *bool                     `json:"disabled"`
		Capabilities     []operatorauth.Capability `json:"capabilities"`
		ResetSessions    *bool                     `json:"resetSessions"`
		ResetPassword    *bool                     `json:"resetPassword"`
	}
	if !readObject(w, r, 4096, []string{"actorId", "expectedRevision", "disabled", "capabilities", "resetSessions", "resetPassword"}, &input) {
		return
	}
	if input.Disabled == nil || input.ResetSessions == nil || input.ResetPassword == nil || input.ExpectedRevision == 0 || input.Capabilities == nil {
		fail(w, 400, "invalid_account_change", "Supply the exact reviewed revision, capabilities and explicit change flags.")
		return
	}
	change := operatorauth.AccountChange{TargetID: input.ActorID, ExpectedRevision: input.ExpectedRevision, Disabled: *input.Disabled, Capabilities: input.Capabilities, ResetCredentials: *input.ResetSessions}
	var err error
	if *input.ResetPassword {
		err = h.auth.ChangeAccountWithCredentialProposal(r.Context(), session, change)
	} else {
		err = h.auth.ChangeAccount(r.Context(), session, change)
	}
	switch {
	case err == nil:
		if session.ActorID() == input.ActorID {
			clearNamedOperatorCookie(w, h.cookieName, !h.insecureHTTPTest)
		}
		write(w, 200, map[string]any{"updated": true, "revision": input.ExpectedRevision + 1})
	case errors.Is(err, operatorauth.ErrAccountConflict):
		fail(w, 409, "account_revision_conflict", "Read the current account revision before another explicit review.")
	case errors.Is(err, operatorauth.ErrAuthorityUncertain):
		fail(w, 503, "account_authority_uncertain", "The account is fenced. Do not retry; inspect protected durable authority and audit before recovery.")
	case errors.Is(err, operatorauth.ErrConfiguration):
		fail(w, 400, "invalid_account_change", "Review capabilities, the remaining administrator and any protected credential proposal.")
	default:
		fail(w, 403, "operator_capability_required", "Current account-management authority is required.")
	}
}
