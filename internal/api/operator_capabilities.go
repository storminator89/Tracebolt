package api

import (
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/operatorauth"
	"net/http"
	"strings"
)

// Named read accounts can inspect existing state, including the exact bounded
// POST query endpoints that deliberately keep search/cursor data out of URLs.
// Enqueueing collection, enrollment/trust, AI, notes, feed sync/import and health
// writes are NOT read. Their existing legacy administrator mapping is unchanged.
// Maintenance capabilities do not confer these unrelated administrative rights.
func namedReadRoute(r *http.Request) bool {
	if r.Method == "GET" || r.Method == "HEAD" {
		return true
	}
	if r.Method != "POST" {
		return false
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") {
		return false
	}
	if len(parts) == 6 && parts[4] == "journal" && parts[5] == "query" {
		return true
	}
	if len(parts) == 7 && parts[4] == "inventory" && parts[6] == "query" {
		switch parts[5] {
		case "system", "overview", "packages", "complete-updates":
			return true
		}
	}
	return false
}

// beginOperatorCapability is the fail-closed seam for future typed maintenance
// endpoints. It requires LAN operator context, current Origin/CSRF, a named
// server-derived actor and a specific explicit capability; development/shared
// sessions can never authorize a new controlled action. No route calls it yet.
// Future dispatch must call it again immediately before committing dispatch,
// and derive the approval actor from the returned value, never the request.
func (s *Server) beginOperatorCapability(w http.ResponseWriter, r *http.Request, capability operatorauth.Capability) (string, func(), bool) {
	operator, ok := operatorContext(r)
	if !ok || !operator.session.Named() || capability == operatorauth.Read {
		fail(w, 403, "operator_capability_required", "A named operator with the required maintenance permission is required.")
		return "", nil, false
	}
	if !s.authorizeJSONMutation(w, r) || !operatorStillActive(w, r) {
		return "", nil, false
	}
	release, err := operator.session.BeginCapability(r.Context(), capability)
	if err != nil {
		if err == operatorauth.ErrUnauthenticated {
			fail(w, 401, "authentication_required", "Operator session expired or was revoked.")
		} else {
			fail(w, 403, "operator_capability_required", "The required maintenance permission is not granted.")
		}
		return "", nil, false
	}
	return operator.session.ActorID(), release, true
}
