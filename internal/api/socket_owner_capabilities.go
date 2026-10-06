package api

import (
	"encoding/json"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
	"net/http"
)

const socketOwnerCapabilitiesPath = "/v4/system/capabilities"

// Static receiver protocol support only. This public metadata does not grant
// endpoint privileges or disclose identities, socket rows, policy or telemetry.
// Fresh onboarding checks the exact agent origin using the existing public
// bootstrap transport/CA boundary before enabling any optional socket scope.
func serveSocketOwnerCapabilities(w http.ResponseWriter, r *http.Request, b EnrollmentBootstrap, admission *bootstrapAdmission) {
	if r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if !admitPublicMetadata(w, r, admission) {
		return
	}
	value := struct {
		SchemaVersion     string `json:"schemaVersion"`
		AgentOrigin       string `json:"agentOrigin"`
		SystemFrame       string `json:"systemFrame"`
		SocketOwnerSource string `json:"socketOwnerSource"`
		SocketOwnerScope  string `json:"socketOwnerScope"`
	}{"tracebolt.system-manager-capabilities.v1", b.AgentOrigin, systemwire.SocketOwnerFrameVersion, systeminventory.SocketOwnerSourceVersion, systeminventory.SocketOwnerSourceScope}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 2048 {
		fail(w, 503, "capabilities_unavailable", "Capabilities are unavailable.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
