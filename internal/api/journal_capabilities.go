package api

import (
	"encoding/json"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"net/http"
)

const journalBrowseCapabilitiesPath = "/v4/journal/capabilities"

const journalCapabilitiesPath = "/v3/journal/capabilities"

// Static protocol support only. No device lookup, secret, local permission,
// telemetry, or captured content is returned or changed by this route.
func serveJournalCapabilities(w http.ResponseWriter, r *http.Request, b EnrollmentBootstrap, admission *bootstrapAdmission) {
	if r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if !admitPublicMetadata(w, r, admission) {
		return
	}
	if r.URL.Path == journalBrowseCapabilitiesPath {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		write(w, 200, struct {
			SchemaVersion    string `json:"schemaVersion"`
			AgentOrigin      string `json:"agentOrigin"`
			BrowsingContract string `json:"browsingContract"`
			GenerationReport string `json:"generationReport"`
			Request          string `json:"request"`
		}{"tracebolt.journal-browse-manager-capabilities.v1", b.AgentOrigin, journalview.BrowseContract, journalgeneration.ReportVersionV3, journalrequest.SchemaVersionV3})
		return
	}
	value := struct {
		SchemaVersion        string                                   `json:"schemaVersion"`
		AgentOrigin          string                                   `json:"agentOrigin"`
		GenerationReport     string                                   `json:"generationReport"`
		Request              string                                   `json:"request"`
		ServiceAuthorization []journalgeneration.ServiceAuthorization `json:"serviceAuthorization"`
	}{"tracebolt.journal-manager-capabilities.v1", b.AgentOrigin, journalgeneration.ReportVersionV2, journalrequest.SchemaVersionV2, []journalgeneration.ServiceAuthorization{journalgeneration.ExactUnits, journalgeneration.AllSystemServices}}
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
