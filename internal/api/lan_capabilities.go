package api

import (
	"localrmm/internal/model"
	"net/http"
)

func (s *Server) mode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lanOnly {
		if s.insecureHTTPTest {
			return "lan-http-test"
		}
		return "lan-tls-pilot"
	}
	return "local-development"
}
func (s *Server) lanCapabilities(w http.ResponseWriter) bool {
	s.mu.RLock()
	lan, insecure, guided := s.lanOnly, s.insecureHTTPTest, s.guidedEnrollment
	s.mu.RUnlock()
	if !lan {
		return false
	}
	transport := "https-mtls"
	identityMode := "manual-v1"
	collector := "Separate manually approved agent observations; no manager-side collector or fallback."
	limitations := []string{"One-environment LAN pilot with one operator and manually approved agent certificates.", "Only latest bounded observations are retained; no scheduler, history, host health evaluation or automatic remediation.", "Agent observations are authenticated claims, not independent attestation of the operating system.", "No software update or CVE assessment is integrated into this runtime yet.", "No online certificate issuer, discovery, automatic enrollment, service installation or remote shell.", "SQLite state is protected by filesystem access controls but is not encrypted.", "AI settings do not verify connectivity; analysis requires an explicit request. Private LAN model endpoints remain unsupported by the current provider policy."}
	if guided {
		identityMode = "guided-v2"
		collector = "Separately enrolled agent observations with explicit approval and activation; no manager-side collector or fallback."
		limitations = []string{"Guided Linux enrollment pilot, capped at 25 retained records including tombstones; one operator and one environment.", "Foreground reporting and an explicitly installed Linux/systemd service are available. This API does not establish service installation, enablement or successful OS reboot; credential renewal is not implemented.", "The selected profile determines inventory scope. The v3 profile supports complete dpkg generations and paged service/socket views; their current coverage, permission gaps and original ages are shown separately.", "Only bounded latest/last-complete observations are retained, without a historical time series or automatic remediation. Offline advisory review, where available, is candidate evidence rather than confirmed CVE or offered-update coverage.", "Agent observations are authenticated claims, not independent operating-system attestation or proof of an installed service.", "The online issuer uses a dedicated preprovided client-only intermediate; the root private key remains offline.", "SQLite state is protected by filesystem controls and is not encrypted; old-backup rollback requires explicit recovery.", "Optional on-demand service log content requires a compatible updated endpoint and separate local helper/content permission. It is ephemeral, may contain secrets despite masking, and is excluded from AI, exports and diagnostics.", "Managed inventory is excluded from AI. Other AI analysis needs explicit consent; current private LAN model endpoints remain unsupported."}
	}
	if insecure {
		transport = "http-signed-test"
		limitations = append([]string{"UNENCRYPTED LAN TEST: telemetry, operator passwords and sessions are exposed. Signed telemetry has no server or UI authenticity and does not prevent operator session hijacking. Use distinct disposable test material."}, limitations...)
	}
	write(w, 200, map[string]any{"mode": s.mode(), "version": model.Version, "syntheticFleet": false, "realCollector": collector, "remoteEnrollment": guided, "identityMode": identityMode, "manualDeviceApproval": true, "shellExecution": false, "aiConnected": false, "aiConfigured": s.aiConfigured(), "managedPreview": false, "persistence": "SQLite", "agentTransport": transport, "insecureTestMode": insecure, "limitations": limitations})
	return true
}
