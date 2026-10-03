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
	lan, insecure := s.lanOnly, s.insecureHTTPTest
	s.mu.RUnlock()
	if !lan {
		return false
	}
	transport := "https-mtls"
	limitations := []string{"One-environment LAN pilot with one operator and manually approved agent certificates.", "Only latest bounded observations are retained; no scheduler, history, host health evaluation or automatic remediation.", "Agent observations are authenticated claims, not independent attestation of the operating system.", "No software update or CVE assessment is integrated into this runtime yet.", "No online certificate issuer, discovery, automatic enrollment, service installation or remote shell.", "SQLite state is protected by filesystem access controls but is not encrypted.", "AI settings do not verify connectivity; analysis requires an explicit request. Private LAN model endpoints remain unsupported by the current provider policy."}
	if insecure {
		transport = "http-signed-test"
		limitations = append([]string{"UNENCRYPTED LAN TEST: telemetry, operator passwords and sessions are exposed. Signed telemetry has no server or UI authenticity and does not prevent operator session hijacking. Use distinct disposable test material."}, limitations...)
	}
	write(w, 200, map[string]any{"mode": s.mode(), "version": model.Version, "syntheticFleet": false, "realCollector": "Separate manually approved agent observations; no manager-side collector or fallback.", "remoteEnrollment": false, "manualDeviceApproval": true, "shellExecution": false, "aiConnected": false, "aiConfigured": s.aiConfigured(), "managedPreview": false, "persistence": "SQLite", "agentTransport": transport, "insecureTestMode": insecure, "limitations": limitations})
	return true
}
