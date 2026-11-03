package api

import (
	"localrmm/internal/enrollmentcrypto"
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
	profile, renewal := s.aiCollectionProfile, s.automaticCertificateRenewal
	health, journalAI, cve := s.health != nil, s.journalAI != nil, s.linuxCVE != nil
	s.mu.RUnlock()
	if !lan {
		return false
	}
	transport := "https-mtls"
	identityMode := "manual-v1"
	collector := "Separately approved agent inventory observations; no manager-side endpoint inventory collector or synthetic fallback."
	limitations := []string{
		"Manual agent-certificate approval is configured; there is no online certificate issuer, guided enrollment or discovery in this identity mode.",
		"Only latest bounded manual-agent observations are retained; guided resource history and complete-profile Linux inventory, health and CVE assessment are not configured.",
	}
	if guided {
		identityMode = "guided-v2"
		collector = "Separately enrolled agent inventory observations with explicit approval and activation; no manager-side endpoint inventory collector or synthetic fallback."
		limitations = []string{
			"Guided enrollment requires invitation, identity approval and activation, with at most 25 retained identities including tombstones per configured store; it does not provide discovery or unattended trust.",
			"Foreground reporting and separately installed agent services are supported source paths. This API does not establish service installation, enablement, native acceptance or successful OS reboot.",
			"Bounded resource history retains newly accepted basic utilization observations with their original ages and visible gaps; it does not backfill missing samples or establish host health.",
			"The online issuer uses a dedicated preprovided client-only intermediate; the root private key remains offline.",
		}
		switch profile {
		case enrollmentcrypto.CollectionProfile:
			limitations = append(limitations, "Configured Linux collection profile "+profile+" does not enable managed operational/package inventory or complete-profile health checks. Separately configured platform domains retain their own consent and scope.")
		case enrollmentcrypto.CollectionProfileOperational:
			limitations = append(limitations, "Configured Linux collection profile "+profile+" supports bounded operational metadata, not complete dpkg generations or complete-profile health checks.")
		case enrollmentcrypto.CollectionProfilePackages:
			limitations = append(limitations, "Configured Linux collection profile "+profile+" adds bounded selected package observations, not complete dpkg generations or complete-profile health checks. Offline advisory review is candidate evidence rather than confirmed CVE or offered-update coverage.")
		case enrollmentcrypto.CollectionProfileComplete:
			limitations = append(limitations, "Configured Linux collection profile "+profile+" supports complete dpkg generations and paged service/socket views; current coverage, permission gaps and original ages are shown separately. Optional inventory extensions still require their own local consent.")
		default:
			limitations = append(limitations, "Collection scope is unavailable in this metadata; no managed inventory or host authority may be inferred from guided enrollment alone.")
		}
		if renewal && !insecure {
			limitations = append(limitations, "Automatic same-key certificate renewal is configured for freshly consented TLS identities. It does not extend original collection/helper grants, install services or prove successful endpoint renewal; each identity reports its own renewal status.")
		} else {
			limitations = append(limitations, "Automatic certificate renewal is not configured for this identity mode; HTTP-test renewal is unsupported. Existing identities and grants are not promoted automatically.")
		}
		if health {
			limitations = append(limitations, "Complete-profile Linux health monitoring evaluates accepted agent contact, root-filesystem capacity and explicitly selected services, with bounded incident history. It does not execute remediation. Background health-summary AI requires separate device/provider consent.")
		}
		if cve {
			limitations = append(limitations, "Linux CVE warnings compare complete supported distribution package generations with explicitly downloaded or imported advisory data. A published-fix version match is not proof of exploitability, an offered update or permission to install it.")
		}
		if journalAI {
			limitations = append(limitations, "Optional service log content requires a compatible endpoint and separate local helper/content permission. It is ephemeral and may contain secrets despite masking. General case AI and health-summary AI exclude logs; service-log AI requires its own default-off device/service/provider export approval and does not export retained browsing pages.")
		}
		if enrollmentcrypto.ManagedCollectionProfile(profile) {
			limitations = append(limitations, "Managed inventory is excluded from general case AI; collection consent alone never authorizes AI export.")
		}
	}
	limitations = append(limitations,
		"Agent observations are authenticated claims, not independent operating-system attestation. There is no remote shell or automatic remediation; separately supported reviewed actions require their own setup, grants and operator approval.",
		"SQLite state is protected by filesystem access controls but is not encrypted; old-backup rollback requires explicit recovery.",
		"Saving AI settings does not test connectivity or start analysis. Manual analysis requires an explicit request. Private IPv4 LAN HTTPS providers require explicit destination and evidence-sharing consent and remain process-memory-only; private-CA trust additionally requires the authenticated TLS operator surface.",
	)
	if insecure {
		transport = "http-signed-test"
		limitations = append([]string{"UNENCRYPTED LAN TEST: telemetry, operator passwords and sessions are exposed. Signed telemetry has no server or UI authenticity and does not prevent operator session hijacking. Use distinct disposable test material."}, limitations...)
	}
	write(w, 200, map[string]any{"mode": s.mode(), "version": model.Version, "syntheticFleet": false, "realCollector": collector, "remoteEnrollment": guided, "identityMode": identityMode, "manualDeviceApproval": true, "shellExecution": false, "aiConnected": false, "aiConfigured": s.aiConfigured(), "managedPreview": false, "persistence": "SQLite", "agentTransport": transport, "insecureTestMode": insecure, "limitations": limitations})
	return true
}
