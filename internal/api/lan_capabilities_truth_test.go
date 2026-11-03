package api

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/model"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLANCapabilitiesDescribeConfiguredScope(t *testing.T) {
	for _, tc := range []struct {
		name, profile             string
		guided, insecure, renewal bool
		complete                  bool
		want, absent              []string
	}{
		{name: "manual-tls", want: []string{"Manual agent-certificate approval", "Only latest bounded manual-agent observations"}, absent: []string{"Bounded resource history retains", "Automatic same-key"}},
		{name: "manual-http", insecure: true, want: []string{"Manual agent-certificate approval"}, absent: []string{"Bounded resource history retains", "Automatic same-key"}},
		{name: "guided-basic", guided: true, profile: enrollmentcrypto.CollectionProfile, want: []string{"basic-readonly-v1 does not enable", "Bounded resource history retains", "renewal is not configured"}, absent: []string{"supports complete dpkg", "Offline advisory review", "Linux CVE warnings compare", "health monitoring evaluates", "service-log AI requires"}},
		{name: "guided-operational", guided: true, profile: enrollmentcrypto.CollectionProfileOperational, want: []string{"managed-operations-v1 supports bounded operational metadata", "Managed inventory is excluded from general case AI"}, absent: []string{"supports complete dpkg", "Offline advisory review", "Linux CVE warnings compare", "health monitoring evaluates", "service-log AI requires"}},
		{name: "guided-packages", guided: true, profile: enrollmentcrypto.CollectionProfilePackages, want: []string{"managed-operations-v2 adds bounded selected package observations", "Offline advisory review is candidate evidence"}, absent: []string{"supports complete dpkg", "Linux CVE warnings compare", "health monitoring evaluates", "service-log AI requires"}},
		{name: "guided-complete", guided: true, complete: true, profile: enrollmentcrypto.CollectionProfileComplete, want: []string{"managed-operations-v3 supports complete dpkg", "original ages", "health monitoring evaluates", "Linux CVE warnings compare", "separate local helper/content permission", "service-log AI requires its own default-off", "does not export retained browsing pages", "renewal is not configured"}, absent: []string{"Automatic same-key"}},
		{name: "renewable-tls", guided: true, renewal: true, profile: enrollmentcrypto.CollectionProfile, want: []string{"Automatic same-key certificate renewal is configured", "does not extend original collection/helper grants", "each identity reports its own renewal status"}, absent: []string{"renewal is not configured", "supports complete dpkg"}},
		{name: "http-never-renewable", guided: true, insecure: true, renewal: true, profile: enrollmentcrypto.CollectionProfile, want: []string{"HTTP-test renewal is unsupported"}, absent: []string{"Automatic same-key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{lanOnly: true, guidedEnrollment: tc.guided, insecureHTTPTest: tc.insecure, automaticCertificateRenewal: tc.renewal, aiCollectionProfile: tc.profile, ai: &aiState{}}
			if tc.complete {
				s.health, s.journalAI, s.linuxCVE = &healthMonitor{}, &journalAIState{}, &linuxCVEState{}
			}
			w := httptest.NewRecorder()
			if !s.lanCapabilities(w) || w.Code != http.StatusOK {
				t.Fatal("LAN capabilities unavailable")
			}
			var got struct {
				Mode, IdentityMode, AgentTransport          string
				RemoteEnrollment, InsecureTestMode          bool
				ShellExecution, AIConnected, SyntheticFleet bool
				Limitations                                 []string
			}
			if json.Unmarshal(w.Body.Bytes(), &got) != nil || got.ShellExecution || got.AIConnected || got.SyntheticFleet || got.RemoteEnrollment != tc.guided || got.InsecureTestMode != tc.insecure {
				t.Fatal("invalid capabilities or expanded authority")
			}
			identity, mode, transport := "manual-v1", "lan-tls-pilot", "https-mtls"
			if tc.guided {
				identity = "guided-v2"
			}
			if tc.insecure {
				mode, transport = "lan-http-test", "http-signed-test"
			}
			if got.IdentityMode != identity || got.Mode != mode || got.AgentTransport != transport || strings.HasPrefix(got.Limitations[0], "UNENCRYPTED LAN TEST") != tc.insecure {
				t.Fatal("identity or transport metadata mismatch")
			}
			text := strings.Join(got.Limitations, "\n")
			for _, want := range append(tc.want, "not independent operating-system attestation", "no remote shell or automatic remediation", "does not test connectivity or start analysis", "Private IPv4 LAN HTTPS providers require explicit", "private-CA trust additionally requires the authenticated TLS operator surface") {
				if !strings.Contains(text, want) {
					t.Fatalf("missing scope boundary %q", want)
				}
			}
			for _, obsolete := range append(tc.absent, "credential renewal is not implemented", "without a historical time series", "Private LAN model endpoints remain unsupported", "excluded from AI, exports and diagnostics", "one operator") {
				if strings.Contains(text, obsolete) {
					t.Fatalf("unconfigured or obsolete claim %q", obsolete)
				}
			}
		})
	}
	w := httptest.NewRecorder()
	if (&Server{}).lanCapabilities(w) || w.Body.Len() != 0 {
		t.Fatal("development surface received LAN metadata")
	}
}

func TestLANCapabilitiesRenewalPolicyComesFromEnrollment(t *testing.T) {
	f := newWindowsEventOperatorFixtureWithIssuerLifetime(t, false, 24*time.Hour, true)
	r, got := f.call(t, http.MethodGet, "/api/capabilities", nil, "", nil)
	encoded, err := json.Marshal(got)
	if err != nil || r.StatusCode != http.StatusOK || !strings.Contains(string(encoded), "Automatic same-key certificate renewal is configured") {
		t.Fatal("configured renewal policy missing from capabilities")
	}
	h := f.server.Config.Handler.(*operatorHandler)
	if _, err := NewLANOperatorHandler(f.app, LANOperatorConfig{Origin: f.server.URL, Auth: h.auth, Registry: f.registry, Devices: func() ([]model.Device, error) { return []model.Device{}, nil }}); err != nil {
		t.Fatal(err)
	}
	if f.app.automaticCertificateRenewal || f.app.guidedEnrollment {
		t.Fatal("manual configuration retained guided renewal metadata")
	}
}
