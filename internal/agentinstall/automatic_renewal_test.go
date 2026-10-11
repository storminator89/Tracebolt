package agentinstall

import (
	"strings"
	"testing"
)

func TestRenewalInstallPlanRequiresExactFreshTLSConsent(t *testing.T) {
	base := Request{Action: Install, AgentBinary: "/fixture/agent", EnrollBinary: "/fixture/enroll", SourceArchive: "/fixture/source", BootstrapFile: "/fixture/bootstrap", AgentSHA256: strings.Repeat("1", 64), EnrollSHA256: strings.Repeat("2", 64), SourceSHA256: strings.Repeat("3", 64), BootstrapSHA256: strings.Repeat("4", 64)}
	for _, selected := range []bool{false, true} {
		for _, acknowledged := range []bool{false, true} {
			r := base
			r.AutomaticRenewalAcknowledged = acknowledged
			h := HostFacts{Linux: true, SystemdAvailable: true, AccountCompatible: true, Profile: "tls", AutomaticRenewal: selected}
			if _, err := BuildPlan(r, h); (err == nil) != (selected == acknowledged) {
				t.Fatal("renewal plan mismatch")
			}
		}
	}
	for _, action := range []Action{Install, Upgrade, Restart, Uninstall} {
		r := base
		r.Action = action
		r.AutomaticRenewalAcknowledged = true
		h := HostFacts{Linux: true, SystemdAvailable: true, AccountCompatible: true, Profile: "tls", AutomaticRenewal: true, InstallationOwned: action != Install}
		if action == Install {
			r.Resume = true
			h.RetainedPreparation = true
		}
		if _, err := BuildPlan(r, h); err == nil {
			t.Fatal("retained renewal adoption")
		}
	}
	r := base
	r.AutomaticRenewalAcknowledged = true
	r.InsecureHTTPTest = true
	h := HostFacts{Linux: true, SystemdAvailable: true, AccountCompatible: true, Profile: "http-test", AutomaticRenewal: true}
	if _, err := BuildPlan(r, h); err == nil {
		t.Fatal("HTTP renewal")
	}
}
