package agentinstall

import (
	"strings"
	"testing"
)

func TestReadAdminRequiresExplicitCompleteProfileBeforeEffects(t *testing.T) {
	r := Request{Action: Install, RequireCompleteProfile: true,
		AgentBinary: "/fixture/agent", EnrollBinary: "/fixture/enroll", SourceArchive: "/fixture/source.tar", BootstrapFile: "/fixture/bootstrap.json",
		AgentSHA256: strings.Repeat("1", 64), EnrollSHA256: strings.Repeat("2", 64), SourceSHA256: strings.Repeat("3", 64), BootstrapSHA256: strings.Repeat("4", 64)}
	h := HostFacts{Linux: true, SystemdAvailable: true, AccountCompatible: true, Profile: "tls"}
	for _, profile := range []string{"", "managed-operations-v1", "managed-operations-v2", "managed-operations-v3", "unknown"} {
		h.CollectionProfile = profile
		_, err := BuildPlan(r, h)
		if (err == nil) != (profile == "managed-operations-v3") {
			t.Fatalf("profile gate failed: %s", profile)
		}
	}
	h.CollectionProfile = "managed-operations-v3"
	r.ExpectedAgentOrigin = "https://manager.example:8444"
	if _, err := BuildPlan(r, h); err == nil {
		t.Fatal("unverified agent ingress accepted")
	}
	h.AgentOrigin = r.ExpectedAgentOrigin
	if _, err := BuildPlan(r, h); err != nil {
		t.Fatal("verified agent ingress rejected")
	}
	h.InstallationOwned = true
	r.Action = Upgrade
	if _, err := BuildPlan(r, h); err == nil {
		t.Fatal("read-admin flag silently expanded an existing upgrade")
	}
}
