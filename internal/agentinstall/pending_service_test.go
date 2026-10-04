package agentinstall

import (
	"strings"
	"testing"
)

func TestPendingServicePlanRequiresExplicitFreshModeAndStableResume(t *testing.T) {
	r := Request{Action: Install, PendingService: true, AgentBinary: "/fixture/agent", AgentSHA256: strings.Repeat("a", 64), EnrollBinary: "/fixture/enroll", EnrollSHA256: strings.Repeat("b", 64), SourceArchive: "/fixture/source.tar", SourceSHA256: strings.Repeat("c", 64), BootstrapFile: "/fixture/bootstrap.json", BootstrapSHA256: strings.Repeat("d", 64)}
	h := HostFacts{Linux: true, SystemdAvailable: true, Root: true, AccountCompatible: true, Profile: "tls"}
	p, e := BuildPlan(r, h)
	if e != nil || p.SchemaVersion != "tracebolt.agent-install-plan.v2" || p.ServiceStartRequiresEnrollment || !p.ServiceStartRequiresCommittedClaim {
		t.Fatal("pending plan contract", e)
	}
	h.RetainedPreparation = true
	r.Resume = true
	if _, e = BuildPlan(r, h); e == nil {
		t.Fatal("ready-only preparation adopted")
	}
	h.PendingService = true
	if _, e = BuildPlan(r, h); e != nil {
		t.Fatal("same pending mode rejected", e)
	}
	r.PendingService = false
	if _, e = BuildPlan(r, h); e == nil {
		t.Fatal("pending preparation downgraded")
	}
	r.PendingService = true
	r.Action = Upgrade
	r.Resume = false
	h.InstallationOwned = true
	h.RetainedPreparation = false
	if _, e = BuildPlan(r, h); e == nil {
		t.Fatal("explicit mode accepted on upgrade")
	}
	r.PendingService = false
	if p, e = BuildPlan(r, h); e != nil || !p.ServiceStartRequiresCommittedClaim {
		t.Fatal("upgrade did not derive owned pending mode", e)
	}
}
func TestPendingServiceUnitPinsModeProfileAndNumericIdentity(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		unit, e := PendingUnitForAccount(1001, 1002, profile)
		if e != nil || strings.Contains(unit, "ConditionPathExists=") || !strings.Contains(unit, "--service-identity 1001:1002") || !strings.Contains(unit, "--enrollment-bootstrap "+BootstrapPath) || !strings.Contains(unit, "--enrollment-state-directory "+EnrollmentDirectory) || strings.Contains(unit, "--insecure-http-test") != (profile == "http-test") {
			t.Fatal("unit mode/profile/identity contract")
		}
		for _, required := range []string{"NoNewPrivileges=true", "ProtectSystem=strict", "RestartPreventExitStatus=2", "KillMode=control-group", "User=1001\n", "Group=1002\n"} {
			if !strings.Contains(unit, required) {
				t.Fatal("pending unit lost guard", required)
			}
		}
	}
	if _, e := PendingUnitForAccount(0, 0, "tls"); e == nil {
		t.Fatal("root unit allowed")
	}
	if _, e := PendingUnitForAccount(1001, 1002, "unknown"); e == nil {
		t.Fatal("unknown profile")
	}
	ready, _ := UnitForAccount(1001, 1002)
	if !strings.Contains(ready, "ConditionPathExists=") || strings.Contains(ready, "--enrollment-bootstrap") {
		t.Fatal("v1 unit silently changed")
	}
}
