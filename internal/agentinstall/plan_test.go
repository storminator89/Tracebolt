package agentinstall

import (
	"strings"
	"testing"
)

func TestPlanGatesAndRetainedIdentity(t *testing.T) {
	h := HostFacts{Linux: true, SystemdAvailable: true, Root: true, AccountCompatible: true, InstallationOwned: true, EnrollmentReady: true, Profile: "tls"}
	r := Request{Action: Install, AgentBinary: "/fixture/agent", AgentSHA256: strings.Repeat("1", 64), EnrollBinary: "/fixture/enroll", EnrollSHA256: strings.Repeat("2", 64), BootstrapFile: "/fixture/public.json", BootstrapSHA256: strings.Repeat("4", 64), SourceArchive: "/fixture/source.tar", SourceSHA256: strings.Repeat("3", 64)}
	for _, action := range []Action{Install, Upgrade, Restart, Uninstall} {
		r.Action = action
		h.InstallationOwned = action != Install
		p, e := BuildPlan(r, h)
		if e != nil || !p.DryRun || !p.IdentityRetained || !p.ServiceStartRequiresEnrollment {
			t.Fatal("invalid safe plan")
		}
	}
	r.Action = Install
	r.Apply = true
	bad := h
	bad.Root = false
	if _, e := BuildPlan(r, bad); e == nil {
		t.Fatal("unprivileged apply accepted")
	}
	bad = h
	bad.SystemdAvailable = false
	if _, e := BuildPlan(r, bad); e == nil {
		t.Fatal("non-systemd fallback accepted")
	}
	bad = h
	bad.AccountCompatible = false
	if _, e := BuildPlan(r, bad); e == nil {
		t.Fatal("incompatible account adopted")
	}
	bad = h
	bad.Profile = "http-test"
	if _, e := BuildPlan(r, bad); e == nil {
		t.Fatal("HTTP service without explicit acknowledgement")
	}
	r.Action = Uninstall
	bad = h
	bad.InstallationOwned = false
	if _, e := BuildPlan(r, bad); e == nil {
		t.Fatal("foreign installation removed")
	}
}
func TestUnitHasNoDynamicShellOrPrivilegeGrant(t *testing.T) {
	for _, required := range []string{"User=tracebolt-agent", "Group=tracebolt-agent", "NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true", "CapabilityBoundingSet=\n", "ReadWritePaths=/var/lib/tracebolt-agent", "--foreground", "ConditionPathExists="} {
		if !strings.Contains(Unit, required) {
			t.Fatal("missing unit control")
		}
	}
	for _, forbidden := range []string{"/bin/sh", "/bin/bash", "curl ", "wget ", "Environment=", "sudo ", "User=root"} {
		if strings.Contains(Unit, forbidden) {
			t.Fatal("unexpected unit privilege or shell")
		}
	}
}
