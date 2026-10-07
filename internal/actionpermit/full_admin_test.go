package actionpermit

import "testing"

func TestV2FreshScopeNeverWidensLegacyVerifier(t *testing.T) {
	p, pins, key := fixture(t)
	legacy, e := NewVerifier(pins)
	if e != nil {
		t.Fatal(e)
	}
	old := signed(t, p, key)
	p.Version = VersionV2
	p.Plan.Version = PlanVersionV2
	p.Plan.Unit = "sshd.service"
	p.Plan.AffectedServicesDigest, _ = AffectedServicesDigest([]string{"sshd.service"})
	p.PlanDigest, _ = PlanDigest(p.Plan)
	raw := signed(t, p, key)
	if _, e = legacy.Verify(raw); e == nil {
		t.Fatal("v1 admitted v2")
	}
	pins.Services = nil
	pins.Scope = FullAdminServiceScope
	v2, e := NewVerifier(pins)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = v2.Verify(raw); e != nil {
		t.Fatal(e)
	}
	if _, e = v2.Verify(old); e == nil {
		t.Fatal("v2 admitted legacy scope")
	}
	p.Version = Version
	if _, e = SigningMessage(p); e == nil {
		t.Fatal("mixed plan and envelope version")
	}
	pins.Scope = ""
	if _, e = NewVerifier(pins); e == nil {
		t.Fatal("empty legacy allowlist widened")
	}
	pins.Scope = FullAdminServiceScope
	pins.Services = []ServiceRule{{"sshd.service", Digest(nil)}}
	if _, e = NewVerifier(pins); e == nil {
		t.Fatal("static and full scope mixed")
	}
}
