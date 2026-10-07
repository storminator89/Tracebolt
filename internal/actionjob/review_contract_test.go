package actionjob

import (
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionpermit"
	"testing"
	"time"
)

func reviewedImpactFixture(t *testing.T) (Record, func(actionpermit.Permit) ([]byte, error)) {
	t.Helper()
	r, sign := fixture(t)
	c := *r.Capabilities
	c.Services = append([]actionhelper.CapabilityService(nil), c.Services...)
	c.Version = actionhelper.CapabilitiesVersionV2
	c.Scope = actionhelper.FullAdminServiceScope
	c.ReviewNotice = actionhelper.FullAdminReviewNotice
	c.Services[0].AffectedServices = []string{"dependent.service", "fixture.service"}
	c.CapturedAt++
	if e := r.Report(c, at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	return r, sign
}

// Preserves the reviewer's attack setup. The manager cannot authenticate an
// opaque graph digest, but it now signs the exact reported projection so that
// the root helper can reject a genuine graph digest paired with a shorter list.
func TestReviewAffectedServiceProjectionIsBoundToSignedPlan(t *testing.T) {
	r, sign := reviewedImpactFixture(t)
	genuine := r.Capabilities.Services[0].UnitPolicyDigest
	r.Capabilities.Services[0].AffectedServices = []string{"fixture.service"}
	p, e := r.MakePreview("action_33333333333333333333333333333333", "operator_44444444444444444444444444444444", "fixture.service", actionhelper.ProductionTLS, at.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	shortened, _ := actionpermit.AffectedServicesDigest([]string{"fixture.service"})
	trusted, _ := actionpermit.AffectedServicesDigest([]string{"dependent.service", "fixture.service"})
	if p.Plan.AffectedServicesDigest != shortened || p.Plan.AffectedServicesDigest == trusted || p.Plan.UnitPolicyDigest != genuine {
		t.Fatal("projection not independently bound", p)
	}
	j, e := r.Approve(p.ID, p.Digest, p.ActorID, p.TransportProfile, at.Add(2*time.Second), sign)
	if e != nil {
		t.Fatal(e)
	}
	permit, e := actionpermit.Decode(j.Envelope)
	if e != nil || permit.Plan.AffectedServicesDigest != shortened || permit.Plan != p.Plan {
		t.Fatal(permit, e)
	}
}
func TestReviewPreviewCannotChangeVisibleProjectionWithoutSignedPlan(t *testing.T) {
	r, _ := reviewedImpactFixture(t)
	p, e := r.MakePreview("action_33333333333333333333333333333333", "operator_44444444444444444444444444444444", "fixture.service", actionhelper.ProductionTLS, at.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	for _, list := range [][]string{nil, {"fixture.service"}, {"dependent.service", "extra.service", "fixture.service"}, {"fixture.service", "dependent.service"}, {"dependent.service", "fixture.service", "fixture.service"}} {
		altered := p
		altered.AffectedServices = list
		altered.Digest = PreviewDigest(altered)
		if validPreview(altered) {
			t.Fatal("display projection diverged from signed plan", list)
		}
	}
}
func TestReviewCapabilityProjectionDriftStopsApprovalBeforeSigning(t *testing.T) {
	r, sign := reviewedImpactFixture(t)
	p, e := r.MakePreview("action_33333333333333333333333333333333", "operator_44444444444444444444444444444444", "fixture.service", actionhelper.ProductionTLS, at.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	c := *r.Capabilities
	c.Services = append([]actionhelper.CapabilityService(nil), c.Services...)
	c.Services[0].AffectedServices = []string{"fixture.service"}
	c.CapturedAt++
	if e = r.Report(c, at.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	called := false
	_, e = r.Approve(p.ID, p.Digest, p.ActorID, p.TransportProfile, at.Add(3*time.Second), func(p actionpermit.Permit) ([]byte, error) { called = true; return sign(p) })
	if e == nil || called {
		t.Fatal("capability projection changed after exact preview", e, called)
	}
}
