package actionjob

import (
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionpermit"
	"testing"
	"time"
)

func TestFullAdminNamedPreviewBindsScopeRiskGraphAndOriginalExpiry(t *testing.T) {
	r, sign := fixture(t)
	c := *r.Capabilities
	c.Services = append([]actionhelper.CapabilityService(nil), c.Services...)
	c.Version = actionhelper.CapabilitiesVersionV2
	c.Scope = actionhelper.FullAdminServiceScope
	c.ReviewNotice = actionhelper.FullAdminReviewNotice
	c.Services[0].AffectedServices = []string{"fixture.service"}
	c.CapturedAt++
	if e := r.Report(c, at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	p, e := r.MakePreview("action_33333333333333333333333333333333", "operator_44444444444444444444444444444444", "fixture.service", actionhelper.ProductionTLS, at.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if p.Version != PreviewVersionV2 || p.Plan.Version != actionpermit.PlanVersionV2 || p.ReviewNotice != actionhelper.FullAdminReviewNotice || p.Scope != actionhelper.FullAdminServiceScope || len(p.AffectedServices) != 1 {
		t.Fatal(p)
	}
	changed := p
	changed.ReviewNotice = "reduced warning"
	if PreviewDigest(changed) == p.Digest || validPreview(changed) {
		t.Fatal("notice unbound")
	}
	j, e := r.Approve(p.ID, p.Digest, p.ActorID, p.TransportProfile, at.Add(2*time.Second), sign)
	if e != nil {
		t.Fatal(e)
	}
	permit, e := actionpermit.Decode(j.Envelope)
	if e != nil || permit.Version != actionpermit.VersionV2 || j.Approval.Version != ApprovalVersionV2 || permit.StartDeadline != at.Add(47*time.Second).Unix() {
		t.Fatal(permit, e)
	}
	if e = Validate(r); e != nil {
		t.Fatal(e)
	}
	duplicate, e := r.Approve(p.ID, p.Digest, p.ActorID, p.TransportProfile, at.Add(3*time.Second), sign)
	if e != nil || string(duplicate.Envelope) != string(j.Envelope) {
		t.Fatal("renewed approval", e)
	}
}
