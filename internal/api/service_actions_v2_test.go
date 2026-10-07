package api

import (
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionpermit"
	"strings"
	"testing"
	"time"
)

func actionAPIV2Record(t *testing.T) (actionjob.Record, time.Time) {
	t.Helper()
	r, _, at := actionAPIRecord(t)
	c := *r.Capabilities
	r, err := actionjob.New(r.ManagerID, r.DeviceID, r.IncarnationDigest, r.PublicKey, at)
	if err != nil {
		t.Fatal(err)
	}
	c.Version = actionhelper.CapabilitiesVersionV2
	c.Scope = actionhelper.FullAdminServiceScope
	c.ReviewNotice = actionhelper.FullAdminReviewNotice
	c.Services = []actionhelper.CapabilityService{{Unit: "fixture.service", UnitPolicyDigest: actionpermit.Digest([]byte("unit")), AffectedServices: []string{"dependent.service", "fixture.service"}}}
	c.ExcludedServices = []actionhelper.ServiceExclusion{{Unit: "tracebolt-agent.service", Reason: "control_plane_protected"}}
	if err := r.Report(c, at); err != nil {
		t.Fatal(err)
	}
	if _, err := r.MakePreview("action_"+strings.Repeat("8", 32), namedActorID, "fixture.service", actionhelper.ProductionTLS, at); err != nil {
		t.Fatal(err)
	}
	return r, at
}

func TestServiceActionV2APIEmitsExactImpactAndPreservesV1(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		r, _, at := actionAPIRecord(t)
		if v2 {
			r, at = actionAPIV2Record(t)
		}
		o, _ := namedOperatorFixture(t)
		o.server.Config.Handler.(*operatorHandler).actions = &clockActionFixture{record: r, observed: at.Add(time.Second)}
		o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
		response, view := o.call(t, "GET", "/api/devices/"+namedDeviceID+"/service-actions", nil, "", nil)
		if response.StatusCode != 200 {
			t.Fatal(response.StatusCode, view)
		}
		service := view["services"].([]any)[0].(map[string]any)
		preview := view["preview"].(map[string]any)
		if v2 {
			if view["schemaVersion"] != "tracebolt.service-action-view.v2" || view["scope"] != actionhelper.FullAdminServiceScope || view["reviewNotice"] != actionhelper.FullAdminReviewNotice {
				t.Fatal(view)
			}
			impact := service["affectedServices"].([]any)
			if len(impact) != 2 || impact[0] != "dependent.service" || impact[1] != "fixture.service" {
				t.Fatal(service)
			}
			if len(preview["affectedServices"].([]any)) != 2 || preview["version"] != actionjob.PreviewVersionV2 || preview["plan"].(map[string]any)["affectedServicesDigest"] != r.Preview.Plan.AffectedServicesDigest {
				t.Fatal(preview)
			}
		} else {
			if view["schemaVersion"] != "tracebolt.service-action-view.v1" || view["scope"] != nil || view["reviewNotice"] != nil || service["affectedServices"] != nil || preview["affectedServices"] != nil || preview["plan"].(map[string]any)["affectedServicesDigest"] != nil {
				t.Fatal("v1 broadened", view)
			}
		}
	}
}

func TestServiceActionV2ImpactDriftSuppressesPreview(t *testing.T) {
	for _, which := range []string{"shortened", "added", "reordered", "duplicate", "preview", "notice", "version"} {
		t.Run(which, func(t *testing.T) {
			r, at := actionAPIV2Record(t)
			if usableServicePreview(r, actionhelper.ProductionTLS, at.Add(time.Second)) == nil {
				t.Fatal("valid preview hidden")
			}
			switch which {
			case "shortened":
				r.Capabilities.Services[0].AffectedServices = []string{"fixture.service"}
			case "added":
				r.Capabilities.Services[0].AffectedServices = []string{"dependent.service", "extra.service", "fixture.service"}
			case "reordered":
				r.Capabilities.Services[0].AffectedServices = []string{"fixture.service", "dependent.service"}
			case "duplicate":
				r.Capabilities.Services[0].AffectedServices = []string{"fixture.service", "fixture.service"}
			case "preview":
				r.Preview.AffectedServices = []string{"fixture.service"}
			case "notice":
				r.Preview.ReviewNotice = "changed"
			case "version":
				r.Preview.Version = actionjob.PreviewVersion
			}
			if usableServicePreview(r, actionhelper.ProductionTLS, at.Add(time.Second)) != nil {
				t.Fatal("changed impact emitted with valid opaque unit digest")
			}
		})
	}
}
