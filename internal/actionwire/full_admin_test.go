package actionwire

import (
	"encoding/json"
	"fmt"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionpermit"
	"testing"
)

func TestV2CapabilityBudgetAndCodecCannotWidenV1(t *testing.T) {
	d := actionpermit.Digest(nil)
	c := actionhelper.Capabilities{Version: actionhelper.CapabilitiesVersionV2, Enabled: true, ManagerID: "manager_11111111111111111111111111111111", KeyID: d, EndpointID: "agent_22222222222222222222222222222222", IncarnationDigest: d, RootPolicyDigest: d, TransportProfile: actionhelper.ProductionTLS, CapturedAt: 1700000000, MaxLifetimeSeconds: 60, Services: []actionhelper.CapabilityService{}, Scope: actionhelper.FullAdminServiceScope, ReviewNotice: actionhelper.FullAdminReviewNotice}
	for i := 0; i < 100; i++ {
		unit := fmt.Sprintf("ordinary%03d.service", i)
		c.Services = append(c.Services, actionhelper.CapabilityService{Unit: unit, UnitPolicyDigest: d, AffectedServices: []string{unit}})
	}
	raw, e := EncodeCapabilitiesV2(c)
	if e != nil || len(raw) <= MaxBodyBytes {
		t.Fatal("not expanded bounded fixture", len(raw), e)
	}
	if _, e = DecodeCapabilitiesV2(raw); e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeCapabilities(raw); e == nil {
		t.Fatal("v1 decoder widened")
	}
	if _, e = EncodeCapabilities(c); e == nil {
		t.Fatal("v1 encoder widened")
	}
	if BodyLimit(CapabilitiesPath) != MaxBodyBytes || BodyLimit(CapabilitiesPathV2) != MaxCapabilitiesBytesV2 {
		t.Fatal("wrong path budget")
	}
	c.Version = actionhelper.CapabilitiesVersion
	c.Scope = ""
	c.ReviewNotice = ""
	for i := range c.Services {
		c.Services[i].AffectedServices = nil
	}
	raw, _ = json.Marshal(c)
	if _, e = DecodeCapabilities(raw); e == nil {
		t.Fatal("v1 service count widened")
	}
}
