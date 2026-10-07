package actionclient

import (
	"context"
	"localrmm/internal/actionhelper"
	"testing"
)

func TestClientRequiresExplicitVersionedFullAdminCapabilityExchange(t *testing.T) {
	c := fixtureCapabilities()
	c.Version = actionhelper.CapabilitiesVersionV2
	c.Scope = actionhelper.FullAdminServiceScope
	c.ReviewNotice = actionhelper.FullAdminReviewNotice
	c.Services[0].AffectedServices = []string{"fixture.service"}
	client, calls := fixtureClient(t, actionhelper.Request{Version: actionhelper.RequestVersionV2, Operation: actionhelper.CapabilitiesOperation}, responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersionV2, Capabilities: &c}))
	got, e := client.FullAdminCapabilities(context.Background())
	if e != nil || got.Version != c.Version || calls.Load() != 1 {
		t.Fatal(got, e)
	}
	client, _ = fixtureClient(t, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.CapabilitiesOperation}, responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersionV2, Capabilities: &c}))
	if _, e = client.Capabilities(context.Background()); e == nil {
		t.Fatal("legacy client adopted broad scope")
	}
}
