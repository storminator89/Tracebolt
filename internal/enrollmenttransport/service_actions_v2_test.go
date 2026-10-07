package enrollmenttransport

import (
	"context"
	"encoding/json"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionwire"
	"localrmm/internal/enrollmentcrypto"
	"testing"
)

// Inert loopback transport/store proof. No native command, target restart or
// host policy change. Real mTLS and signed-HTTP framing remain authoritative.
func TestServiceActionV2TransportPreviewImpactBinding(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, true)
			h, server, client := f.listen(t, nil)
			manager, helper, backend, peer := prepareActions(t, f, h)
			caps, err := helper.Capabilities(context.Background(), peer)
			if err != nil {
				t.Fatal(err)
			}
			caps.Version = actionhelper.CapabilitiesVersionV2
			caps.Scope = actionhelper.FullAdminServiceScope
			caps.ReviewNotice = actionhelper.FullAdminReviewNotice
			caps.Services[0].AffectedServices = []string{"dependent.service", "fixture.service"}
			body, err := actionwire.EncodeCapabilitiesV2(caps)
			if err != nil {
				t.Fatal(err)
			}
			response(t, client, f.actionRequest(t, server.URL, actionwire.CapabilitiesPathV2, 1, body), 200)
			o := actionOperatorNew(t, f, manager, true)
			path := "/api/devices/" + f.snapshot.Approval.DeviceID + "/service-actions"
			w := o.call(t, "POST", path+"/preview", map[string]string{"unit": "fixture.service"}, nil)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			var view struct {
				SchemaVersion string             `json:"schemaVersion"`
				Preview       *actionjob.Preview `json:"preview"`
			}
			if err = json.Unmarshal(w.Body.Bytes(), &view); err != nil || view.SchemaVersion != "tracebolt.service-action-view.v2" || view.Preview == nil {
				t.Fatal(err, w.Body.String())
			}
			impact, _ := actionpermit.AffectedServicesDigest(caps.Services[0].AffectedServices)
			if view.Preview.Plan.AffectedServicesDigest != impact || len(view.Preview.AffectedServices) != 2 || view.Preview.Version != actionjob.PreviewVersionV2 {
				t.Fatal("unbound impact", view.Preview)
			}
			approval := map[string]string{"previewId": view.Preview.ID, "previewDigest": view.Preview.Digest}
			// A valid new capability report may change the impact projection while the
			// opaque unit digest stays equal. That invalidates the old exact review.
			caps.Services[0].AffectedServices = []string{"fixture.service"}
			caps.CapturedAt++
			body, err = actionwire.EncodeCapabilitiesV2(caps)
			if err != nil {
				t.Fatal(err)
			}
			response(t, client, f.actionRequest(t, server.URL, actionwire.CapabilitiesPathV2, 1, body), 200)
			w = o.call(t, "POST", path+"/approve", approval, nil)
			if w.Code != 409 {
				t.Fatal("stale impact approval", w.Code, w.Body.String())
			}
			if backend.calls.Load() != 0 {
				t.Fatal("test dispatched native target")
			}
		})
	}
}
