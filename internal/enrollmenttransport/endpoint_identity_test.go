package enrollmenttransport

import (
	"bytes"
	"context"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/systemwire"
	"testing"
	"time"
)

func TestEndpointIdentityTLSHTTPActivationReplayAndRevocation(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, false)
			_, server, client := f.listen(t, nil)
			at := time.Now().UTC().Add(-time.Second)
			system := systemSnapshotFixture(t, f.snapshot.Approval.DeviceID, 1, at)
			identity := endpointidentity.Empty(system.GenerationID, at, endpointidentity.ReasonNotCollected)
			hostname := "fixture-endpoint"
			identity.ReportedHostname = endpointidentity.Hostname{Coverage: endpointidentity.Complete, Reason: endpointidentity.ReasonNone, Value: &hostname}
			raw, e := systemwire.EncodeEndpoint(1, system, identity)
			if e != nil {
				t.Fatal(e)
			}
			response(t, client, f.systemRequest(t, server.URL, 1, raw), 403)
			f.activate(t)
			first := response(t, client, f.systemRequest(t, server.URL, 1, raw), 200)
			if _, e = systemwire.DecodeReceipt(first, f.snapshot.Approval.DeviceID, raw); e != nil {
				t.Fatal(e)
			}
			again := response(t, client, f.systemRequest(t, server.URL, 1, raw), 200)
			if !bytes.Equal(first, again) {
				t.Fatal("extended exact retry changed receipt")
			}
			response(t, client, f.systemRequest(t, server.URL, 1, append([]byte(" "), raw...)), 409)
			view, e := f.store.EndpointIdentityView(context.Background(), f.snapshot.Approval.DeviceID, time.Now().UTC())
			if e != nil || view.Latest == nil || *view.Latest.ReportedHostname.Value != hostname {
				t.Fatal("accepted identity unavailable", e)
			}
			f.revoke(t)
			response(t, client, f.systemRequest(t, server.URL, 1, raw), 403)
			view, e = f.store.EndpointIdentityView(context.Background(), f.snapshot.Approval.DeviceID, time.Now().UTC())
			if e != nil || view.Status != "revoked" || view.Latest != nil {
				t.Fatal("revoked identity visible", e)
			}
		})
	}
}
