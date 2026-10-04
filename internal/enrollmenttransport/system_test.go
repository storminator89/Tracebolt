package enrollmenttransport

import (
	"bytes"
	"context"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
	"net/http"
	"testing"
	"time"
)

func systemSnapshotFixture(t *testing.T, device string, sequence uint64, at time.Time) systeminventory.Snapshot {
	t.Helper()
	generation, e := systemwire.GenerationID(device, sequence)
	if e != nil {
		t.Fatal(e)
	}
	s := systeminventory.Empty(generation, at, systeminventory.ReasonReadFailed)
	count := uint64(257)
	s.Services.Meta = systeminventory.SectionMeta{GenerationID: generation, ObservedAt: at, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: &count, CountExact: true}
	enabled := "enabled"
	for i := 0; i < int(count); i++ {
		s.Services.Items = append(s.Services.Items, systeminventory.Service{Name: fmt.Sprintf("invented-%04d.service", i), Runtime: &systeminventory.ServiceRuntime{LoadState: "loaded", ActiveState: "active", SubState: "running"}, Enablement: &enabled})
	}
	sockets := uint64(1)
	s.Sockets.Meta = systeminventory.SectionMeta{GenerationID: generation, ObservedAt: at, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: &sockets, CountExact: true}
	s.Sockets.Items = []systeminventory.Socket{{Protocol: "tcp", Family: "ipv4", Kind: "listener", Local: systeminventory.Endpoint{Address: "127.0.0.1", Port: 8080}, Remote: systeminventory.Endpoint{Address: "0.0.0.0"}, State: "listen", Owners: []systeminventory.Owner{}, Attribution: systeminventory.Attribution{Coverage: systeminventory.AttributionUnavailable, Reason: systeminventory.ReasonPermissionDenied}}}
	if systeminventory.Validate(s) != nil {
		t.Fatal("invalid synthetic system fixture")
	}
	return s
}
func (f *fixture) systemRequest(t *testing.T, origin string, seq uint64, raw []byte) *http.Request {
	t.Helper()
	if f.config.Binding.Profile == "http-test" {
		r, e := systemwire.NewSignedRequest(context.Background(), origin, f.pair, seq, time.Now().UTC(), raw)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	r, e := http.NewRequest(http.MethodPost, origin+systemwire.Path, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}
func TestSystemObservationRealTLSAndHTTPAuthorityReplayAndRetention(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, false)
			_, server, client := f.listen(t, nil)
			at := time.Now().UTC().Add(-time.Second)
			snapshot := systemSnapshotFixture(t, f.snapshot.Approval.DeviceID, 1, at)
			raw, e := systemwire.Encode(1, snapshot)
			if e != nil {
				t.Fatal(e)
			}
			response(t, client, f.systemRequest(t, server.URL, 1, raw), 403)
			f.activate(t)
			first := response(t, client, f.systemRequest(t, server.URL, 1, raw), 200)
			receipt, e := systemwire.DecodeReceipt(first, f.snapshot.Approval.DeviceID, raw)
			if e != nil || !receipt.CollectedAt.Equal(at) {
				t.Fatal("receipt mismatch", e)
			}
			again := response(t, client, f.systemRequest(t, server.URL, 1, raw), 200)
			if !bytes.Equal(first, again) {
				t.Fatal("exact retry refreshed receipt")
			}
			response(t, client, f.systemRequest(t, server.URL, 1, append([]byte(" "), raw...)), 409)
			query := enrollmentstore.SystemPageRequest{Section: "services", GenerationID: snapshot.GenerationID, Limit: 100, Filter: "active"}
			page, e := f.store.SystemPage(context.Background(), f.snapshot.Approval.DeviceID, query, time.Now().UTC())
			if e != nil || page.TotalRows != 257 || len(page.Services) != 100 || page.Exhausted {
				t.Fatal("full service rows not retained", e)
			}
			later := at.Add(time.Millisecond)
			generation, _ := systemwire.GenerationID(f.snapshot.Approval.DeviceID, 2)
			failed := systeminventory.Empty(generation, later, systeminventory.ReasonPermissionDenied)
			body, _ := systemwire.Encode(2, failed)
			response(t, client, f.systemRequest(t, server.URL, 2, body), 200)
			view, e := f.store.SystemView(context.Background(), f.snapshot.Approval.DeviceID, time.Now().UTC())
			if e != nil || view.Latest == nil || view.Latest.Services.Coverage != systeminventory.Failed || view.LastComplete.Services == nil || view.LastComplete.Services.Meta.GenerationID != snapshot.GenerationID || !view.LastComplete.Services.Meta.ObservedAt.Equal(at) {
				t.Fatal("failure erased/refreshed complete section", e)
			}
			f.revoke(t)
			response(t, client, f.systemRequest(t, server.URL, 2, body), 403)
		})
	}
}
func TestSystemObservationRefusesOlderCollectionProfiles(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t, profile, true)
			_, server, client := f.listen(t, nil)
			response(t, client, f.systemRequest(t, server.URL, 1, []byte(`{}`)), 404)
		})
	}
}
