//go:build linux

package security_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func systemAPISnapshot(t *testing.T, device string, at time.Time) systeminventory.Snapshot {
	t.Helper()
	generation, _ := systemwire.GenerationID(device, 1)
	s := systeminventory.Empty(generation, at, systeminventory.ReasonReadFailed)
	count := uint64(257)
	enabled := "enabled"
	s.Services.Meta = systeminventory.SectionMeta{GenerationID: generation, ObservedAt: at, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: &count, CountExact: true}
	for i := 0; i < 257; i++ {
		s.Services.Items = append(s.Services.Items, systeminventory.Service{Name: fmt.Sprintf("invented-%04d.service", i), Runtime: &systeminventory.ServiceRuntime{LoadState: "loaded", ActiveState: "active", SubState: "running"}, Enablement: &enabled})
	}
	if systeminventory.Validate(s) != nil {
		t.Fatal("invalid synthetic API fixture")
	}
	return s
}
func TestSystemInventoryOperatorActualTLSHTTPAllPagesAndDelayedExpiry(t *testing.T) {
	for _, plain := range []bool{false, true} {
		t.Run(fmt.Sprint(plain), func(t *testing.T) {
			h, _ := operationalAPIHTTPFixture(t, plain, enrollmentcrypto.CollectionProfileComplete)
			identity := operationalStoreActivate(t, h.f)
			session := h.session(t)
			at := h.f.clock()
			snapshot := systemAPISnapshot(t, identity.Approval.DeviceID, at)
			raw, e := systemwire.Encode(1, snapshot)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = h.f.store.SaveSystemObservation(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, raw, at); e != nil {
				t.Fatal(e)
			}
			path := "/api/devices/" + identity.Approval.DeviceID + "/inventory/system"
			read := func(r *http.Request) {
				h.browser(session)(r)
				r.Method = "GET"
				r.Header.Del("Origin")
				r.Header.Del("X-CSRF-Token")
			}
			code, body, _ := h.request(t, path, nil, read)
			var view enrollmentstore.SystemView
			if code != 200 || json.Unmarshal(body, &view) != nil || view.CollectionProfile != enrollmentcrypto.CollectionProfileComplete || view.Status != "fresh" || view.LastComplete.Services == nil || view.Latest.Sockets.Coverage != systeminventory.Failed {
				t.Fatal("system summary contract failed")
			}
			var metadata map[string]json.RawMessage
			if json.Unmarshal(body, &metadata) != nil || string(metadata["sequence"]) != `"1"` {
				t.Fatal("unsafe numeric sequence")
			}
			query := enrollmentstore.SystemPageRequest{Section: "services", GenerationID: snapshot.GenerationID, Limit: 100, Filter: "active"}
			seen := map[string]bool{}
			firstCursor := ""
			for pages := 0; pages < 4; pages++ {
				data, _ := json.Marshal(query)
				if pages == 0 {
					if code, _, _ := h.request(t, path+"/query", data, func(r *http.Request) { h.browser(session)(r); r.Header.Del("X-CSRF-Token") }); code != 403 {
						t.Fatal("system query bypassed CSRF")
					}
				}
				code, body, _ := h.request(t, path+"/query", data, h.browser(session))
				var response struct {
					SchemaVersion, DeviceID, CollectionProfile string
					ServerNow                                  time.Time
					enrollmentstore.SystemPageResult
				}
				if code != 200 || json.Unmarshal(body, &response) != nil || response.SchemaVersion != "tracebolt.system-inventory-page.v1" || response.DeviceID != identity.Approval.DeviceID || response.TotalRows != 257 {
					t.Fatal("system page response failed", code)
				}
				for _, item := range response.Services {
					if seen[item.Name] {
						t.Fatal("page duplicated service")
					}
					seen[item.Name] = true
				}
				if pages == 0 {
					firstCursor = response.NextCursor
				}
				if response.Exhausted {
					break
				}
				if response.NextCursor == "" {
					t.Fatal("page silently truncated")
				}
				query.Cursor = response.NextCursor
			}
			if len(seen) != 257 {
				t.Fatal("full system dataset was truncated")
			}
			query.Cursor = firstCursor
			data, _ := json.Marshal(query)
			r := httptest.NewRequest(http.MethodPost, h.origin+path+"/query", nil)
			if !plain {
				r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
			}
			r.Header.Set("Content-Type", "application/json")
			h.browser(session)(r)
			r.ContentLength = int64(len(data))
			entered := false
			r.Body = &reviewRevokingBody{reader: bytes.NewReader(data), revoke: func() { entered = true; h.f.now.Add(int64((15*time.Minute + time.Second) / time.Second)) }}
			w := httptest.NewRecorder()
			h.handler.ServeHTTP(w, r)
			if !entered || w.Code != 409 || bytes.Contains(w.Body.Bytes(), []byte("invented-")) {
				t.Fatal("delayed body retained expired page authority", w.Code)
			}
			h.auth.Logout(session.Token)
			if code, _, _ := h.request(t, path, nil, read); code != 401 {
				t.Fatal("logged out operator retained inventory")
			}
		})
	}
}
