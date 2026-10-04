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
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/inventorywire"
	"localrmm/internal/linuxpackages"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCompleteInventoryOperatorBodyWaitRechecksRetentionClock(t *testing.T) {
	for _, httpTest := range []bool{false, true} {
		for _, kind := range []string{"cursor", "observation"} {
			t.Run(fmt.Sprintf("%v/%s", httpTest, kind), func(t *testing.T) {
				h, _ := operationalAPIHTTPFixture(t, httpTest, enrollmentcrypto.CollectionProfileComplete)
				identity := operationalStoreActivate(t, h.f)
				session := h.session(t)
				ctx := context.Background()
				at := h.f.clock()
				generation, _ := inventorywire.GenerationID(identity.Approval.DeviceID, 1)
				rows := []linuxpackages.PackageRow{}
				for _, name := range []string{"invented-a", "invented-b"} {
					rows = append(rows, linuxpackages.PackageRow{Name: name, Version: "1", Architecture: "amd64", SourcePackage: name, SourceVersion: "1", SourceMapping: "binary-default", InstallState: "installed"})
				}
				manifest, chunks, e := fullinventory.Build(ctx, fullinventory.SourceInventory{GenerationID: generation, CollectedAt: at, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}, Rows: rows}, nil)
				if e != nil {
					t.Fatal(e)
				}
				hash, _ := fullinventory.ManifestDigest(manifest)
				binding := enrollmentstore.InventoryBinding{Sequence: 1, GenerationID: generation, ManifestHash: hash}
				if _, e = h.f.store.InventoryBegin(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, manifest, at); e != nil {
					t.Fatal(e)
				}
				for _, c := range chunks {
					if _, e = h.f.store.InventoryAppend(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, c, at); e != nil {
						t.Fatal(e)
					}
				}
				if _, e = h.f.store.InventoryFinalize(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, at); e != nil {
					t.Fatal(e)
				}
				cursor := ""
				advance := 24*time.Hour + time.Second
				if kind == "cursor" {
					page, e := h.f.store.InventoryPage(ctx, identity.Approval.DeviceID, inventoryledger.PageRequest{GenerationID: generation, Limit: 1}, at)
					if e != nil || page.NextCursor == "" {
						t.Fatal("cursor fixture", e)
					}
					cursor = page.NextCursor
					advance = 15*time.Minute + time.Second
				}
				raw, _ := json.Marshal(map[string]any{"generationId": generation, "cursor": cursor, "search": "", "limit": 1})
				r := httptest.NewRequest(http.MethodPost, h.origin+"/api/devices/"+identity.Approval.DeviceID+"/inventory/packages/query", nil)
				if !httpTest {
					r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
				}
				r.Header.Set("Content-Type", "application/json")
				h.browser(session)(r)
				r.ContentLength = int64(len(raw))
				entered := false
				r.Body = &reviewRevokingBody{reader: bytes.NewReader(raw), revoke: func() { entered = true; h.f.now.Add(int64(advance / time.Second)) }}
				w := httptest.NewRecorder()
				h.handler.ServeHTTP(w, r)
				if !entered || w.Code != 409 || bytes.Contains(w.Body.Bytes(), []byte("invented-")) {
					t.Fatal("body delay used pre-body expiry time", w.Code)
				}
			})
		}
	}
}

// Owner integration checks use only the existing synthetic enrollment fixtures,
// generated keys, invented package rows and loopback HTTP/normal verified TLS.
func TestCompleteInventoryOperatorActualTransportAndAllPages(t *testing.T) {
	for _, httpTest := range []bool{false, true} {
		t.Run(fmt.Sprint(httpTest), func(t *testing.T) {
			h, _ := operationalAPIHTTPFixture(t, httpTest, enrollmentcrypto.CollectionProfileComplete)
			identity := operationalStoreActivate(t, h.f)
			session := h.session(t)
			path := "/api/devices/" + identity.Approval.DeviceID + "/inventory/packages"
			read := func(r *http.Request) {
				h.browser(session)(r)
				r.Method = "GET"
				r.Header.Del("Origin")
				r.Header.Del("X-CSRF-Token")
			}
			code, body, _ := h.request(t, path, nil, read)
			var view struct {
				SchemaVersion, Status, CollectionProfile string
				Complete                                 *struct {
					Binding  struct{ Sequence, GenerationID, ManifestHash string }
					Manifest fullinventory.Manifest
					State    string
				}
			}
			if code != 200 || json.Unmarshal(body, &view) != nil || view.Status != "awaiting" || view.Complete != nil {
				t.Fatal("uncollected data became successful inventory")
			}
			generation, err := inventorywire.GenerationID(identity.Approval.DeviceID, 1)
			if err != nil {
				t.Fatal(err)
			}
			rows := make([]linuxpackages.PackageRow, 513)
			for i := range rows {
				name := fmt.Sprintf("package-%06d", i)
				rows[i] = linuxpackages.PackageRow{Name: name, Version: "1.0", Architecture: "amd64", SourcePackage: name, SourceVersion: "1.0", SourceMapping: "binary-default", InstallState: "installed"}
			}
			source := fullinventory.SourceInventory{GenerationID: generation, CollectedAt: h.f.clock(), Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}, Rows: rows}
			manifest, chunks, err := fullinventory.Build(context.Background(), source, nil)
			if err != nil {
				t.Fatal(err)
			}
			hash, _ := fullinventory.ManifestDigest(manifest)
			binding := enrollmentstore.InventoryBinding{Sequence: 1, GenerationID: generation, ManifestHash: hash}
			if _, err = h.f.store.InventoryBegin(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, binding, manifest, h.f.clock()); err != nil {
				t.Fatal(err)
			}
			for _, chunk := range chunks {
				if _, err = h.f.store.InventoryAppend(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, binding, chunk, h.f.clock()); err != nil {
					t.Fatal(err)
				}
			}
			code, body, _ = h.request(t, path, nil, read)
			if code != 200 || json.Unmarshal(body, &view) != nil || view.Complete != nil {
				t.Fatal("unfinalized chunks became complete")
			}
			if _, err = h.f.store.InventoryFinalize(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, binding, h.f.clock()); err != nil {
				t.Fatal(err)
			}
			code, body, _ = h.request(t, path, nil, read)
			if code != 200 || json.Unmarshal(body, &view) != nil || view.Complete == nil || view.Complete.Binding.Sequence != "1" || view.Complete.Manifest.ObservedCount != 513 {
				t.Fatal("committed complete view missing")
			}
			cursor := ""
			seen := map[string]bool{}
			for page := 0; page < 7; page++ {
				raw, _ := json.Marshal(map[string]any{"generationId": generation, "cursor": cursor, "search": "", "limit": 100})
				if page == 0 {
					if code, _, _ := h.request(t, path+"/query", raw, func(r *http.Request) { h.browser(session)(r); r.Header.Del("X-CSRF-Token") }); code != 403 {
						t.Fatal("query bypassed CSRF")
					}
				}
				code, body, _ := h.request(t, path+"/query", raw, h.browser(session))
				var result struct {
					SchemaVersion string
					TotalRows     uint64
					Items         []linuxpackages.PackageRow
					NextCursor    string
					Exhausted     bool
					Binding       struct{ Sequence, GenerationID, ManifestHash string }
				}
				if code != 200 || json.Unmarshal(body, &result) != nil || result.TotalRows != 513 || result.Binding.GenerationID != generation || result.Binding.Sequence != "1" {
					t.Fatal("page lost exact generation/count")
				}
				for _, row := range result.Items {
					if seen[row.Name] {
						t.Fatal("duplicate page row")
					}
					seen[row.Name] = true
				}
				cursor = result.NextCursor
				if result.Exhausted {
					if cursor != "" {
						t.Fatal("exhausted page has cursor")
					}
					break
				}
				if cursor == "" {
					t.Fatal("page prefix was silently final")
				}
			}
			if len(seen) != 513 {
				t.Fatal("not every supported row was accessible")
			}
			raw := []byte(`{"generationId":"` + generation + `","cursor":"","search":"","limit":100}`)
			if code, _, _ := h.request(t, path+"/query?", raw, h.browser(session)); code != 400 {
				t.Fatal("query path contract changed")
			}
			h.auth.Logout(session.Token)
			if code, _, _ := h.request(t, path+"/query", raw, h.browser(session)); code != 401 {
				t.Fatal("expired operator session admitted page")
			}
		})
	}
}
