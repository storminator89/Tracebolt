package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanstore"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestMacOSClosedIngressPlatformCredentialAndRouteFences(t *testing.T) {
	f := newCollectionFixture(t, "tls", enrollmentcrypto.CollectionProfile, true, "darwin")
	h, err := New(f.store, f.issuer.IssuerDER(), "https://manager.test")
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return f.now }
	var value lanstore.Frame
	if json.Unmarshal(frame(t, 1, f.now), &value) != nil {
		t.Fatal("fixture")
	}
	value.Observation.Platform = "macos"
	value.Observation.Observation.Platform = "macos"
	value.Observation.Observation.ID = "local-macos"
	value.Observation.Observation.Name = "Local macOS"
	value.Observation.Observation.Source = "local"
	value.Observation.Observation.Site = "Local machine"
	raw, _ := json.Marshal(value)
	if _, err := lanstore.ValidateFrame(raw, f.now); err != nil {
		t.Fatal("Mac fixture frame", err)
	}
	cert, err := x509.ParseCertificate(f.cert.DER())
	if err != nil {
		t.Fatal(err)
	}
	call := func(path string, body []byte, tlsState bool) int {
		r := httptest.NewRequest("POST", "https://manager.test"+path, bytes.NewReader(body))
		r.RequestURI = path
		r.Header.Set("Content-Type", "application/json")
		if tlsState {
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{cert, f.issuerCertificate(t)}, VerifiedChains: [][]*x509.Certificate{{cert, f.issuerCertificate(t)}}}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if got := call("/v1/macos/telemetry", raw, false); got != 403 {
		t.Fatal("missing TLS", got)
	}
	for _, path := range []string{"/v1/agent/telemetry", "/v1/windows/agent/telemetry", "/v3/service-actions/claim", "/v1/macos/unknown"} {
		if got := call(path, raw, true); got != 404 {
			t.Fatal("foreign route", path, got)
		}
	}
	if got := call("/v1/macos/telemetry", frame(t, 1, f.now), true); got < 400 {
		t.Fatal("Linux frame accepted")
	}
	if got := call("/v1/macos/telemetry", raw, true); got != 200 {
		t.Fatal("Mac frame rejected", got)
	}
	history, err := f.store.ResourceHistory(context.Background(), f.snapshot.Approval.DeviceID, f.now)
	if err != nil || len(history.Points) != 1 || history.Points[0].Sequence != "1" {
		t.Fatal("Mac resource history unavailable", err)
	}
	rows, err := f.store.LatestObservations(context.Background())
	if err != nil || len(rows) != 1 || rows[0].Device.Platform != "macos" {
		t.Fatal("Mac projection", err)
	}
	f.store.Close()
	f.store, err = enrollmentstore.Open(f.path, f.config, f.issuer.IssuerDER())
	if err != nil {
		t.Fatal(err)
	}
	h, err = New(f.store, f.issuer.IssuerDER(), "https://manager.test")
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return f.now }
	if got := call("/v1/macos/telemetry", raw, true); got != 200 {
		t.Fatal("exact retry after reopen", got)
	}
	// The exact Mac leaf still cannot authorize a different store under this issuer.
	primaryConfig := f.config
	primaryConfig.Platform = ""
	primary, err := enrollmentstore.Open(filepath.Join(t.TempDir(), "private", "primary.db"), primaryConfig, f.issuer.IssuerDER())
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	h, err = New(primary, f.issuer.IssuerDER(), "https://manager.test")
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return f.now }
	if got := call("/v1/agent/telemetry", raw, true); got != 403 {
		t.Fatal("same issuer crossed identity stores", got)
	}
	h, err = New(f.store, f.issuer.IssuerDER(), "https://manager.test")
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return f.now }
	// A valid chain does not grant the independently activated Linux identity access.
	foreign := newFixture(t, "tls", true)
	cert, _ = x509.ParseCertificate(foreign.cert.DER())
	if got := call("/v1/macos/telemetry", raw, true); got != 403 {
		t.Fatal("foreign store identity accepted", got)
	}
}
func (f *fixture) issuerCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	c, e := x509.ParseCertificate(f.issuer.IssuerDER())
	if e != nil {
		t.Fatal(e)
	}
	return c
}
