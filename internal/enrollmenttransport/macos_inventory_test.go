package enrollmenttransport

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanstore"
	"localrmm/internal/macosinventory"
	"localrmm/internal/macosinventorywire"
)

type macInventoryTransportFixture struct {
	f       *fixture
	h       *Ingress
	cert    *x509.Certificate
	control macosinventorywire.Control
}

func macInventoryTransport(t *testing.T) macInventoryTransportFixture {
	t.Helper()
	f := newCollectionFixture(t, "tls", enrollmentcrypto.CollectionProfileMacOSInventory, true, "darwin")
	h, e := New(f.store, f.issuer.IssuerDER(), "https://manager.test")
	if e != nil {
		t.Fatal(e)
	}
	h.now = func() time.Time { return f.now }
	cert, e := x509.ParseCertificate(f.cert.DER())
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte("tracebolt.sender-binding.macos-inventory.v1\nmacos-read-inventory-v1\ntls\nhttps://manager.test\n" + f.cert.CertificateHash() + "\n" + f.snapshot.Approval.DeviceID))
	c := macosinventorywire.Control{SchemaVersion: macosinventorywire.ControlVersion, Binding: macosinventorywire.Binding{Platform: "darwin", Profile: macosinventorywire.Profile, DeviceID: f.snapshot.Approval.DeviceID, SenderBinding: hex.EncodeToString(sum[:])}, GrantID: strings.Repeat("b", 32), GrantRevision: 1, ControlRevision: 1, Enabled: true, ChangedAt: f.now}
	return macInventoryTransportFixture{f, h, cert, c}
}
func (f macInventoryTransportFixture) request(t *testing.T, path string, raw []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", "https://manager.test"+path, bytes.NewReader(raw))
	r.RequestURI = path
	r.Header.Set("Content-Type", "application/json")
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{f.cert, f.f.issuerCertificate(t)}, VerifiedChains: [][]*x509.Certificate{{f.cert, f.f.issuerCertificate(t)}}}
	return r
}
func (f macInventoryTransportFixture) call(t *testing.T, path string, raw []byte) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, f.request(t, path, raw))
	return w
}
func (f macInventoryTransportFixture) report(t *testing.T, n int) []byte {
	t.Helper()
	id, e := macosinventorywire.GenerationID(f.control.Binding, f.control.GrantID, 1, 1)
	if e != nil {
		t.Fatal(e)
	}
	request := macosinventory.Request{Consent: macosinventory.Consent{SchemaVersion: macosinventory.ConsentVersion, Scope: macosinventory.Scope, SenderBinding: f.control.Binding.SenderBinding, GrantID: f.control.GrantID, Enabled: true}, SenderBinding: f.control.Binding.SenderBinding, GenerationID: id, CollectedAt: f.f.now}
	snapshot := macosinventory.Empty(request, macosinventory.ErrUnavailable.Error())
	snapshot.Processes = macosinventory.Processes{Status: macosinventory.Status{Source: macosinventory.ProcessSource, Quality: "observed"}, Rows: []macosinventory.Process{}}
	for i := 0; i < n; i++ {
		snapshot.Processes.Rows = append(snapshot.Processes.Rows, macosinventory.Process{PID: uint32(i + 1), ParentPID: 0, AccountingName: "PrivateFixture", NameQuality: "observed"})
	}
	r, e := macosinventorywire.BuildReport(f.control, 1, snapshot)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := macosinventorywire.EncodeReport(r)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestMacOSInventoryIngressDedicatedCanonicalTLSAndLargeReport(t *testing.T) {
	f := macInventoryTransport(t)
	enable, _ := macosinventorywire.EncodeControl(f.control)
	report := f.report(t, 1000)
	if len(report) <= lanstore.MaxFrameBytes || lanstore.MaxFrameBytes != 72*1024 {
		t.Fatal("independent frame budget")
	}
	if w := f.call(t, macOSInventoryReportPath, report); w.Code != 409 {
		t.Fatal("pre-enable report", w.Code, w.Body.String())
	}
	first := f.call(t, macOSInventoryControlPath, enable)
	if first.Code != 200 {
		t.Fatal("enable", first.Code, first.Body.String())
	}
	if _, e := macosinventorywire.DecodeReceipt(first.Body.Bytes(), enable); e != nil {
		t.Fatal(e)
	}
	receipt := f.call(t, macOSInventoryReportPath, report)
	if receipt.Code != 200 {
		t.Fatal("large independent report", receipt.Code, receipt.Body.String())
	}
	if _, e := macosinventorywire.DecodeReceipt(receipt.Body.Bytes(), report); e != nil {
		t.Fatal(e)
	}
	f.f.now = f.f.now.Add(time.Second)
	retry := f.call(t, macOSInventoryReportPath, report)
	if retry.Code != 200 || !bytes.Equal(receipt.Body.Bytes(), retry.Body.Bytes()) {
		t.Fatal("receipt retry", retry.Code)
	}
	for _, path := range []string{"/v1/agent/telemetry", "/v1/windows/agent/telemetry", "/v1/macos/telemetry", "/v1/macos/inventory/unknown", "/v3/service-actions/claim"} {
		if w := f.call(t, path, report); w.Code != 404 {
			t.Fatal("cross route", path, w.Code)
		}
	}
	basic := newCollectionFixture(t, "tls", enrollmentcrypto.CollectionProfile, true, "darwin")
	other, e := New(basic.store, basic.issuer.IssuerDER(), "https://manager.test")
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	other.ServeHTTP(w, f.request(t, macOSInventoryReportPath, report))
	if w.Code != 404 {
		t.Fatal("basic became inventory", w.Code)
	}
	disabled, e := macosinventorywire.Disable(f.control, 3, f.f.now)
	if e != nil {
		t.Fatal(e)
	}
	disableRaw, _ := macosinventorywire.EncodeControl(disabled)
	if w := f.call(t, macOSInventoryControlPath, disableRaw); w.Code != 200 {
		t.Fatal("disable", w.Code, w.Body.String())
	}
	if w := f.call(t, macOSInventoryReportPath, report); w.Code != 409 || strings.Contains(w.Body.String(), "PrivateFixture") {
		t.Fatal("disabled retry", w.Code)
	}
}
func TestMacOSInventoryIngressStrictFramingAndCertificateBounds(t *testing.T) {
	f := macInventoryTransport(t)
	enable, _ := macosinventorywire.EncodeControl(f.control)
	for _, kind := range []string{"method", "query", "rawpath", "requestURI", "wrong-host", "wrong-content-type", "duplicate-content-type", "encoding", "transfer", "length", "missing-TLS", "wrong-leaf", "legacy-auth", "oversized-control", "oversized-report", "duplicate-json", "whitespace"} {
		t.Run(kind, func(t *testing.T) {
			raw := enable
			path := macOSInventoryControlPath
			switch kind {
			case "oversized-control":
				raw = bytes.Repeat([]byte("x"), macosinventorywire.MaxControlBytes+1)
			case "oversized-report":
				path = macOSInventoryReportPath
				raw = bytes.Repeat([]byte("x"), macosinventorywire.MaxReportBytes+1)
			case "duplicate-json":
				raw = bytes.Replace(raw, []byte(`"grantRevision":1`), []byte(`"grantRevision":1,"grantRevision":1`), 1)
			case "whitespace":
				raw = append(bytes.Clone(raw), '\n')
			}
			r := f.request(t, path, raw)
			switch kind {
			case "method":
				r.Method = "GET"
			case "query":
				r.URL.RawQuery = "x=private"
			case "rawpath":
				r.URL.RawPath = "/v1/macos/inventory/%63ontrol"
			case "requestURI":
				r.RequestURI = "https://manager.test" + path
			case "wrong-host":
				r.Host = "other.test"
			case "wrong-content-type":
				r.Header.Set("Content-Type", "application/json; charset=utf-8")
			case "duplicate-content-type":
				r.Header.Add("Content-Type", "application/json")
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
			case "transfer":
				r.TransferEncoding = []string{"chunked"}
			case "length":
				r.ContentLength++
			case "missing-TLS":
				r.TLS = nil
			case "wrong-leaf":
				other := newFixture(t, "tls", true)
				leaf, _ := x509.ParseCertificate(other.cert.DER())
				r.TLS.PeerCertificates[0] = leaf
			case "legacy-auth":
				r.Header.Set("X-Tracebolt-Signature", "fixture")
			}
			w := httptest.NewRecorder()
			f.h.ServeHTTP(w, r)
			if w.Code < 400 || strings.Contains(w.Body.String(), "private") {
				t.Fatal("bad request accepted/leaked", kind, w.Code)
			}
		})
	}
}
func TestMacOSInventoryIngressFinalClockAndRevocation(t *testing.T) {
	f := macInventoryTransport(t)
	enable, _ := macosinventorywire.EncodeControl(f.control)
	if w := f.call(t, macOSInventoryControlPath, enable); w.Code != 200 {
		t.Fatal(w.Code)
	}
	raw := f.report(t, 1)
	if w := f.call(t, macOSInventoryReportPath, raw); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	// Same request crosses leaf expiry on the final TLS check, after apply's
	// internal recheck. No already-committed receipt may escape that boundary.
	calls := 0
	f.h.now = func() time.Time { calls++; return f.f.now }
	if w := f.call(t, macOSInventoryReportPath, raw); w.Code != 200 {
		t.Fatal(w.Code)
	}
	allCalls := calls
	calls = 0
	f.h.now = func() time.Time {
		calls++
		if calls >= allCalls-3 {
			return f.cert.NotAfter
		}
		return f.f.now
	}
	w := f.call(t, macOSInventoryReportPath, raw)
	if w.Code == 200 || strings.Contains(w.Body.String(), "requestSha256") {
		t.Fatal("final expired receipt", w.Code, calls, allCalls)
	}
	f.h.now = func() time.Time { return f.f.now }
	f.f.revoke(t)
	if w := f.call(t, macOSInventoryReportPath, raw); w.Code != 403 {
		t.Fatal("revoked retry", w.Code)
	}
}

func TestMacOSInventoryIngressFinalExactRequestOutputEdge(t *testing.T) {
	for _, kind := range []string{"report-expiry", "terminal-disable", "revoke"} {
		t.Run(kind, func(t *testing.T) {
			f := macInventoryTransport(t)
			enable, _ := macosinventorywire.EncodeControl(f.control)
			if w := f.call(t, macOSInventoryControlPath, enable); w.Code != 200 {
				t.Fatal(w.Code)
			}
			raw := f.report(t, 1)
			if w := f.call(t, macOSInventoryReportPath, raw); w.Code != 200 {
				t.Fatal(w.Code)
			}
			calls := 0
			f.h.now = func() time.Time { calls++; return f.f.now }
			if w := f.call(t, macOSInventoryReportPath, raw); w.Code != 200 {
				t.Fatal(w.Code)
			}
			edge := calls - 3
			if edge < 1 {
				t.Fatal("missing final guard")
			}
			calls = 0
			injected := false
			f.h.now = func() time.Time {
				calls++
				if calls == edge {
					injected = true
					switch kind {
					case "report-expiry":
						f.f.now = f.control.ChangedAt.Add(macosinventorywire.Retention)
					case "terminal-disable":
						disabled, e := macosinventorywire.Disable(f.control, 1, f.f.now)
						if e != nil {
							t.Fatal(e)
						}
						body, _ := macosinventorywire.EncodeControl(disabled)
						ctx := enrollmentstore.WithMacOSInventoryIngressOrigin(context.Background(), "https://manager.test")
						if _, e = f.f.store.ApplyMacOSInventoryControl(ctx, f.f.snapshot.InvitationID, f.f.cert.CertificateHash(), body, f.f.now); e != nil {
							t.Fatal("injected disable", e)
						}
					case "revoke":
						if _, e := f.f.store.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: f.f.control(900), State: enrollmentstate.Revoked}); e != nil {
							t.Fatal("injected revoke", e)
						}
					}
				}
				return f.f.now
			}
			w := f.call(t, macOSInventoryReportPath, raw)
			if !injected || w.Code == 200 || strings.Contains(w.Body.String(), "requestSha256") {
				t.Fatal("output edge bypass", kind, w.Code, calls, edge)
			}
			if kind == "report-expiry" && w.Code != 409 {
				t.Fatal("original report expiry was masked by leaf expiry", w.Code)
			}
		})
	}
}
