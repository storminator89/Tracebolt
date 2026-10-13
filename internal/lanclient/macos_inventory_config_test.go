package lanclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	inventory "localrmm/internal/macosinventory"
	sender "localrmm/internal/macosinventorysender"
	wire "localrmm/internal/macosinventorywire"
	"net/http"
	"strings"
	"testing"
	"time"
)

func macOSInventoryConfigFixture() MacOSInventoryConfig {
	return MacOSInventoryConfig{Config: Config{SchemaVersion: MacOSInventoryConfigVersion, Profile: "tls", CollectionProfile: inventory.Scope, ManagerOrigin: "https://fixture.invalid", AgentID: "agent_" + strings.Repeat("a", 32), CertificateFile: "/private/endpoint/agent-cert.pem", PrivateKeyFile: "/private/endpoint/agent-key.pem", ServerCAFile: "/private/endpoint/server-ca.pem", StateDirectory: "/private/endpoint/telemetry"}, ConsentFile: "/private/endpoint/" + MacOSInventoryConsentName, OriginalEnableFile: "/private/endpoint/" + MacOSInventoryEnableName}
}
func TestMacOSInventoryConfigIsSeparateStrictFreshDomain(t *testing.T) {
	path := "/private/endpoint/agent.json"
	c := macOSInventoryConfigFixture()
	raw, _ := json.MarshalIndent(c, "", "  ")
	if _, e := ParseMacOSInventoryConfig(raw, path); e != nil {
		t.Fatal(e)
	}
	if c.Config.Validate() == nil || c.Config.platformAllowed("darwin") {
		t.Fatal("generic sender profile widened")
	}
	for _, mutate := range []func(*MacOSInventoryConfig){func(c *MacOSInventoryConfig) { c.SchemaVersion = GuidedConfigVersion }, func(c *MacOSInventoryConfig) { c.CollectionProfile = "basic-readonly-v1" }, func(c *MacOSInventoryConfig) { c.Profile = "http-test" }, func(c *MacOSInventoryConfig) { c.ConsentFile = c.CertificateFile }, func(c *MacOSInventoryConfig) { c.OriginalEnableFile = "/private/other/enable.json" }, func(c *MacOSInventoryConfig) { c.RenewalManifestFile = "/private/other/renewal-manifest.json" }, func(c *MacOSInventoryConfig) { c.StateDirectory = "/private/other/telemetry" }, func(c *MacOSInventoryConfig) { c.InsecureHTTPAcknowledged = true }} {
		next := c
		mutate(&next)
		raw, _ := json.MarshalIndent(next, "", "  ")
		if _, e := ParseMacOSInventoryConfig(raw, path); e == nil {
			t.Fatal("mixed authority accepted")
		}
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), ' '), bytes.Replace(raw, []byte(`"schemaVersion":`), []byte(`"SCHEMAVersion":`), 1), bytes.Replace(raw, []byte(`"profile": "tls",`), []byte(`"profile": "tls", "profile": "tls",`), 1)} {
		if _, e := ParseMacOSInventoryConfig(bad, path); e == nil {
			t.Fatal("noncanonical config accepted")
		}
	}
}

type macOSInventoryRoundTrip func(*http.Request) (*http.Response, error)

func (f macOSInventoryRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func macOSInventoryControlFixture(t *testing.T) []byte {
	t.Helper()
	raw, e := wire.EncodeControl(wire.Control{SchemaVersion: wire.ControlVersion, Binding: wire.Binding{Platform: "darwin", Profile: inventory.Scope, DeviceID: "agent_" + strings.Repeat("a", 32), SenderBinding: strings.Repeat("b", 64)}, GrantID: strings.Repeat("c", 32), GrantRevision: 1, ControlRevision: 1, Enabled: true, ChangedAt: time.Now().UTC().Add(-time.Second)})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestMacOSInventoryExchangeFixedFramingAndNoImplicitRetry(t *testing.T) {
	body := macOSInventoryControlFixture(t)
	receipt, e := wire.ReceiptFor(body, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := wire.EncodeReceipt(receipt, body)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	x := &MacOSInventoryExchange{origin: "https://fixture.invalid", client: &http.Client{Transport: macOSInventoryRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		got, _ := io.ReadAll(r.Body)
		if r.URL.String() != "https://fixture.invalid"+sender.ControlPath || r.Method != "POST" || r.ContentLength != int64(len(body)) || !bytes.Equal(got, body) || r.GetBody != nil || r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("unbound transport")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw)), TLS: &tls.ConnectionState{Version: tls.VersionTLS13, VerifiedChains: [][]*x509.Certificate{{{}}}}}, nil
	})}}
	got, e := x.Exchange(context.Background(), sender.ControlPath, body)
	if e != nil || !bytes.Equal(got, raw) || calls != 1 {
		t.Fatal("exact request failed", e)
	}
	for _, path := range []string{"/v1/agent/telemetry", sender.ControlPath + "?x=1", "https://other.invalid"} {
		if _, e := x.Exchange(context.Background(), path, body); e == nil {
			t.Fatal("path escaped")
		}
	}
	if calls != 1 {
		t.Fatal("rejected path invoked transport")
	}
	x.client.Transport = macOSInventoryRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("private transport text")
	})
	_, e = x.Exchange(context.Background(), sender.ControlPath, body)
	if e == nil || strings.Contains(e.Error(), "private") || calls != 2 {
		t.Fatal("transport retry or leakage")
	}
}
func TestMacOSInventoryExchangeCancellationAndReceiptBounds(t *testing.T) {
	body := macOSInventoryControlFixture(t)
	for _, bad := range []string{"oversize", "encoding", "no-tls", "redirect", "wrong-receipt"} {
		calls := 0
		x := &MacOSInventoryExchange{origin: "https://fixture.invalid", client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: macOSInventoryRoundTrip(func(r *http.Request) (*http.Response, error) {
			calls++
			res := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`)), TLS: &tls.ConnectionState{Version: tls.VersionTLS13, VerifiedChains: [][]*x509.Certificate{{{}}}}}
			switch bad {
			case "oversize":
				res.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", wire.MaxReceiptBytes+1)))
			case "encoding":
				res.Header.Set("Content-Encoding", "gzip")
			case "no-tls":
				res.TLS = nil
			case "redirect":
				res.StatusCode = 302
				res.Header.Set("Location", "https://other.invalid")
			}
			return res, nil
		})}}
		if _, e := x.Exchange(context.Background(), sender.ControlPath, body); e == nil || calls != 1 {
			t.Fatal("invalid response admitted", bad)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	x := &MacOSInventoryExchange{origin: "https://fixture.invalid", client: &http.Client{Transport: macOSInventoryRoundTrip(func(r *http.Request) (*http.Response, error) {
		cancel()
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}}
	if _, e := x.Exchange(ctx, sender.ControlPath, body); e == nil {
		t.Fatal("cancelled request confirmed")
	}
}
