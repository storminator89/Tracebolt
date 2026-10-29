package analysis

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestLANPolicyExactLiteralAndNoDNS(t *testing.T) {
	for _, tc := range []struct {
		base, approved string
		ok             bool
	}{
		{"https://10.5.6.7:8443/v1", "https://10.5.6.7:8443", true},
		{"https://172.31.1.2:443/v1", "https://172.31.1.2:443", true},
		{"https://192.168.1.2:11434/v1", "https://192.168.1.2:11434", true},
		{"http://10.5.6.7:8443/v1", "http://10.5.6.7:8443", false},
		{"https://10.5.6.7/v1", "https://10.5.6.7", false},
		{"https://10.5.6.7:8443/v1", "https://10.5.6.8:8443", false},
		{"https://model.example.test:8443/v1", "https://model.example.test:8443", false},
		{"https://169.254.169.254:8443/v1", "https://169.254.169.254:8443", false},
		{"https://127.0.0.1:8443/v1", "https://127.0.0.1:8443", false},
		{"https://[fd00::1]:8443/v1", "https://[fd00::1]:8443", false},
		{"https://[::ffff:10.5.6.7]:8443/v1", "https://[::ffff:10.5.6.7]:8443", false},
	} {
		t.Run(tc.base, func(t *testing.T) {
			p, e := parseEndpointWithLAN(tc.base, nil, tc.approved)
			if (e == nil) != tc.ok {
				t.Fatal("unexpected policy result", e)
			}
			if tc.ok {
				addr, e := p.resolveTarget(context.Background(), func(context.Context, string, string) ([]netip.Addr, error) {
					t.Fatal("LAN literal unexpectedly resolved DNS")
					return nil, nil
				})
				if e != nil || addr != net.JoinHostPort(p.host, p.port) {
					t.Fatal("wrong target", e)
				}
			}
		})
	}
	if _, e := parseEndpoint("https://10.5.6.7:8443/v1", []string{"https://10.5.6.7:8443"}); e == nil {
		t.Fatal("old path widened")
	}
	if _, e := parseEndpointWithLAN("https://10.5.6.7:8443/v1", []string{"https://10.5.6.7:8443"}, "https://10.5.6.7:8443"); e == nil {
		t.Fatal("mixed trust modes accepted")
	}
}

func TestLANHTTPSUsesNormalCertificateAndNoRedirect(t *testing.T) {
	now := time.Now()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	root, e = x509.ParseCertificate(rootDER)
	if e != nil {
		t.Fatal(e)
	}
	leafPub, leafKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("10.5.6.7")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, root, leafPub, key)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(leafKey)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int32
	var redirect atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if redirect.Load() {
			http.Redirect(w, r, "https://example.invalid/", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fakeCompletion(validFindings))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	provider, e := NewOpenAIProvider(OpenAIConfig{BaseURL: "https://10.5.6.7:8443/v1", Model: "test-model", LANOrigin: "https://10.5.6.7:8443"})
	if e != nil {
		t.Fatal(e)
	}
	tr := provider.client.Transport.(*http.Transport)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	tr.TLSClientConfig.RootCAs = roots
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "10.5.6.7:8443" {
			t.Fatal("unapproved dial target")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	if _, e = provider.Generate(context.Background(), providerInput()); e != nil {
		t.Fatal("valid LAN TLS rejected", e)
	}
	if provider.Identity().Destination != "operator-approved-lan-https" {
		t.Fatal("LAN provenance missing")
	}
	redirect.Store(true)
	if _, e = provider.Generate(context.Background(), providerInput()); e == nil {
		t.Fatal("redirect followed")
	}
	if calls.Load() != 2 {
		t.Fatal("unexpected requests", calls.Load())
	}
	redirect.Store(false)
	tr.TLSClientConfig.RootCAs = x509.NewCertPool()
	if _, e = provider.Generate(context.Background(), providerInput()); e == nil {
		t.Fatal("untrusted CA accepted")
	}
	tr.TLSClientConfig.RootCAs = roots
	tr.TLSClientConfig.ServerName = "10.5.6.8"
	if _, e = provider.Generate(context.Background(), providerInput()); e == nil {
		t.Fatal("wrong certificate identity accepted")
	}
}
