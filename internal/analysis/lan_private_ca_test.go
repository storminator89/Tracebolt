package analysis

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func privateCAFixture(t *testing.T, isCA bool, expiry time.Time) (string, string, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(h[:]), cert, key
}

func TestPrivateLANCAActualTLSHandshake(t *testing.T) {
	now := time.Now()
	rootPEM, rootHash, ca, key := privateCAFixture(t, true, now.Add(time.Hour))
	otherPEM, otherHash, _, _ := privateCAFixture(t, true, now.Add(time.Hour))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(23), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("10.5.6.7")}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	postBody := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			postBody <- string(b)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: leafKey}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	for _, tc := range []struct {
		name, ip, pem, hash string
		pass                bool
	}{
		{"approved CA and IP", "10.5.6.7", rootPEM, rootHash, true},
		{"incorrect IP SAN", "10.5.6.8", rootPEM, rootHash, false},
		{"different CA", "10.5.6.7", otherPEM, otherHash, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := "https://" + tc.ip + ":8443"
			p, err := NewOpenAIProvider(OpenAIConfig{BaseURL: origin + "/v1", Model: "fixture", LANOrigin: origin, LANPrivateCAPEM: tc.pem, LANPrivateCASHA256: tc.hash})
			if err != nil {
				t.Fatal(err)
			}
			// The test-only dialer redirects to loopback; TLS still verifies the
			// configured IP against the leaf and the provider's exclusive pool.
			p.client.Transport.(*http.Transport).DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}
			resp, err := p.client.Get(origin + "/v1")
			if resp != nil {
				resp.Body.Close()
			}
			if (err == nil) != tc.pass {
				t.Fatalf("TLS acceptance=%v, error=%v", err == nil, err)
			}
			if tc.pass {
				cfg := OpenAIConfig{LANPrivateCAPEM: tc.pem, LANPrivateCASHA256: tc.hash}
				if text := fmt.Sprintf("%+v %#v %+v %#v", cfg, cfg, p, *p); strings.Contains(text, tc.pem) || strings.Contains(text, tc.hash) {
					t.Fatal("formatting disclosed private CA context")
				}
				_, _ = p.Generate(context.Background(), ProviderRequest{Messages: []Message{{Role: "system", Content: "fixture"}, {Role: "user", Content: "fixture"}}, Schema: []byte(`{}`)})
				body := <-postBody
				if strings.Contains(body, tc.pem) || strings.Contains(body, tc.hash) {
					t.Fatal("CA context was sent as model evidence")
				}
			}
		})
	}
}

func TestPrivateLANCAValidationAndExclusiveIPTrust(t *testing.T) {
	now := time.Now()
	pemText, hash, ca, key := privateCAFixture(t, true, now.Add(time.Hour))
	pool, err := privateLANRoots(pemText, hash, now)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("10.5.6.7")}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issued, _ := x509.ParseCertificate(der)
	if _, err = issued.Verify(x509.VerifyOptions{Roots: pool, DNSName: "10.5.6.7", CurrentTime: now}); err != nil {
		t.Fatal(err)
	}
	if _, err = issued.Verify(x509.VerifyOptions{Roots: pool, DNSName: "10.5.6.8", CurrentTime: now}); err == nil {
		t.Fatal("wrong IP accepted")
	}
	other, otherHash, _, _ := privateCAFixture(t, true, now.Add(time.Hour))
	otherPool, err := privateLANRoots(other, otherHash, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = issued.Verify(x509.VerifyOptions{Roots: otherPool, DNSName: "10.5.6.7", CurrentTime: now}); err == nil {
		t.Fatal("other CA accepted")
	}
	notCA, notCAHash, _, _ := privateCAFixture(t, false, now.Add(time.Hour))
	expired, expiredHash, _, _ := privateCAFixture(t, true, now.Add(-time.Second))
	for _, tc := range []struct{ text, hash string }{{pemText, strings.ToUpper(hash)}, {pemText, strings.Repeat("0", 64)}, {pemText + pemText, hash}, {"garbage" + pemText, hash}, {notCA, notCAHash}, {expired, expiredHash}, {pemText + strings.Repeat(" ", 4096), hash}} {
		if _, err := privateLANRoots(tc.text, tc.hash, now); err == nil {
			t.Fatal("invalid CA accepted")
		}
	}
	if _, err := NewOpenAIProvider(OpenAIConfig{BaseURL: "https://10.5.6.7:8443/v1", Model: "fixture", LANOrigin: "https://10.5.6.7:8443", LANPrivateCAPEM: pemText, LANPrivateCASHA256: hash}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewOpenAIProvider(OpenAIConfig{BaseURL: "http://127.0.0.1:11434/v1", Model: "fixture", LANPrivateCAPEM: pemText, LANPrivateCASHA256: hash}); err == nil {
		t.Fatal("CA accepted outside private LAN")
	}
}
