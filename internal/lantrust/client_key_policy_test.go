package lantrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
	"time"
)

// Ordinary generated keys and already verified chains only. This is not an
// existing-path malformed-key/forged-request exploit test.
func TestClientVerifiedChainPolicyPreservesGeneratedKeys(t *testing.T) {
	ca := newCA(t)
	r := registry(t, ca, nil)
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("fixture key")
	}
	server := ca.leaf(t, x509.ExtKeyUsageServerAuth, nil, key)
	client := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	approve(t, r, client)
	config, e := ClientTLSConfig(client.pair, ca.pem, "127.0.0.1")
	if e != nil || config.VerifyConnection == nil || config.InsecureSkipVerify {
		t.Fatal("missing additive verification policy")
	}
	if config.VerifyConnection(tls.ConnectionState{}) == nil {
		t.Fatal("unverified empty chain accepted")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	chains, e := server.cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if e != nil {
		t.Fatal("normal fixture verification")
	}
	if config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{server.cert}, VerifiedChains: chains}) != nil {
		t.Fatal("ordinary generated chain rejected")
	}
	srv := serve(t, r, server)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: config}
	defer transport.CloseIdleConnections()
	response, e := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(srv.URL)
	if e != nil {
		t.Fatal("normal verified TLS failed")
	}
	response.Body.Close()
}
