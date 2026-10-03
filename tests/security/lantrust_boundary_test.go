package security_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"localrmm/internal/lantrust"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type reviewCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func makeReviewCA(t *testing.T) reviewCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Ephemeral test CA; never a user identity"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return reviewCA{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})}
}
func makeReviewLeaf(t *testing.T, ca reviewCA, usages []x509.ExtKeyUsage, expiry time.Time) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	if expiry.IsZero() {
		expiry = time.Now().Add(10 * time.Minute)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "forged-device-name-must-not-be-identity"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: expiry, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, DNSNames: []string{"operator.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	raw, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key, Leaf: leaf}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}
func reviewMTLSServer(t *testing.T, r *lantrust.Registry, server tls.Certificate) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	config, err := r.TLSConfig(server)
	if err != nil {
		t.Fatal(err)
	}
	if config.InsecureSkipVerify || config.MinVersion != tls.VersionTLS13 || config.ClientAuth != tls.RequireAndVerifyClientCert || config.ClientCAs == nil || !config.SessionTicketsDisabled || config.VerifyConnection == nil {
		t.Fatal("unsafe mTLS server configuration")
	}
	connections := &atomic.Int64{}
	s := httptest.NewUnstartedServer(r.Middleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		agent, ok := lantrust.FromContext(req.Context())
		if !ok {
			t.Error("no registry identity")
		}
		_, _ = io.WriteString(w, agent.ID)
	})))
	s.TLS = config
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s, connections
}
func reviewMTLSClient(t *testing.T, client tls.Certificate, ca []byte, name string) *http.Client {
	t.Helper()
	config, err := lantrust.ClientTLSConfig(client, ca, name)
	if err != nil {
		t.Fatal(err)
	}
	if config.InsecureSkipVerify || config.RootCAs == nil || config.ServerName != name {
		t.Fatal("unsafe client trust configuration")
	}
	transport := &http.Transport{TLSClientConfig: config, MaxConnsPerHost: 1}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}
func reviewGET(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Agent-ID", "forged-agent-from-header")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(raw)
}

func TestLANTrustStrictPublicApproval(t *testing.T) {
	ca := makeReviewCA(t)
	if _, err := lantrust.NewRegistry(context.Background(), nil, lantrust.NewMemoryStore()); err == nil {
		t.Fatal("missing explicit CA accepted")
	}
	r, err := lantrust.NewRegistry(context.Background(), ca.pem, lantrust.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	_, both := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, time.Time{})
	if _, err = r.Approve(context.Background(), both, "test agent"); err == nil {
		t.Fatal("dual-purpose certificate approved")
	}
	_, clientPEM := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Time{})
	contaminated := append(append([]byte{}, clientPEM...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a real private key")})...)
	if _, err = r.Approve(context.Background(), contaminated, "test agent"); err == nil {
		t.Fatal("private-key PEM accepted at public-only boundary")
	}
	otherCA := makeReviewCA(t)
	_, foreign := makeReviewLeaf(t, otherCA, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Time{})
	if _, err = r.Approve(context.Background(), foreign, "test agent"); err == nil {
		t.Fatal("foreign trust chain approved")
	}
}

func TestLANTrustRevokesAlreadyOpenConnection(t *testing.T) {
	ca := makeReviewCA(t)
	store := lantrust.NewMemoryStore()
	r, err := lantrust.NewRegistry(context.Background(), ca.pem, store)
	if err != nil {
		t.Fatal(err)
	}
	leaf, public := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Time{})
	agent, err := r.Approve(context.Background(), public, "Test operator-selected alias")
	if err != nil {
		t.Fatal(err)
	}
	server, _ := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Time{})
	s, connections := reviewMTLSServer(t, r, server)
	client := reviewMTLSClient(t, leaf, ca.pem, "127.0.0.1")
	code, body := reviewGET(t, client, s.URL)
	if code != 200 || body != agent.ID {
		t.Fatal("certificate did not map to server-assigned identity")
	}
	if code, _ = reviewGET(t, client, s.URL); code != 200 {
		t.Fatal("second approved request failed")
	}
	if connections.Load() != 1 {
		t.Fatal("fixture did not establish connection reuse")
	}
	if err = r.Revoke(context.Background(), agent.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ = reviewGET(t, client, s.URL); code != 401 {
		t.Fatal("revoked certificate remained authorized")
	}
	if connections.Load() != 1 {
		t.Fatal("revocation proof unexpectedly used a new connection")
	}
	if _, err = r.Approve(context.Background(), public, "New misleading alias"); !errors.Is(err, lantrust.ErrAlreadyApproved) {
		t.Fatal("revoked leaf was reapproved")
	}
	restarted, err := lantrust.NewRegistry(context.Background(), ca.pem, store)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := reviewMTLSServer(t, restarted, server)
	if code, _ = reviewGET(t, client, second.URL); code != 401 {
		t.Fatal("reload lost revocation tombstone")
	}
}

func TestLANTrustChecksServerNameAndMissingCertificate(t *testing.T) {
	ca := makeReviewCA(t)
	r, err := lantrust.NewRegistry(context.Background(), ca.pem, lantrust.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	leaf, public := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Time{})
	if _, err = r.Approve(context.Background(), public, "test"); err != nil {
		t.Fatal(err)
	}
	server, _ := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Time{})
	s, _ := reviewMTLSServer(t, r, server)
	wrong := reviewMTLSClient(t, leaf, ca.pem, "wrong-server.test")
	if response, err := wrong.Get(s.URL); err == nil {
		response.Body.Close()
		t.Fatal("wrong server SAN accepted")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.pem) {
		t.Fatal("test root")
	}
	bareTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer bareTransport.CloseIdleConnections()
	noCertificate := &http.Client{Transport: bareTransport, Timeout: 2 * time.Second}
	if response, err := noCertificate.Get(s.URL); err == nil {
		response.Body.Close()
		t.Fatal("mTLS accepted absent client certificate")
	}
}
