package lantrust

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test credentials are generated ephemerally in memory. No provisioned or
// committed keys, existing user files, system roots, or non-loopback binds.
type fixtureCA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pem  []byte
}
type fixtureLeaf struct {
	cert *x509.Certificate
	pair tls.Certificate
	pem  []byte
}

func newKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func newCA(t *testing.T) fixtureCA {
	t.Helper()
	key := newKey(t)
	now := time.Now().UTC()
	tmpl := &x509.Certificate{SerialNumber: serial(t), Subject: pkix.Name{CommonName: "ephemeral test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return fixtureCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})}
}
func (ca fixtureCA) leaf(t *testing.T, role x509.ExtKeyUsage, edit func(*x509.Certificate), key crypto.Signer) fixtureLeaf {
	t.Helper()
	if key == nil {
		key = newKey(t)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{SerialNumber: serial(t), Subject: pkix.Name{CommonName: "claimed-administrator-id"}, DNSNames: []string{"claimed-agent-id", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{role}}
	if edit != nil {
		edit(tmpl)
	}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return fixtureLeaf{cert: cert, pair: tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key}, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})}
}
func registry(t *testing.T, ca fixtureCA, store Store) *Registry {
	t.Helper()
	if store == nil {
		store = NewMemoryStore()
	}
	r, err := NewRegistry(context.Background(), ca.pem, store)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func approve(t *testing.T, r *Registry, leaf fixtureLeaf) Agent {
	t.Helper()
	a, err := r.Approve(context.Background(), leaf.pem, "My endpoint")
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func requestWithCert(leaf fixtureLeaf) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://localhost/api/agent/telemetry", nil)
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf.cert}, VerifiedChains: [][]*x509.Certificate{{leaf.cert}}}
	return r
}
func serve(t *testing.T, r *Registry, server fixtureLeaf) *httptest.Server {
	t.Helper()
	cfg, err := r.TLSConfig(server.pair)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(r.Middleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a, ok := FromContext(req.Context())
		if !ok {
			t.Error("handler missing authenticated agent")
			http.Error(w, "missing", 500)
			return
		}
		io.Copy(io.Discard, req.Body)
		fmt.Fprint(w, a.ID)
	})))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = cfg
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}
func client(t *testing.T, ca fixtureCA, leaf fixtureLeaf) *http.Client {
	t.Helper()
	cfg, err := ClientTLSConfig(leaf.pair, ca.pem, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: cfg, Proxy: nil, MaxConnsPerHost: 1}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func get(t *testing.T, c *http.Client, url string) (int, string, bool) {
	t.Helper()
	reused := false
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(raw), reused
}

func TestApprovedAgentUsesOpaqueIDAndPublicOnlyDescriptor(t *testing.T) {
	ca := newCA(t)
	leaf := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	r := registry(t, ca, nil)
	a := approve(t, r, leaf)
	if !strings.HasPrefix(a.ID, "agent_") || len(a.ID) != 38 || a.ID == leaf.cert.Subject.CommonName || a.ID == leaf.cert.DNSNames[0] {
		t.Fatalf("bad identity: %q", a.ID)
	}
	if a.FingerprintSHA256 != Fingerprint(leaf.cert) {
		t.Fatal("fingerprint mismatch")
	}
	got, err := r.Authenticate(requestWithCert(leaf))
	if err != nil || got.ID != a.ID {
		t.Fatalf("auth=%+v %v", got, err)
	}
	body, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err = json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 7 {
		t.Fatalf("descriptor fields=%v", fields)
	}
	for _, secret := range []string{"PRIVATE KEY", "BEGIN CERTIFICATE", leaf.cert.Subject.CommonName, "claimed-agent-id"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatalf("descriptor leaked %q", secret)
		}
	}
	copy := r.List()
	copy[0].Label = "changed"
	if r.List()[0].Label != a.Label {
		t.Fatal("List exposed mutable state")
	}
}
func TestApprovalRejectsInvalidCertsAndLabels(t *testing.T) {
	ca := newCA(t)
	other := newCA(t)
	r := registry(t, ca, nil)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]fixtureLeaf{
		"wrong CA":                  other.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil),
		"expired":                   ca.leaf(t, x509.ExtKeyUsageClientAuth, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }, nil),
		"not yet valid":             ca.leaf(t, x509.ExtKeyUsageClientAuth, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }, nil),
		"server EKU":                ca.leaf(t, x509.ExtKeyUsageServerAuth, nil, nil),
		"missing EKU":               ca.leaf(t, x509.ExtKeyUsageClientAuth, func(c *x509.Certificate) { c.ExtKeyUsage = nil }, nil),
		"any EKU":                   ca.leaf(t, x509.ExtKeyUsageAny, nil, nil),
		"dual role":                 ca.leaf(t, x509.ExtKeyUsageClientAuth, func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) }, nil),
		"missing digital signature": ca.leaf(t, x509.ExtKeyUsageClientAuth, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }, nil),
		"CA leaf":                   ca.leaf(t, x509.ExtKeyUsageClientAuth, func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }, nil),
		"weak key":                  ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, weak),
	}
	for name, leaf := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := r.Approve(context.Background(), leaf.pem, "endpoint"); !errors.Is(err, ErrCertificate) {
				t.Fatalf("expected invalid cert; got %v", err)
			}
		})
	}
	good := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	for _, label := range []string{"", " ", " leading", "trailing ", "new\nline", strings.Repeat("x", MaxLabelBytes+1), string([]byte{0xff})} {
		if _, err := r.Approve(context.Background(), good.pem, label); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("invalid label accepted: %q %v", label, err)
		}
	}
	if len(r.List()) != 0 {
		t.Fatal("invalid approval changed registry")
	}
}
func TestCertificatePEMRejectsPrivateKeysGarbageAndAmbiguity(t *testing.T) {
	ca := newCA(t)
	leaf := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	r := registry(t, ca, nil)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cases := [][]byte{nil, []byte("garbage"), append([]byte("garbage\n"), leaf.pem...), append(append([]byte{}, leaf.pem...), []byte("trailing garbage")...), append(append([]byte{}, leaf.pem...), keyPEM...), append(append([]byte{}, keyPEM...), leaf.pem...), append(append([]byte{}, leaf.pem...), leaf.pem...), []byte("-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----"), append([]byte("-----BEGIN CERTIFICATE-----\nbroken\n"), leaf.pem...), bytes.Repeat([]byte("x"), MaxCertificatePEMBytes+1)}
	for i, raw := range cases {
		if _, err := r.Approve(context.Background(), raw, "endpoint"); !errors.Is(err, ErrCertificate) {
			t.Errorf("case %d: got %v", i, err)
		}
	}
	if _, err := r.Approve(context.Background(), append(append([]byte{}, leaf.pem...), ca.pem...), "endpoint"); err != nil {
		t.Fatalf("valid leaf and chain rejected: %v", err)
	}
}
func TestConfigurationFailsClosedWithoutExplicitPublicCA(t *testing.T) {
	ca := newCA(t)
	leaf := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	for _, raw := range [][]byte{nil, {}, []byte("invalid"), leaf.pem, append(append([]byte{}, ca.pem...), ca.pem...)} {
		if _, err := NewRegistry(context.Background(), raw, NewMemoryStore()); !errors.Is(err, ErrConfiguration) {
			t.Errorf("CA accepted, err=%v", err)
		}
	}
	if _, err := NewRegistry(context.Background(), ca.pem, nil); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("nil Store accepted: %v", err)
	}
}
func TestRevokePersistentAndCannotReapprove(t *testing.T) {
	ca := newCA(t)
	leaf := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	store := NewMemoryStore()
	r := registry(t, ca, store)
	a := approve(t, r, leaf)
	r = registry(t, ca, store)
	if _, err := r.Authenticate(requestWithCert(leaf)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Approve(context.Background(), leaf.pem, "new label"); !errors.Is(err, ErrAlreadyApproved) {
		t.Fatalf("duplicate approval: %v", err)
	}
	if err := r.Revoke(context.Background(), a.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.Revoke(context.Background(), a.ID); err != nil {
		t.Fatal(err)
	}
	r = registry(t, ca, store)
	if _, err := r.Authenticate(requestWithCert(leaf)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revocation lost: %v", err)
	}
	if _, err := r.Approve(context.Background(), leaf.pem, "endpoint"); !errors.Is(err, ErrAlreadyApproved) {
		t.Fatalf("revocation undone: %v", err)
	}
	newLeaf := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, leaf.pair.PrivateKey.(crypto.Signer))
	renewed := approve(t, r, newLeaf)
	if renewed.ID == a.ID || renewed.FingerprintSHA256 == a.FingerprintSHA256 {
		t.Fatal("renewal reused old identity")
	}
}
func TestTLSApprovedUnapprovedRevokedReusedConnectionAndClaimedID(t *testing.T) {
	ca := newCA(t)
	server := ca.leaf(t, x509.ExtKeyUsageServerAuth, nil, nil)
	leaf := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	r := registry(t, ca, nil)
	a := approve(t, r, leaf)
	s := serve(t, r, server)
	c := client(t, ca, leaf)
	status, body, _ := get(t, c, s.URL)
	if status != 200 || body != a.ID {
		t.Fatalf("valid agent: %d %q", status, body)
	}
	req, err := http.NewRequest(http.MethodPost, s.URL+"?deviceId=victim", strings.NewReader(`{"deviceId":"victim","id":"victim"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Agent-ID", "victim")
	req.Header.Set("X-Forwarded-Client-Cert", "victim")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || string(raw) != a.ID {
		t.Fatalf("claimed identity changed authenticated context: %d %q", resp.StatusCode, raw)
	}
	unapproved := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	status, _, _ = get(t, client(t, ca, unapproved), s.URL)
	if status != 401 {
		t.Fatalf("unapproved accepted: %d", status)
	}
	if err := r.Revoke(context.Background(), a.ID); err != nil {
		t.Fatal(err)
	}
	status, _, reused := get(t, c, s.URL)
	if !reused {
		t.Fatal("revocation test did not reuse existing TLS connection")
	}
	if status != 401 {
		t.Fatalf("revoked reused connection accepted: %d", status)
	}
}
func TestTLSRejectsUntrustedExpiredWrongRoleAndNoCertificate(t *testing.T) {
	ca := newCA(t)
	other := newCA(t)
	r := registry(t, ca, nil)
	server := ca.leaf(t, x509.ExtKeyUsageServerAuth, nil, nil)
	s := serve(t, r, server)
	for name, leaf := range map[string]fixtureLeaf{"wrong CA": other.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil), "expired": ca.leaf(t, x509.ExtKeyUsageClientAuth, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }, nil), "future": ca.leaf(t, x509.ExtKeyUsageClientAuth, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }, nil), "wrong EKU": ca.leaf(t, x509.ExtKeyUsageServerAuth, nil, nil), "no cert": {}} {
		t.Run(name, func(t *testing.T) {
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(ca.pem)
			cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"}
			if len(leaf.pair.Certificate) > 0 {
				cfg.Certificates = []tls.Certificate{leaf.pair}
			}
			tr := &http.Transport{TLSClientConfig: cfg}
			defer tr.CloseIdleConnections()
			c := &http.Client{Transport: tr, Timeout: 3 * time.Second}
			resp, err := c.Get(s.URL)
			if err == nil {
				resp.Body.Close()
				t.Fatalf("invalid client completed TLS: %d", resp.StatusCode)
			}
		})
	}
}
func TestExpiryRecheckedOnReusedConnection(t *testing.T) {
	ca := newCA(t)
	r := registry(t, ca, nil)
	leaf := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	approve(t, r, leaf)
	s := serve(t, r, ca.leaf(t, x509.ExtKeyUsageServerAuth, nil, nil))
	c := client(t, ca, leaf)
	status, _, _ := get(t, c, s.URL)
	if status != 200 {
		t.Fatal(status)
	}
	// Requests above have completed. No parallel access to the deterministic clock.
	r.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	status, _, reused := get(t, c, s.URL)
	if !reused || status != 401 {
		t.Fatalf("expired reused cert: status=%d reused=%v", status, reused)
	}
}
func TestConcurrentAuthenticationAndRevocation(t *testing.T) {
	ca := newCA(t)
	r := registry(t, ca, nil)
	leaf := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	a := approve(t, r, leaf)
	req := requestWithCert(leaf)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for j := 0; j < 30; j++ {
				_, err := r.Authenticate(req)
				if err != nil && !errors.Is(err, ErrUnauthorized) {
					t.Errorf("auth: %v", err)
				}
			}
		}()
	}
	close(start)
	if err := r.Revoke(context.Background(), a.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		if _, err := r.Authenticate(req); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("authentication after revoke acknowledgment: %v", err)
		}
	}
	workers.Wait()
}
