package lantrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type failingStore struct {
	MemoryStore
	loadErr, saveErr bool
}

func (s *failingStore) Load(ctx context.Context) ([]Agent, error) {
	if s.loadErr {
		return nil, errors.New("sensitive backing-store diagnostic")
	}
	return s.MemoryStore.Load(ctx)
}
func (s *failingStore) Save(ctx context.Context, a Agent) error {
	if s.saveErr {
		return errors.New("sensitive backing-store diagnostic")
	}
	return s.MemoryStore.Save(ctx, a)
}

type loadedStore struct{ rows []Agent }

func (s loadedStore) Load(context.Context) ([]Agent, error) { return s.rows, nil }
func (s loadedStore) Save(context.Context, Agent) error     { return nil }
func TestStoreFailureCannotActivateApprovalOrAcknowledgeRevocation(t *testing.T) {
	ca := newCA(t)
	leaf := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	store := &failingStore{MemoryStore: *NewMemoryStore(), loadErr: true}
	if _, err := NewRegistry(context.Background(), ca.pem, store); !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatal(err)
	}
	store.loadErr = false
	store.saveErr = true
	r := registry(t, ca, store)
	if _, err := r.Approve(context.Background(), leaf.pem, "endpoint"); !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatalf("approval error=%v", err)
	}
	if len(r.List()) != 0 {
		t.Fatal("failed approval activated")
	}
	if _, err := r.Authenticate(requestWithCert(leaf)); !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatalf("store failure did not fail closed: %v", err)
	}
	store.saveErr = false
	r = registry(t, ca, store)
	a := approve(t, r, leaf)
	store.saveErr = true
	if err := r.Revoke(context.Background(), a.ID); !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatalf("false successful revoke: %v", err)
	}
	if _, err := r.Authenticate(requestWithCert(leaf)); !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatalf("failed revoke still permits telemetry: %v", err)
	}
	h := r.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("failed registry called handler") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithCert(leaf))
	if w.Code != 503 || strings.Contains(w.Body.String(), "sensitive") {
		t.Fatalf("bad storage failure response: %d %q", w.Code, w.Body.String())
	}
}
func TestPersistedRegistryRejectsInvalidOrAmbiguousMetadata(t *testing.T) {
	ca := newCA(t)
	r := registry(t, ca, nil)
	good := approve(t, r, ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil))
	for name, edit := range map[string]func(*Agent){"id": func(a *Agent) { a.ID = "attacker-claimed-id" }, "fingerprint": func(a *Agent) { a.FingerprintSHA256 = "invalid" }, "label": func(a *Agent) { a.Label = "\n" }, "approval before certificate": func(a *Agent) { a.ApprovedAt = a.NotBefore.Add(-time.Second) }, "approval after expiry": func(a *Agent) { a.ApprovedAt = a.ExpiresAt }, "revoke before approval": func(a *Agent) { a.RevokedAt = a.ApprovedAt.Add(-time.Second) }} {
		t.Run(name, func(t *testing.T) {
			bad := good
			edit(&bad)
			if _, err := NewRegistry(context.Background(), ca.pem, loadedStore{[]Agent{bad}}); !errors.Is(err, ErrConfiguration) {
				t.Fatal(err)
			}
		})
	}
	if _, err := NewRegistry(context.Background(), ca.pem, loadedStore{[]Agent{good, good}}); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("duplicate ID: %v", err)
	}
	other := good
	other.ID = "agent_00000000000000000000000000000000"
	if _, err := NewRegistry(context.Background(), ca.pem, loadedStore{[]Agent{good, other}}); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("duplicate fingerprint: %v", err)
	}
	if _, err := NewRegistry(context.Background(), ca.pem, loadedStore{make([]Agent, MaxAgents+1)}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity: %v", err)
	}
}
func TestTLSConfigurationAndServerNameVerification(t *testing.T) {
	ca := newCA(t)
	r := registry(t, ca, nil)
	server := ca.leaf(t, x509.ExtKeyUsageServerAuth, nil, nil)
	leaf := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	approve(t, r, leaf)
	cfg, err := r.TLSConfig(server.pair)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.ClientCAs == nil || !cfg.SessionTicketsDisabled || cfg.VerifyConnection == nil || cfg.InsecureSkipVerify || cfg.KeyLogWriter != nil {
		t.Fatal("unsafe server TLS configuration")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("empty verified chain accepted")
	}
	cc, err := ClientTLSConfig(leaf.pair, ca.pem, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if cc.MinVersion != tls.VersionTLS13 || cc.RootCAs == nil || cc.InsecureSkipVerify || cc.ServerName != "127.0.0.1" || cc.KeyLogWriter != nil {
		t.Fatal("unsafe client TLS configuration")
	}
	for _, name := range []string{"", "https://manager.local", "manager.local:8443", "*.local", " leading.local", "trailing.local ", "bad..local", "-bad.local", "127.0.0.1%lo", "[::1]"} {
		if _, err := ClientTLSConfig(leaf.pair, ca.pem, name); !errors.Is(err, ErrConfiguration) {
			t.Errorf("name %q accepted: %v", name, err)
		}
	}
	s := serve(t, r, server)
	for name, mutate := range map[string]func(*tls.Config){"wrong SAN": func(c *tls.Config) { c.ServerName = "another.local" }, "wrong server CA": func(c *tls.Config) {
		other := newCA(t)
		c.RootCAs = x509.NewCertPool()
		c.RootCAs.AppendCertsFromPEM(other.pem)
	}, "TLS 1.2": func(c *tls.Config) { c.MinVersion = tls.VersionTLS12; c.MaxVersion = tls.VersionTLS12 }} {
		t.Run(name, func(t *testing.T) {
			conf := cc.Clone()
			mutate(conf)
			tr := &http.Transport{TLSClientConfig: conf}
			defer tr.CloseIdleConnections()
			c := &http.Client{Transport: tr, Timeout: 3 * time.Second}
			resp, err := c.Get(s.URL)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				t.Fatal("server verification unexpectedly succeeded")
			}
		})
	}
}
func TestTLSConfigRejectsInvalidServerMaterial(t *testing.T) {
	ca := newCA(t)
	r := registry(t, ca, nil)
	server := ca.leaf(t, x509.ExtKeyUsageServerAuth, nil, nil)
	wrongKey := server.pair
	wrongKey.PrivateKey = newKey(t)
	nilKey := server.pair
	nilKey.PrivateKey = (*ecdsa.PrivateKey)(nil)
	for name, pair := range map[string]tls.Certificate{"empty": {}, "wrong key": wrongKey, "typed nil key": nilKey, "client role": ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil).pair, "no SAN": ca.leaf(t, x509.ExtKeyUsageServerAuth, func(c *x509.Certificate) { c.DNSNames = nil; c.IPAddresses = nil }, nil).pair, "expired": ca.leaf(t, x509.ExtKeyUsageServerAuth, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }, nil).pair} {
		t.Run(name, func(t *testing.T) {
			if _, err := r.TLSConfig(pair); !errors.Is(err, ErrConfiguration) {
				t.Fatal(err)
			}
		})
	}
}
func TestAuthenticationRejectsUnverifiedAndSpoofedTLSState(t *testing.T) {
	ca := newCA(t)
	r := registry(t, ca, nil)
	leaf := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	approve(t, r, leaf)
	other := ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil)
	if _, err := r.Authenticate(nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*http.Request){"plaintext": func(req *http.Request) { req.TLS = nil }, "no handshake": func(req *http.Request) { req.TLS.HandshakeComplete = false }, "no verified chain": func(req *http.Request) { req.TLS.VerifiedChains = nil }, "empty verified chain": func(req *http.Request) { req.TLS.VerifiedChains = [][]*x509.Certificate{{}} }, "different verified leaf": func(req *http.Request) { req.TLS.VerifiedChains = [][]*x509.Certificate{{other.cert}} }, "old TLS": func(req *http.Request) { req.TLS.Version = tls.VersionTLS12 }, "no peer": func(req *http.Request) { req.TLS.PeerCertificates = nil }} {
		t.Run(name, func(t *testing.T) {
			req := requestWithCert(leaf)
			edit(req)
			if _, err := r.Authenticate(req); !errors.Is(err, ErrUnauthorized) {
				t.Fatal(err)
			}
		})
	}
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("unauthenticated context contains agent")
	}
}
func TestStrongKeyAcceptanceAndWeakCurveRejection(t *testing.T) {
	ca := newCA(t)
	r := registry(t, ca, nil)
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaf := range []fixtureLeaf{ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, ed), ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, rsaKey)} {
		approve(t, r, leaf)
	}
	weak, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Approve(context.Background(), ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, weak).pem, "weak"); !errors.Is(err, ErrCertificate) {
		t.Fatalf("weak curve accepted: %v", err)
	}
}
func TestMemoryStorePreventsReassignmentAndUnrevocation(t *testing.T) {
	ca := newCA(t)
	store := NewMemoryStore()
	r := registry(t, ca, store)
	a := approve(t, r, ca.leaf(t, x509.ExtKeyUsageClientAuth, nil, nil))
	changed := a
	changed.FingerprintSHA256 = strings.Repeat("0", 64)
	if err := store.Save(context.Background(), changed); !errors.Is(err, ErrConfiguration) {
		t.Fatal("fingerprint reassigned")
	}
	changed = a
	changed.ID = "agent_00000000000000000000000000000000"
	if err := store.Save(context.Background(), changed); !errors.Is(err, ErrConfiguration) {
		t.Fatal("fingerprint duplicated")
	}
	if err := r.Revoke(context.Background(), a.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), a); !errors.Is(err, ErrConfiguration) {
		t.Fatal("tombstone removed")
	}
}
