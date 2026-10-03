//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"localrmm/internal/api"
	"localrmm/internal/bundle"
	"localrmm/internal/collector"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureData struct {
	material Material
	registry *lantrust.Registry
	store    *lanstore.Store
	server   *httptest.Server
}

func integrationFixture(t *testing.T, profile string, wrap func(http.Handler) http.Handler) fixtureData {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	raw, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal("fixture root")
	}
	ca, _ = x509.ParseCertificate(raw)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	issuerKey := key
	issue := func(n int64, role x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(n), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{role}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		d, e := x509.CreateCertificate(rand.Reader, leaf, ca, pub, issuerKey)
		if e != nil {
			t.Fatal("fixture leaf")
		}
		cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})
		pk, _ := x509.MarshalPKCS8PrivateKey(key)
		kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
		pair, e := tls.X509KeyPair(cp, kp)
		if e != nil {
			t.Fatal("fixture pair")
		}
		return pair, cp, kp
	}
	serverPair, _, _ := issue(2, x509.ExtKeyUsageServerAuth)
	_, cp, kp := issue(3, x509.ExtKeyUsageClientAuth)
	store, e := lanstore.Open(filepath.Join(dir, "manager-state", "agents.db"))
	if e != nil {
		t.Fatal("fixture state")
	}
	t.Cleanup(func() { store.Close() })
	registry, e := lantrust.NewRegistry(context.Background(), caPEM, store)
	if e != nil {
		t.Fatal("fixture trust")
	}
	agent, e := registry.Approve(context.Background(), cp, "fixture endpoint")
	if e != nil {
		t.Fatal("fixture approval")
	}
	srv := httptest.NewUnstartedServer(nil)
	scheme := "http"
	if profile == "tls" {
		scheme = "https"
	}
	origin := scheme + "://" + srv.Listener.Addr().String()
	var handler http.Handler
	if profile == "tls" {
		handler, e = api.NewLANIngressHandler(registry, store, origin)
		srv.TLS, e = registry.TLSConfig(serverPair)
	} else {
		handler, e = api.NewHTTPTestIngressHandler(registry, store, origin)
	}
	if e != nil {
		t.Fatal("fixture ingress")
	}
	if wrap != nil {
		handler = wrap(handler)
	}
	srv.Config.Handler = handler
	if profile == "tls" {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	cfg := Config{SchemaVersion: ConfigVersion, Profile: profile, ManagerOrigin: origin, AgentID: agent.ID, CertificateFile: filepath.Join(dir, "client.pem"), PrivateKeyFile: filepath.Join(dir, "client.key"), StateDirectory: filepath.Join(dir, "client-state"), InsecureHTTPAcknowledged: profile == "http-test"}
	files := map[string][]byte{cfg.CertificateFile: cp, cfg.PrivateKeyFile: kp}
	if profile == "tls" {
		cfg.ServerCAFile = filepath.Join(dir, "server-ca.pem")
		files[cfg.ServerCAFile] = caPEM
	}
	raw, _ = json.Marshal(cfg)
	configPath := filepath.Join(dir, "agent.json")
	files[configPath] = raw
	for path, b := range files {
		if os.WriteFile(path, b, 0600) != nil {
			t.Fatal("fixture write")
		}
	}
	m, e := Load(configPath)
	if e != nil {
		t.Fatal("fixture config")
	}
	return fixtureData{m, registry, store, srv}
}
func TestExactRetryAfterCommittedResponseLoss(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			var mu sync.Mutex
			var bodies [][]byte
			var firstReceipt lanstore.Receipt
			f := integrationFixture(t, profile, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					raw, _ := io.ReadAll(io.LimitReader(r.Body, MaxFrameBytes+1))
					r.Body = io.NopCloser(bytes.NewReader(raw))
					mu.Lock()
					bodies = append(bodies, append([]byte(nil), raw...))
					first := len(bodies) == 1
					mu.Unlock()
					if first {
						rec := httptest.NewRecorder()
						next.ServeHTTP(rec, r)
						if rec.Code != 200 {
							t.Error("fixture first commit failed")
						}
						mu.Lock()
						json.Unmarshal(rec.Body.Bytes(), &firstReceipt)
						mu.Unlock()
						conn, _, e := w.(http.Hijacker).Hijack()
						if e != nil {
							t.Error("fixture disconnect")
						}
						conn.Close()
						return
					}
					next.ServeHTTP(w, r)
				})
			})
			report, e := Run(context.Background(), f.material)
			if !errors.Is(e, ErrTransport) || report.Status != "pending_retained" || report.Sequence != 1 {
				t.Fatal("uncertain delivery not retained")
			}
			report, e = Run(context.Background(), f.material)
			if e != nil || report.Status != "acknowledged" || !report.Duplicate || !report.RetriedPending || report.Sequence != 1 {
				t.Fatal("exact pending retry failed")
			}
			mu.Lock()
			equal := len(bodies) == 2 && bytes.Equal(bodies[0], bodies[1])
			mu.Unlock()
			if !equal {
				t.Fatal("retry changed original bytes")
			}
			state, e := lanclientstate.Open(f.material.config.StateDirectory, f.material.binding)
			if e != nil {
				t.Fatal("state reopen")
			}
			pending, e := state.Pending()
			sequence, e2 := state.NextSequence()
			state.Close()
			if e != nil || e2 != nil || pending != nil || sequence != 2 {
				t.Fatal("ack state not durable")
			}
			mu.Lock()
			recordedReceipt := firstReceipt
			mu.Unlock()
			devices, e := f.store.Devices(context.Background(), f.registry.List(), time.Now())
			if e != nil || len(devices) != 1 || !devices[0].LastSeen.Equal(recordedReceipt.CollectedAt) {
				t.Fatal("sample identity mismatch")
			}
		})
	}
}
func TestOriginBindingChangeFailsBeforeNetwork(t *testing.T) {
	f := integrationFixture(t, "http-test", nil)
	state, e := lanclientstate.Open(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal("state open")
	}
	state.Close()
	m := f.material
	m.binding = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, e = Run(context.Background(), m); !errors.Is(e, ErrConfiguration) {
		t.Fatal("changed binding accepted")
	}
}
func TestDestinationPolicy(t *testing.T) {
	for _, raw := range []string{"0.0.0.0", "169.254.169.254", "168.63.129.16", "100.100.100.200", "224.0.0.1", "::", "fe80::1", "fd00:ec2::254", "::ffff:169.254.169.254", "64:ff9b::a00:1", "2002:a00:1::1"} {
		if permittedAddress(netip.MustParseAddr(raw)) {
			t.Fatal("forbidden destination accepted")
		}
	}
	for _, raw := range []string{"127.0.0.1", "10.0.0.2", "172.16.0.2", "192.168.0.2", "::1", "fd42::1"} {
		ip := netip.MustParseAddr(raw)
		if !vettedAddresses([]netip.Addr{ip}, true) {
			t.Fatal("LAN destination rejected")
		}
	}
	if vettedAddresses([]netip.Addr{netip.MustParseAddr("8.8.8.8")}, true) {
		t.Fatal("public plaintext accepted")
	}
	if !vettedAddresses([]netip.Addr{netip.MustParseAddr("8.8.8.8")}, false) {
		t.Fatal("configured public TLS rejected")
	}
	if vettedAddresses([]netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("169.254.169.254")}, false) {
		t.Fatal("mixed DNS set accepted")
	}
}

func TestStalePendingIsNotRetimestamped(t *testing.T) {
	f := integrationFixture(t, "http-test", nil)
	// Create a legitimate bounded observation, then persist an explicitly old
	// fixture. Run must discard it without ever sending its bytes.
	raw, e := bundle.Encode(collector.Snapshot())
	if e != nil {
		t.Fatal("fixture observation")
	}
	var old bundle.Bundle
	json.Unmarshal(raw, &old)
	at := time.Now().Add(-3 * time.Minute).UTC()
	old.GeneratedAt = at
	old.Observation.LastSeen = at
	old.Observation.CPU.CollectedAt = at
	old.Observation.Memory.CollectedAt = at
	old.Observation.Disk.CollectedAt = at
	for i := range old.Observation.Evidence {
		old.Observation.Evidence[i].CollectedAt = at
	}
	body, _ := json.Marshal(frame{SchemaVersion: FrameVersion, Sequence: 1, Observation: old})
	state, e := lanclientstate.Open(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal("state open")
	}
	if _, e = state.Stage(1, body); e != nil {
		t.Fatal("fixture stage")
	}
	state.Close()
	report, e := Run(context.Background(), f.material)
	if e != nil || !report.DiscardedStale || report.RetriedPending || report.Sequence != 2 || report.Status != "acknowledged" {
		t.Fatal("old pending was replayed or sequence reused")
	}
	ds, e := f.store.Devices(context.Background(), f.registry.List(), time.Now())
	if e != nil || len(ds) != 1 || !ds[0].LastSeen.After(at) {
		t.Fatal("new observation was not actually collected")
	}
}
func TestMalformedOrEncodedReceiptRetainsPending(t *testing.T) {
	for _, kind := range []string{"missing-field", "encoded", "oversized", "wrong-agent"} {
		t.Run(kind, func(t *testing.T) {
			f := integrationFixture(t, "http-test", func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					rec := httptest.NewRecorder()
					next.ServeHTTP(rec, r)
					var body map[string]any
					json.Unmarshal(rec.Body.Bytes(), &body)
					w.Header().Set("Content-Type", "application/json")
					switch kind {
					case "missing-field":
						delete(body, "duplicate")
					case "encoded":
						w.Header().Set("Content-Encoding", "gzip")
					case "oversized":
						body["padding"] = strings.Repeat("x", 9000)
					case "wrong-agent":
						body["agentId"] = "agent_00000000000000000000000000000000"
					}
					json.NewEncoder(w).Encode(body)
				})
			})
			report, e := Run(context.Background(), f.material)
			if !errors.Is(e, ErrReceipt) || report.Status != "pending_retained" {
				t.Fatal("malformed receipt acknowledged")
			}
			state, e := lanclientstate.Open(f.material.config.StateDirectory, f.material.binding)
			if e != nil {
				t.Fatal("state reopen")
			}
			pending, _ := state.Pending()
			state.Close()
			if pending == nil {
				t.Fatal("pending observation lost")
			}
		})
	}
}
func TestRedirectAndCancellationDoNotSendElsewhere(t *testing.T) {
	var redirects atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirects.Add(1) }))
	defer target.Close()
	f := integrationFixture(t, "http-test", func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) })
	})
	if _, e := Run(context.Background(), f.material); !errors.Is(e, ErrTransport) || redirects.Load() != 0 {
		t.Fatal("redirect followed or incorrectly acknowledged")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Run(ctx, f.material); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled attempt continued")
	}
}
func TestMaterialCannotFallbackToAmbientTrust(t *testing.T) {
	f := integrationFixture(t, "tls", nil)
	for _, mutate := range []func(*Material){func(m *Material) { m.loaded = false }, func(m *Material) { m.tlsConfig = nil }, func(m *Material) { m.tlsConfig = m.tlsConfig.Clone(); m.tlsConfig.RootCAs = nil }, func(m *Material) { m.tlsConfig = m.tlsConfig.Clone(); m.tlsConfig.InsecureSkipVerify = true }, func(m *Material) { m.tlsConfig = m.tlsConfig.Clone(); m.tlsConfig.ServerName = "other.invalid" }, func(m *Material) { m.tlsConfig = m.tlsConfig.Clone(); m.tlsConfig.Certificates = nil }} {
		m := f.material
		mutate(&m)
		if _, e := Run(context.Background(), m); !errors.Is(e, ErrConfiguration) {
			t.Fatal("invalid trust material accepted")
		}
	}
}
func TestHTTPMaterialRejectsExpiredAndWrongRoleBeforeState(t *testing.T) {
	for _, kind := range []string{"expired", "server-role", "ca-leaf", "mixed-role"} {
		t.Run(kind, func(t *testing.T) {
			f := integrationFixture(t, "http-test", nil)
			now := time.Now()
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			leaf := &x509.Certificate{SerialNumber: big.NewInt(70), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
			switch kind {
			case "expired":
				leaf.NotBefore = now.Add(-2 * time.Hour)
				leaf.NotAfter = now.Add(-time.Hour)
			case "server-role":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			case "ca-leaf":
				leaf.IsCA = true
				leaf.BasicConstraintsValid = true
				leaf.KeyUsage |= x509.KeyUsageCertSign
			case "mixed-role":
				leaf.ExtKeyUsage = append(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
			}
			der, e := x509.CreateCertificate(rand.Reader, leaf, leaf, pub, key)
			if e != nil {
				t.Fatal("fixture certificate")
			}
			pk, _ := x509.MarshalPKCS8PrivateKey(key)
			os.WriteFile(f.material.config.CertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
			os.WriteFile(f.material.config.PrivateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600)
			path := filepath.Join(filepath.Dir(f.material.config.PrivateKeyFile), "agent.json")
			if _, e = Load(path); !errors.Is(e, ErrConfiguration) {
				t.Fatal("invalid HTTP certificate admitted")
			}
			if _, e = os.Stat(f.material.config.StateDirectory); !os.IsNotExist(e) {
				t.Fatal("configuration rejection created state")
			}
		})
	}
}
func TestConfigChangeCannotReusePendingState(t *testing.T) {
	f := integrationFixture(t, "http-test", nil)
	state, e := lanclientstate.Open(f.material.config.StateDirectory, f.material.binding)
	if e != nil {
		t.Fatal("state open")
	}
	state.Close()
	c := f.material.config
	c.ManagerOrigin = "http://127.0.0.1:12345"
	raw, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "changed-agent.json")
	os.WriteFile(path, raw, 0600)
	m, e := Load(path)
	if e != nil {
		t.Fatal("changed fixture load")
	}
	if _, e = Run(context.Background(), m); !errors.Is(e, ErrState) {
		t.Fatal("different configured origin reused state")
	}
}
func TestBuiltAgentCLIExactRetry(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "lan-agent")
	if exec.Command("go", "build", "-buildvcs=false", "-o", binary, "../../cmd/lan-agent").Run() != nil {
		t.Fatal("agent fixture build")
	}
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			var mu sync.Mutex
			var bodies [][]byte
			f := integrationFixture(t, profile, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					raw, _ := io.ReadAll(io.LimitReader(r.Body, MaxFrameBytes+1))
					r.Body = io.NopCloser(bytes.NewReader(raw))
					mu.Lock()
					bodies = append(bodies, bytes.Clone(raw))
					first := len(bodies) == 1
					mu.Unlock()
					if first {
						rec := httptest.NewRecorder()
						next.ServeHTTP(rec, r)
						if rec.Code != 200 {
							t.Error("fixture commit failed")
						}
						conn, _, e := w.(http.Hijacker).Hijack()
						if e != nil {
							t.Error("fixture disconnect")
							return
						}
						conn.Close()
						return
					}
					next.ServeHTTP(w, r)
				})
			})
			path := filepath.Join(filepath.Dir(f.material.config.PrivateKeyFile), "agent.json")
			invoke := func() (Report, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binary, "--config", path)
				var stdout bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = io.Discard
				e := cmd.Run()
				var report Report
				if json.Unmarshal(stdout.Bytes(), &report) != nil {
					t.Fatal("CLI did not return bounded status JSON")
				}
				if strings.Contains(stdout.String(), "CERTIFICATE") || strings.Contains(stdout.String(), "fixture endpoint") {
					t.Fatal("CLI leaked material")
				}
				return report, e
			}
			first, e := invoke()
			if e == nil || first.Status != "pending_retained" || first.Sequence != 1 {
				t.Fatal("CLI uncertain attempt not retained")
			}
			second, e := invoke()
			if e != nil || second.Status != "acknowledged" || !second.Duplicate || !second.RetriedPending || second.Sequence != 1 {
				t.Fatal("new CLI process did not retry pending bytes")
			}
			mu.Lock()
			equal := len(bodies) == 2 && bytes.Equal(bodies[0], bodies[1])
			mu.Unlock()
			if !equal {
				t.Fatal("CLI restart changed observation bytes")
			}
		})
	}
}
