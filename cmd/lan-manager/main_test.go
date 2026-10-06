//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"golang.org/x/crypto/argon2"
	"io"
	"localrmm/internal/bundle"
	"localrmm/internal/collector"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/signedhttp"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Generated test-only material is shared by the native manager fixture and the
// offline OpenSSL interoperability regression. No listener is created here.
func fixtureTLS(t *testing.T) (caPEM, cert, keyPEM []byte, client tls.Certificate, clientPEM []byte, roots *x509.CertPool) {
	t.Helper()
	now := time.Now()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	ca := &x509.Certificate{Subject: pkix.Name{CommonName: "Ephemeral Tracebolt test root"}, SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal("fixture CA")
	}
	ca, _ = x509.ParseCertificate(der)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	roots = x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(n int64, role x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
		p, k, _ := ed25519.GenerateKey(rand.Reader)
		leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "Ephemeral Tracebolt test leaf"}, SerialNumber: big.NewInt(n), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{role}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		d, e := x509.CreateCertificate(rand.Reader, leaf, ca, p, key)
		if e != nil {
			t.Fatal("fixture leaf")
		}
		cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})
		pk, _ := x509.MarshalPKCS8PrivateKey(k)
		kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
		pair, e := tls.X509KeyPair(cp, kp)
		if e != nil {
			t.Fatal("fixture pair")
		}
		return pair, cp, kp
	}
	_, cert, keyPEM = issue(2, x509.ExtKeyUsageServerAuth)
	client, clientPEM, _ = issue(3, x509.ExtKeyUsageClientAuth)
	return
}

func fixture(t *testing.T, profile string) (lanconfig.Material, tls.Certificate, []byte, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	caPEM, cert, keyPEM, client, clientPEM, roots := fixtureTLS(t)
	port := func() string {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal("fixture port")
		}
		s := l.Addr().String()
		l.Close()
		return s
	}
	op, agent := port(), port()
	for agent == op {
		agent = port()
	}
	scheme := "https"
	if profile == lanconfig.HTTPTest {
		scheme = "http"
	}
	c := lanconfig.Config{SchemaVersion: lanconfig.SchemaVersion, Profile: profile, OperatorListen: op, AgentListen: agent, OperatorOrigin: scheme + "://" + op, AgentOrigin: scheme + "://" + agent, AgentClientCAFile: filepath.Join(dir, "ca.pem"), OperatorAuthFile: filepath.Join(dir, "auth.json"), StateDirectory: filepath.Join(dir, "state"), WebDirectory: filepath.Join(dir, "web"), InsecureHTTPAcknowledged: profile == lanconfig.HTTPTest}
	salt := []byte("ephemeral-test-salt")
	hash := argon2.IDKey([]byte("fixture-password-only"), salt, 2, 65536, 1, 32)
	phc := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	auth, _ := json.Marshal(map[string]string{"schemaVersion": "tracebolt.operator-auth.v1", "profile": profile, "passwordHash": phc})
	files := map[string][]byte{c.AgentClientCAFile: caPEM, c.OperatorAuthFile: auth}
	if profile == lanconfig.TLS {
		c.TLSCertificateFile = filepath.Join(dir, "server.pem")
		c.TLSPrivateKeyFile = filepath.Join(dir, "server.key")
		files[c.TLSCertificateFile] = cert
		files[c.TLSPrivateKeyFile] = keyPEM
	}
	raw, _ := json.Marshal(c)
	configPath := filepath.Join(dir, "lan.json")
	files[configPath] = raw
	for path, b := range files {
		if os.WriteFile(path, b, 0600) != nil {
			t.Fatal("fixture file")
		}
	}
	os.Mkdir(c.WebDirectory, 0700)
	os.WriteFile(filepath.Join(c.WebDirectory, "index.html"), []byte("fixture"), 0600)
	m, e := lanconfig.Load(configPath)
	if e != nil {
		t.Fatal("fixture config rejected")
	}
	return m, client, clientPEM, roots
}
func TestActualLANRuntimeProfiles(t *testing.T) { testRuntimeProfiles(t, "") }
func TestBuiltLANManagerCLI(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "lan-manager")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", binary, ".")
	if build.Run() != nil {
		t.Fatal("CLI fixture build failed")
	}
	testRuntimeProfiles(t, binary)
}
func testRuntimeProfiles(t *testing.T, binary string) {
	for _, profile := range []string{lanconfig.TLS, lanconfig.HTTPTest} {
		t.Run(profile, func(t *testing.T) {
			m, cert, certPEM, roots := fixture(t, profile)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			var process *os.Process
			if binary == "" {
				go func() { done <- run(ctx, m) }()
			} else {
				raw, _ := json.Marshal(m.Config)
				path := filepath.Join(t.TempDir(), "lan.json")
				if os.WriteFile(path, raw, 0600) != nil {
					t.Fatal("CLI config fixture")
				}
				cmd := exec.Command(binary, "--lan-config", path)
				if cmd.Start() != nil {
					t.Fatal("CLI start failed")
				}
				process = cmd.Process
				go func() { done <- cmd.Wait() }()
			}
			defer func() {
				cancel()
				if process != nil {
					_ = process.Signal(os.Interrupt)
				}
				select {
				case e := <-done:
					if e != nil {
						t.Error("runtime failed")
					}
				case <-time.After(8 * time.Second):
					if process != nil {
						_ = process.Kill()
					}
					t.Error("runtime did not stop")
				}
			}()
			transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
			defer transport.CloseIdleConnections()
			jar, _ := cookiejar.New(nil)
			client := &http.Client{Transport: transport, Jar: jar, Timeout: 5 * time.Second}
			deadline := time.Now().Add(5 * time.Second)
			var response *http.Response
			var e error
			for time.Now().Before(deadline) {
				response, e = client.Get(m.Config.OperatorOrigin + "/api/auth/session")
				if e == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if e != nil {
				t.Fatal("runtime did not become ready")
			}
			response.Body.Close()
			call := func(path string, body any, csrf string) (int, []byte) {
				raw, _ := json.Marshal(body)
				r, _ := http.NewRequest("POST", m.Config.OperatorOrigin+path, bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", m.Config.OperatorOrigin)
				if csrf != "" {
					r.Header.Set("X-CSRF-Token", csrf)
				}
				res, e := client.Do(r)
				if e != nil {
					t.Fatal("operator request failed")
				}
				defer res.Body.Close()
				out, e := io.ReadAll(io.LimitReader(res.Body, 65536))
				if e != nil {
					t.Fatal("operator response")
				}
				return res.StatusCode, out
			}
			status, raw := call("/api/auth/login", map[string]string{"password": "fixture-password-only"}, "")
			if status != 200 {
				t.Fatal("fixture login rejected")
			}
			var session struct {
				CSRFToken, Transport string
				InsecureTestMode     bool
			}
			if json.Unmarshal(raw, &session) != nil || session.CSRFToken == "" || session.InsecureTestMode != (profile == lanconfig.HTTPTest) {
				t.Fatal("auth metadata mismatch")
			}
			leaf, _ := x509.ParseCertificate(cert.Certificate[0])
			status, raw = call("/api/lan/agents/approve", map[string]string{"certificatePEM": string(certPEM), "label": "fixture agent", "expectedFingerprintSHA256": lantrust.Fingerprint(leaf)}, session.CSRFToken)
			if status != 201 {
				t.Fatal("public approval failed")
			}
			var agent lantrust.Agent
			json.Unmarshal(raw, &agent)
			encoded, e := bundle.Encode(collector.Snapshot())
			if e != nil {
				t.Fatal("local observation failed")
			}
			var observation bundle.Bundle
			json.Unmarshal(encoded, &observation)
			frame := lanstore.Frame{SchemaVersion: lanstore.FrameVersion, Sequence: 1, Observation: observation}
			body, _ := json.Marshal(frame)
			agentTransport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
			defer agentTransport.CloseIdleConnections()
			agentClient := &http.Client{Transport: agentTransport, Timeout: 5 * time.Second}
			send := func() (int, lanstore.Receipt) {
				var r *http.Request
				if profile == lanconfig.HTTPTest {
					r, e = signedhttp.NewSignedRequest(ctx, m.Config.AgentOrigin, cert, frame.Sequence, observation.GeneratedAt, body)
				} else {
					r, e = http.NewRequest("POST", m.Config.AgentOrigin+"/v1/agent/telemetry", bytes.NewReader(body))
					r.Header.Set("Content-Type", "application/json")
				}
				if e != nil {
					t.Fatal("fixture sender")
				}
				res, e := agentClient.Do(r)
				if e != nil {
					t.Fatal("agent request failed")
				}
				defer res.Body.Close()
				var receipt lanstore.Receipt
				json.NewDecoder(io.LimitReader(res.Body, 8192)).Decode(&receipt)
				return res.StatusCode, receipt
			}
			status, first := send()
			if status != 200 || first.AgentID != agent.ID || first.Duplicate {
				t.Fatal("first observation failed")
			}
			status, retry := send()
			if status != 200 || !retry.Duplicate || !retry.ReceivedAt.Equal(first.ReceivedAt) {
				t.Fatal("retry refreshed freshness")
			}
			status, _ = call("/api/lan/agents/"+agent.ID+"/revoke", map[string]string{}, session.CSRFToken)
			if status != 200 {
				t.Fatal("revoke failed")
			}
			status, _ = send()
			if status != 403 {
				t.Fatal("revoked agent accepted")
			}
			status, _ = call("/api/auth/logout", map[string]string{}, session.CSRFToken)
			if status != 200 {
				t.Fatal("logout failed")
			}
		})
	}
}
func TestProfileStateIsolation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if lanstore.PrepareProfileDirectory(dir, "tls") != nil {
		t.Fatal("initial profile")
	}
	if lanstore.PrepareProfileDirectory(dir, "tls") != nil {
		t.Fatal("same profile")
	}
	if lanstore.PrepareProfileDirectory(dir, "http-test") == nil {
		t.Fatal("state profile reuse allowed")
	}
}
