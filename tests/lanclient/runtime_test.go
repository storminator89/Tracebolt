//go:build linux

// These tests exercise the public CLI and HTTP contracts only. Neither runtime,
// collector, certificate registry, nor sender state is called in-process.
package lanclient_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

const fixtureLabel = "Disposable runtime endpoint"

var opaqueID = regexp.MustCompile(`^agent_[0-9a-f]{32}$`)

type fixture struct {
	root, profile, managerConfig, agentConfig, origin, ingress string
	password, fingerprint                                      string
	clientCertificate                                          []byte
	roots                                                      *x509.CertPool
	agent                                                      map[string]any
}

type report struct {
	SchemaVersion  string `json:"schemaVersion"`
	Status         string `json:"status"`
	Profile        string `json:"profile"`
	Sequence       uint64 `json:"sequence"`
	Duplicate      bool   `json:"duplicate"`
	RetriedPending bool   `json:"retriedPending"`
	DiscardedStale bool   `json:"discardedStale"`
	Available      int    `json:"availablePercentageFields"`
	Unavailable    int    `json:"unavailablePercentageFields"`
}

type metric struct {
	Value                 *float64 `json:"value"`
	Quality, Source, Unit string
	CollectedAt           time.Time
}

type device struct {
	ID, Name, Platform, OS, Site, Group, Source, Status, AgentVersion string
	Synthetic                                                         bool
	IP                                                                *string
	LastSeen                                                          time.Time
	CPU, Memory, Disk                                                 metric
	Evidence                                                          []struct {
		Synthetic       bool
		Source, Quality string
		CollectedAt     time.Time
	}
	Capabilities []struct{ ID, Status, Detail string }
	Trend        []float64
	CaseIDs      []string
}

type agentDescriptor struct {
	ID, Label, FingerprintSHA256                string
	ApprovedAt, NotBefore, ExpiresAt, RevokedAt time.Time
}

type session struct {
	Mode, Transport                                         string
	Authenticated, AuthenticationRequired, InsecureTestMode bool
	CSRFToken                                               *string
	TransportWarning                                        *string
}

func TestNativeTwoBinaryRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("two-binary local runtime test")
	}
	manager, sender := buildBinaries(t)
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t, profile)
			op := operatorClient(t, f)
			p := startManager(t, manager, f.managerConfig)
			awaitReady(t, p, op, f)
			assertUnauthenticated(t, op, f)
			csrf := login(t, op, f)
			if len(inventory(t, op, f)) != 0 {
				t.Fatal("fresh manager substituted an observation")
			}
			if profile == "tls" {
				assertMTLSRequired(t, op, f)
			}
			a := approve(t, op, f, csrf)
			f.agent["agentId"] = a.ID
			writeJSON(t, f.agentConfig, f.agent)
			awaiting := onlyDevice(t, op, f)
			if awaiting.ID != a.ID || !awaiting.LastSeen.IsZero() || awaiting.CPU.Value != nil || awaiting.Memory.Value != nil || awaiting.Disk.Value != nil || awaiting.Source != "lan" || awaiting.Synthetic || awaiting.Status != "unknown" {
				t.Fatal("unobserved agent did not remain unknown")
			}

			first := runSender(t, sender, f.agentConfig, profile, true)
			assertAcknowledged(t, first, 1)
			d1 := onlyDevice(t, op, f)
			assertObservation(t, d1, a.ID, first)

			second := runSender(t, sender, f.agentConfig, profile, true)
			assertAcknowledged(t, second, 2)
			d2 := onlyDevice(t, op, f)
			assertObservation(t, d2, a.ID, second)
			if !d2.LastSeen.After(d1.LastSeen) {
				t.Fatal("second process did not produce a new observation")
			}

			// Restart the manager using exactly the same protected state. Browser
			// sessions are intentionally memory-only, whereas approvals persist.
			p.stop(t)
			op.CloseIdleConnections()
			p = startManager(t, manager, f.managerConfig)
			awaitReady(t, p, op, f)
			assertUnauthenticated(t, op, f)
			csrf = login(t, op, f)
			assertRegistry(t, op, f, a, false)
			if !onlyDevice(t, op, f).LastSeen.Equal(d2.LastSeen) {
				t.Fatal("manager restart lost the accepted observation")
			}

			// A separate disposable sender state starts at sequence one. Its
			// rejection proves the restarted manager retained its replay floor.
			replayConfig := filepath.Join(f.root, "replay-agent.json")
			replay := cloneMap(f.agent)
			replay["stateDirectory"] = filepath.Join(f.root, "replay-state")
			writeJSON(t, replayConfig, replay)
			rejected := runSender(t, sender, replayConfig, profile, false)
			if rejected.Sequence != 1 || rejected.Status != "pending_retained" {
				t.Fatal("manager restart did not reject a stale sequence")
			}
			if !onlyDevice(t, op, f).LastSeen.Equal(d2.LastSeen) {
				t.Fatal("rejected replay changed the accepted observation")
			}

			third := runSender(t, sender, f.agentConfig, profile, true)
			assertAcknowledged(t, third, 3)
			d3 := onlyDevice(t, op, f)
			assertObservation(t, d3, a.ID, third)
			if !d3.LastSeen.After(d2.LastSeen) {
				t.Fatal("sender state continuity failed after manager restart")
			}

			status, _ := operatorCall(t, op, f, "POST", "/api/lan/agents/"+a.ID+"/revoke", map[string]string{}, csrf)
			if status != http.StatusOK {
				t.Fatal("revocation failed")
			}
			assertRegistry(t, op, f, a, true)
			denied := runSender(t, sender, f.agentConfig, profile, false)
			if denied.Sequence != 4 || denied.Status != "pending_retained" || denied.RetriedPending {
				t.Fatal("revoked sender was not rejected with pending state retained")
			}
			assertRevokedInventory(t, op, f, d3.LastSeen)

			// Revocation and the last accepted observation also survive restart.
			p.stop(t)
			op.CloseIdleConnections()
			p = startManager(t, manager, f.managerConfig)
			awaitReady(t, p, op, f)
			_ = login(t, op, f)
			assertRegistry(t, op, f, a, true)
			denied = runSender(t, sender, f.agentConfig, profile, false)
			if denied.Sequence != 4 || denied.Status != "pending_retained" || !denied.RetriedPending {
				t.Fatal("revocation did not survive manager restart")
			}
			assertRevokedInventory(t, op, f, d3.LastSeen)
			p.stop(t)
			assertProtectedTree(t, f.root)
		})
	}
}

func buildBinaries(t *testing.T) (string, string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("repository location unavailable")
	}
	dir := t.TempDir()
	build := func(name string) string {
		binary := filepath.Join(dir, name)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", binary, "./cmd/"+name)
		cmd.Dir = root
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if cmd.Run() != nil {
			t.Fatal("runtime binary build failed")
		}
		return binary
	}
	return build("lan-manager"), build("lan-agent")
}

func newFixture(t *testing.T, profile string) fixture {
	t.Helper()
	f := fixture{root: t.TempDir(), profile: profile}
	if os.Chmod(f.root, 0700) != nil {
		t.Fatal("fixture directory protection failed")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("fixture CA generation failed")
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal("fixture CA creation failed")
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("fixture CA parse failed")
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.roots = x509.NewCertPool()
	f.roots.AddCert(ca)
	issue := func(n int64, role x509.ExtKeyUsage) ([]byte, []byte, string) {
		pub, private, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal("fixture leaf generation failed")
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(n), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{role}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		d, e := x509.CreateCertificate(rand.Reader, leaf, ca, pub, key)
		if e != nil {
			t.Fatal("fixture leaf creation failed")
		}
		pk, e := x509.MarshalPKCS8PrivateKey(private)
		if e != nil {
			t.Fatal("fixture private key encoding failed")
		}
		sum := sha256.Sum256(d)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), hex.EncodeToString(sum[:])
	}
	serverCert, serverKey, _ := issue(2, x509.ExtKeyUsageServerAuth)
	clientCert, clientKey, fingerprint := issue(3, x509.ExtKeyUsageClientAuth)
	f.clientCertificate, f.fingerprint = clientCert, fingerprint

	// Reserve both addresses together to avoid selecting the same ephemeral
	// port twice. They are released immediately before the actual manager binds.
	op, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("loopback fixture listener failed")
	}
	defer op.Close()
	ag, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("loopback fixture listener failed")
	}
	defer ag.Close()
	scheme := "https"
	if profile == "http-test" {
		scheme = "http"
	}
	f.origin, f.ingress = scheme+"://"+op.Addr().String(), scheme+"://"+ag.Addr().String()

	passwordBytes := make([]byte, 32)
	salt := make([]byte, 24)
	if _, err := rand.Read(passwordBytes); err != nil {
		t.Fatal("fixture password generation failed")
	}
	if _, err := rand.Read(salt); err != nil {
		t.Fatal("fixture salt generation failed")
	}
	f.password = base64.RawStdEncoding.EncodeToString(passwordBytes)
	clear(passwordBytes)
	hash := argon2.IDKey([]byte(f.password), salt, 2, 65536, 1, 32)
	phc := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	authPath, caPath := filepath.Join(f.root, "auth.json"), filepath.Join(f.root, "ca.pem")
	writeJSON(t, authPath, map[string]any{"schemaVersion": "tracebolt.operator-auth.v1", "profile": profile, "passwordHash": phc})
	writePrivate(t, caPath, caPEM)
	webPath := filepath.Join(f.root, "web")
	if os.Mkdir(webPath, 0700) != nil {
		t.Fatal("fixture web directory failed")
	}
	writePrivate(t, filepath.Join(webPath, "index.html"), []byte("Disposable runtime fixture"))
	manager := map[string]any{"schemaVersion": "tracebolt.lan-config.v1", "operatorListen": op.Addr().String(), "agentListen": ag.Addr().String(), "operatorOrigin": f.origin, "agentOrigin": f.ingress, "agentClientCAFile": caPath, "operatorAuthFile": authPath, "stateDirectory": filepath.Join(f.root, "manager-state"), "webDirectory": webPath}
	f.agent = map[string]any{"schemaVersion": "tracebolt.lan-agent.v1", "managerOrigin": f.ingress, "certificateFile": filepath.Join(f.root, "client.pem"), "privateKeyFile": filepath.Join(f.root, "client.key"), "stateDirectory": filepath.Join(f.root, "agent-state")}
	writePrivate(t, f.agent["certificateFile"].(string), clientCert)
	writePrivate(t, f.agent["privateKeyFile"].(string), clientKey)
	if profile == "tls" {
		// Omit both profile fields: TLS must really be the default.
		manager["tlsCertificateFile"] = filepath.Join(f.root, "server.pem")
		manager["tlsPrivateKeyFile"] = filepath.Join(f.root, "server.key")
		writePrivate(t, manager["tlsCertificateFile"].(string), serverCert)
		writePrivate(t, manager["tlsPrivateKeyFile"].(string), serverKey)
		f.agent["serverCAFile"] = caPath
	} else {
		manager["profile"], f.agent["profile"] = profile, profile
		manager["insecureHTTPAcknowledged"], f.agent["insecureHTTPAcknowledged"] = true, true
	}
	clear(clientKey)
	clear(serverKey)
	f.managerConfig, f.agentConfig = filepath.Join(f.root, "manager.json"), filepath.Join(f.root, "agent.json")
	writeJSON(t, f.managerConfig, manager)
	return f
}

func writePrivate(t *testing.T, path string, raw []byte) {
	t.Helper()
	if !filepath.IsAbs(path) || os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("protected fixture write failed")
	}
}
func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("fixture JSON encoding failed")
	}
	writePrivate(t, path, raw)
}
func cloneMap(source map[string]any) map[string]any {
	out := make(map[string]any, len(source))
	for k, v := range source {
		out[k] = v
	}
	return out
}

type process struct {
	cmd     *exec.Cmd
	done    chan struct{}
	err     error
	stopped bool
}

func startManager(t *testing.T, binary, config string) *process {
	t.Helper()
	p := &process{cmd: exec.Command(binary, "--lan-config", config), done: make(chan struct{})}
	p.cmd.Stdout, p.cmd.Stderr = io.Discard, io.Discard
	if p.cmd.Start() != nil {
		t.Fatal("manager process start failed")
	}
	go func() { p.err = p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { p.stop(t) })
	return p
}
func (p *process) stop(t *testing.T) {
	t.Helper()
	if p.stopped {
		return
	}
	p.stopped = true
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
		if p.err != nil {
			t.Error("manager did not exit cleanly")
		}
	case <-time.After(8 * time.Second):
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(time.Second):
		}
		t.Error("manager exceeded bounded SIGTERM shutdown")
	}
}

func operatorClient(t *testing.T, f fixture) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal("operator cookie jar failed")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: f.roots, MinVersion: tls.VersionTLS13}, TLSHandshakeTimeout: 2 * time.Second}
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(transport.CloseIdleConnections)
	return client
}
func awaitReady(t *testing.T, p *process, client *http.Client, f fixture) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-p.done:
			t.Fatal("manager exited before readiness")
		default:
		}
		res, err := client.Get(f.origin + "/api/auth/session")
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 8192))
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("manager readiness timed out")
}
func operatorCall(t *testing.T, client *http.Client, f fixture, method, path string, body any, csrf string) (int, []byte) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal("operator request encoding failed")
		}
	}
	req, err := http.NewRequest(method, f.origin+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal("operator request creation failed")
	}
	if method != "GET" {
		req.Header.Set("Origin", f.origin)
		req.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal("operator request failed")
	}
	defer res.Body.Close()
	out, err := io.ReadAll(io.LimitReader(res.Body, 128*1024+1))
	if err != nil || len(out) > 128*1024 {
		t.Fatal("operator response exceeded safe bounds")
	}
	return res.StatusCode, out
}
func assertUnauthenticated(t *testing.T, client *http.Client, f fixture) {
	t.Helper()
	status, raw := operatorCall(t, client, f, "GET", "/api/auth/session", nil, "")
	var s session
	if status != 200 || json.Unmarshal(raw, &s) != nil || s.Authenticated || !s.AuthenticationRequired || s.CSRFToken != nil {
		t.Fatal("unauthenticated session boundary failed")
	}
	status, _ = operatorCall(t, client, f, "GET", "/api/devices", nil, "")
	if status != 401 {
		t.Fatal("unauthenticated inventory was exposed")
	}
}
func login(t *testing.T, client *http.Client, f fixture) string {
	t.Helper()
	status, raw := operatorCall(t, client, f, "POST", "/api/auth/login", map[string]string{"password": f.password}, "")
	var s session
	if status != 200 || json.Unmarshal(raw, &s) != nil || !s.Authenticated || s.Mode != "lan" || s.CSRFToken == nil || *s.CSRFToken == "" {
		t.Fatal("operator fixture login failed")
	}
	if s.InsecureTestMode != (f.profile == "http-test") || s.AuthenticationRequired != true {
		t.Fatal("operator profile metadata mismatch")
	}
	if f.profile == "tls" && (s.Transport != "https" || s.TransportWarning != nil) {
		t.Fatal("default TLS session contract failed")
	}
	if f.profile == "http-test" && (s.Transport != "http" || s.TransportWarning == nil || *s.TransportWarning != "unencrypted_lan_test") {
		t.Fatal("HTTP test warning was absent")
	}
	return *s.CSRFToken
}
func approve(t *testing.T, client *http.Client, f fixture, csrf string) agentDescriptor {
	t.Helper()
	status, raw := operatorCall(t, client, f, "POST", "/api/lan/agents/approve", map[string]string{"certificatePEM": string(f.clientCertificate), "label": fixtureLabel, "expectedFingerprintSHA256": f.fingerprint}, csrf)
	var a agentDescriptor
	if status != 201 || json.Unmarshal(raw, &a) != nil || !opaqueID.MatchString(a.ID) || a.Label != fixtureLabel || a.FingerprintSHA256 != f.fingerprint || !a.RevokedAt.IsZero() {
		t.Fatal("public approval contract failed")
	}
	return a
}
func assertRegistry(t *testing.T, client *http.Client, f fixture, expected agentDescriptor, revoked bool) {
	t.Helper()
	status, raw := operatorCall(t, client, f, "GET", "/api/lan/agents", nil, "")
	var view struct {
		Items []agentDescriptor
		Total int
	}
	if status != 200 || json.Unmarshal(raw, &view) != nil || view.Total != 1 || len(view.Items) != 1 {
		t.Fatal("registry inventory failed")
	}
	a := view.Items[0]
	if a.ID != expected.ID || a.Label != expected.Label || a.FingerprintSHA256 != expected.FingerprintSHA256 || !a.ApprovedAt.Equal(expected.ApprovedAt) || a.RevokedAt.IsZero() == revoked {
		t.Fatal("durable registry contract failed")
	}
}
func inventory(t *testing.T, client *http.Client, f fixture) []device {
	t.Helper()
	status, raw := operatorCall(t, client, f, "GET", "/api/devices", nil, "")
	var view struct {
		Items []device
		Total int
	}
	if status != 200 || json.Unmarshal(raw, &view) != nil || view.Total != len(view.Items) {
		t.Fatal("authenticated inventory failed")
	}
	var tree any
	if json.Unmarshal(raw, &tree) != nil || hasHostIdentifier(tree) {
		t.Fatal("inventory exposed a host identifier field")
	}
	return view.Items
}
func hasHostIdentifier(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		for k, child := range v {
			switch strings.ToLower(strings.ReplaceAll(k, "_", "")) {
			case "hostname", "machineid", "serialnumber", "macaddress", "username", "userid", "networkinterfaces":
				return true
			}
			if hasHostIdentifier(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if hasHostIdentifier(child) {
				return true
			}
		}
	}
	return false
}
func onlyDevice(t *testing.T, client *http.Client, f fixture) device {
	t.Helper()
	ds := inventory(t, client, f)
	if len(ds) != 1 {
		t.Fatal("expected one independently sent observation")
	}
	return ds[0]
}
func assertObservation(t *testing.T, d device, id string, r report) {
	t.Helper()
	if d.ID != id || d.Name != fixtureLabel || d.Site != "Local network" || d.Group != "Managed devices" || d.IP != nil || d.Source != "lan" || d.Synthetic || d.Status != "unknown" || d.Platform != "linux" || d.LastSeen.IsZero() || len(d.Trend) != 0 || len(d.CaseIDs) != 0 {
		t.Fatal("native observation identity or provenance failed")
	}
	if time.Since(d.LastSeen) > time.Minute || d.LastSeen.After(time.Now().Add(time.Second)) {
		t.Fatal("native observation freshness failed")
	}
	available := 0
	for _, m := range []metric{d.CPU, d.Memory, d.Disk} {
		if m.Source == "" || m.Unit != "%" || m.CollectedAt.IsZero() || m.CollectedAt.After(d.LastSeen) {
			t.Fatal("native metric provenance failed")
		}
		if m.Value != nil {
			if math.IsNaN(*m.Value) || math.IsInf(*m.Value, 0) || *m.Value < 0 || *m.Value > 100 || m.Quality != "healthy" {
				t.Fatal("native metric validity failed")
			}
			available++
		} else if m.Quality == "healthy" {
			t.Fatal("unavailable metric claimed valid collection")
		}
	}
	if available != r.Available || 3-available != r.Unavailable {
		t.Fatal("safe availability counts did not match inventory")
	}
	if len(d.Evidence) == 0 {
		t.Fatal("native provenance evidence was absent")
	}
	for _, e := range d.Evidence {
		if e.Synthetic || e.Source == "" || e.CollectedAt.IsZero() || e.CollectedAt.After(d.LastSeen) {
			t.Fatal("native evidence contract failed")
		}
	}
}
func assertRevokedInventory(t *testing.T, client *http.Client, f fixture, lastSeen time.Time) {
	t.Helper()
	d := onlyDevice(t, client, f)
	if !d.LastSeen.Equal(lastSeen) {
		t.Fatal("revoked sender changed the accepted observation")
	}
	for _, c := range d.Capabilities {
		if c.ID == "agent_identity" && c.Status == "denied" {
			return
		}
	}
	t.Fatal("revocation was not reflected in inventory")
}
func assertMTLSRequired(t *testing.T, client *http.Client, f fixture) {
	t.Helper()
	req, err := http.NewRequest("POST", f.ingress+"/v1/agent/telemetry", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal("unauthenticated agent probe failed")
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err == nil {
		res.Body.Close()
		t.Fatal("TLS agent ingress accepted a handshake without a client certificate")
	}
}

// Capture is bounded even if a regressed binary unexpectedly prints data. No
// captured bytes are ever included in failure messages or persisted artifacts.
type boundedOutput struct {
	raw      []byte
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	room := 16*1024 - len(b.raw)
	if len(p) > room {
		b.overflow = true
		p = p[:room]
	}
	b.raw = append(b.raw, p...)
	return n, nil
}
func runSender(t *testing.T, binary, config, profile string, success bool) report {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--config", config)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 3 * time.Second
	var out boundedOutput
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatal("sender exceeded bounded foreground runtime")
	}
	if success && err != nil {
		t.Fatal("native sender did not acknowledge observation")
	}
	if !success {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			t.Fatal("sender rejection did not use delivery-failure exit status")
		}
	}
	var r report
	dec := json.NewDecoder(bytes.NewReader(out.raw))
	dec.DisallowUnknownFields()
	if out.overflow || dec.Decode(&r) != nil || dec.Decode(new(any)) != io.EOF || r.SchemaVersion != "tracebolt.agent-run.v1" || r.Profile != profile || r.Available < 0 || r.Unavailable < 0 || r.Available+r.Unavailable != 3 {
		t.Fatal("sender stdout exceeded the safe report contract")
	}
	return r
}
func assertAcknowledged(t *testing.T, r report, sequence uint64) {
	t.Helper()
	if r.Status != "acknowledged" || r.Sequence != sequence || r.Duplicate || r.RetriedPending || r.DiscardedStale {
		t.Fatal("sender acknowledgment or sequence continuity failed")
	}
}
func assertProtectedTree(t *testing.T, root string) {
	t.Helper()
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return errors.New("fixture walk failed")
		}
		if info.IsDir() {
			if info.Mode().Perm() != 0700 {
				return errors.New("directory protection failed")
			}
		} else if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("file protection failed")
		}
		return nil
	})
	if err != nil {
		t.Fatal("runtime material permissions did not remain private")
	}
}
