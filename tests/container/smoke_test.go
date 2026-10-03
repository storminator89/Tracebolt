package container_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/signedhttp"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Opt-in because this test starts Docker containers, uses temporary fixture
// credentials and needs sudo chown for a non-root bind-mounted fixture directory.
// Never put real credentials, logs or endpoint observations into its artifacts.
func TestTLSContainerLifecycle(t *testing.T)      { containerLifecycle(t, "tls") }
func TestHTTPTestContainerLifecycle(t *testing.T) { containerLifecycle(t, "http-test") }
func containerLifecycle(t *testing.T, profile string) {
	image := os.Getenv("TRACEBOLT_CONTAINER_IMAGE")
	if image == "" {
		t.Skip("set TRACEBOLT_CONTAINER_IMAGE to run Docker smoke")
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("container smoke command failed: %s (output withheld)", name)
		}
		return strings.TrimSpace(string(out))
	}
	run("docker", "info", "--format", "{{.ServerVersion}}")
	creds := fixtureCredentials(t)
	dir, err := os.MkdirTemp("", "tracebolt-container-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	// Restore fixture ownership before removing its contents; never touch host data.
	defer func() {
		exec.Command("sudo", "-n", "chown", "-R", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), dir).Run()
		os.RemoveAll(dir)
	}()
	port := func() string {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		p := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
		l.Close()
		return p
	}
	opPort, agentPort := port(), port()
	for agentPort == opPort {
		agentPort = port()
	}
	scheme := "https"
	if profile == "http-test" {
		scheme = "http"
	}
	op := scheme + "://127.0.0.1:" + opPort
	ingress := scheme + "://127.0.0.1:" + agentPort
	files := map[string][]byte{"server.pem": creds.serverCert, "server.key": creds.serverKey, "agent-ca.pem": creds.ca}
	files["operator-auth.json"], _ = json.Marshal(map[string]string{"schemaVersion": "tracebolt.operator-auth.v1", "profile": profile, "passwordHash": creds.hash})
	config := map[string]any{
		"schemaVersion": "tracebolt.lan-config.v1", "profile": profile,
		"operatorListen": "0.0.0.0:8443", "agentListen": "0.0.0.0:8444",
		"operatorOrigin": op, "agentOrigin": ingress,
		"tlsCertificateFile": "/run/tracebolt/server.pem", "tlsPrivateKeyFile": "/run/tracebolt/server.key",
		"agentClientCAFile": "/run/tracebolt/agent-ca.pem", "operatorAuthFile": "/run/tracebolt/operator-auth.json",
		"stateDirectory": "/data/state", "webDirectory": "/tracebolt/web",
	}
	if profile == "http-test" {
		config["insecureHTTPAcknowledged"] = true
		delete(config, "tlsCertificateFile")
		delete(config, "tlsPrivateKeyFile")
		delete(files, "server.pem")
		delete(files, "server.key")
	}
	files["lan.json"], _ = json.Marshal(config)
	for name, body := range files {
		if os.WriteFile(filepath.Join(dir, name), body, 0600) != nil {
			t.Fatal("fixture write failed")
		}
	}
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("fixture directory permissions")
	}
	run("sudo", "-n", "chown", "-R", "65532:65532", dir)
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	name := "tracebolt-smoke-" + suffix
	volume := name + "-state"
	run("docker", "volume", "create", volume)
	defer exec.Command("docker", "volume", "rm", volume).Run()
	defer exec.Command("docker", "rm", "-f", name).Run()

	args := []string{"run", "-d", "--name", name, "--read-only", "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", "128", "--memory", "512m", "--cpus", "2", "--mount", "type=volume,src=" + volume + ",dst=/data", "--mount", "type=bind,src=" + dir + ",dst=/run/tracebolt,readonly", "-p", "127.0.0.1:" + opPort + ":8443", "-p", "127.0.0.1:" + agentPort + ":8444", image, "--lan-config", "/run/tracebolt/lan.json"}
	// Missing configuration must fail closed, rather than launching the developer HTTP server.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	defer exec.Command("docker", "rm", "-f", name+"-unconfigured").Run()
	if err := exec.CommandContext(ctx, "docker", "run", "--name", name+"-unconfigured", "--rm", "--read-only", "--cap-drop", "ALL", image).Run(); err == nil {
		t.Fatal("unconfigured image unexpectedly started successfully")
	}
	if ctx.Err() != nil {
		t.Fatal("unconfigured image did not fail promptly")
	}
	run("docker", args...)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(creds.ca) {
		t.Fatal("fixture roots")
	}
	client := func(cert bool) *http.Client {
		config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
		if cert {
			config.Certificates = []tls.Certificate{creds.client}
		}
		jar, _ := cookiejar.New(nil)
		return &http.Client{Transport: &http.Transport{TLSClientConfig: config, Proxy: nil}, Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	operator, agent, anonymous := client(false), client(true), client(false)
	request := func(c *http.Client, method, url string, body []byte, csrf string, want int) []byte {
		t.Helper()
		req, e := http.NewRequest(method, url, bytes.NewReader(body))
		if profile == "http-test" && c == agent {
			var frame lanstore.Frame
			if json.Unmarshal(body, &frame) != nil {
				t.Fatal("signed fixture frame")
			}
			req, e = signedhttp.NewSignedRequest(context.Background(), ingress, creds.client, frame.Sequence, frame.Observation.GeneratedAt, body)
		}
		if e != nil {
			t.Fatal(e)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if strings.HasPrefix(url, op) && method == "POST" {
			req.Header.Set("Origin", op)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		res, e := c.Do(req)
		if e != nil {
			t.Fatalf("request failed (%s); details withheld", method)
		}
		defer res.Body.Close()
		raw, e := io.ReadAll(io.LimitReader(res.Body, 1024*1024))
		if e != nil {
			t.Fatal("response read")
		}
		if res.StatusCode != want {
			t.Fatalf("%s expected %d, got %d", req.URL.Path, want, res.StatusCode)
		}
		return raw
	}
	ready := func() {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			r, e := anonymous.Get(op + "/api/auth/session")
			if e == nil {
				r.Body.Close()
				if r.StatusCode == 200 {
					return
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal("container readiness failed; raw logs intentionally withheld")
	}
	ready()
	if got := run("docker", "inspect", "--format", "{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}}", name); !strings.Contains(got, "65532:65532 true [\"ALL\"]") || !strings.Contains(got, "no-new-privileges") {
		t.Fatal("runtime hardening not active")
	}
	request(anonymous, "GET", op+"/api/overview", nil, "", 401)
	request(anonymous, "GET", op+"/", nil, "", 200)
	login := func() string {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"password": creds.password})
		raw := request(operator, "POST", op+"/api/auth/login", body, "", 200)
		var session struct {
			CSRFToken     string `json:"csrfToken"`
			Authenticated bool   `json:"authenticated"`
		}
		if json.Unmarshal(raw, &session) != nil || session.CSRFToken == "" || !session.Authenticated {
			t.Fatal("authenticated session absent")
		}
		return session.CSRFToken
	}
	request(anonymous, "POST", op+"/api/auth/login", []byte(`{"password":"wrong-disposable-password"}`), "", 401)
	csrf := login()
	request(operator, "GET", op+"/api/health", nil, "", 200)
	// Trusted client certificate without approval is rejected at the HTTP boundary.
	frame := fixtureFrame(t)
	request(agent, "POST", ingress+"/v1/agent/telemetry", frame, "", 403)
	if profile == "tls" {
		// Missing client cert fails the TLS handshake, never reaching the handler.
		r, e := anonymous.Post(ingress+"/v1/agent/telemetry", "application/json", bytes.NewReader(frame))
		if e == nil {
			r.Body.Close()
			t.Fatal("missing client certificate accepted")
		}
	} else {
		request(anonymous, "POST", ingress+"/v1/agent/telemetry", frame, "", 403)
		warning := request(anonymous, "GET", op+"/api/auth/session", nil, "", 200)
		if !bytes.Contains(warning, []byte(`"insecureTestMode":true`)) || !bytes.Contains(warning, []byte(`unencrypted_lan_test`)) {
			t.Fatal("HTTP test warning missing")
		}
	}

	approve, _ := json.Marshal(map[string]string{"certificatePEM": string(creds.clientPEM), "label": "Disposable container fixture", "expectedFingerprintSHA256": lantrust.Fingerprint(creds.client.Leaf)})
	request(operator, "POST", op+"/api/lan/agents/approve", approve, "", 403)
	raw := request(operator, "POST", op+"/api/lan/agents/approve", approve, csrf, 201)
	var approved lantrust.Agent
	if json.Unmarshal(raw, &approved) != nil || approved.ID == "" {
		t.Fatal("approval response")
	}
	request(agent, "POST", ingress+"/v1/agent/telemetry", frame, "", 200)
	// Restart loses operator sessions but preserves approvals and ingestion receipt.
	run("docker", "restart", name)
	ready()
	request(operator, "GET", op+"/api/overview", nil, "", 401)
	csrf = login()
	raw = request(operator, "GET", op+"/api/lan/agents", nil, "", 200)
	if !bytes.Contains(raw, []byte(approved.ID)) {
		t.Fatal("approval missing after restart")
	}
	// An identical retransmission is idempotent (same persisted receipt).
	raw = request(agent, "POST", ingress+"/v1/agent/telemetry", frame, "", 200)
	if !bytes.Contains(raw, []byte(`"duplicate":true`)) {
		t.Fatal("persisted receipt missing after restart")
	}
	request(operator, "POST", op+"/api/lan/agents/"+approved.ID+"/revoke", []byte(`{}`), csrf, 200)
	request(agent, "POST", ingress+"/v1/agent/telemetry", frame, "", 403)
	// Recreate against the same named volume: the image filesystem is disposable.
	run("docker", "rm", "-f", name)
	run("docker", args...)
	ready()
	login()
	request(agent, "POST", ingress+"/v1/agent/telemetry", frame, "", 403)
	raw = request(operator, "GET", op+"/api/lan/agents", nil, "", 200)
	if !bytes.Contains(raw, []byte(approved.ID)) {
		t.Fatal("revocation missing after recreation")
	}
	t.Logf("PASS (%s): UI/health/operator auth, agent rejection/approval, durable receipt/revocation, restart/recreation, non-root read-only runtime", profile)
}
