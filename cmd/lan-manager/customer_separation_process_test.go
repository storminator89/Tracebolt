//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/lanconfig"
)

// This test uses two actual Linux manager subprocesses, not two mocked customer
// handlers. All keys, passwords and state are disposable fixture material. It
// changes no OS trust, services, host permissions or endpoint grants and collects
// no host telemetry. Two same-host processes do not isolate against that host's
// administrator. The private stopped-state copies below are not restore or
// rollback-freshness acceptance.
func TestCustomerSeparateManagerProcesses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "lan-manager")
	build := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", binary, ".")
	if build.Run() != nil {
		t.Fatal("customer separation manager build failed")
	}
	a := newCustomerManagerProcess(t, binary, "1")
	b := newCustomerManagerProcess(t, binary, "2")
	assertCustomerManagerMaterialSeparation(t, a, b)
	a.start(t)
	b.start(t)

	// Identical organizational labels are allowed, but they confer no shared
	// catalog or identity. All mutations go through the actual authenticated API.
	a.assertCatalog(t, nil)
	b.assertCatalog(t, nil)
	a.login(t)
	b.login(t)
	aID := a.create(t, "Same customer label")
	b.assertCatalog(t, []customerProcessRow{})
	bID := b.create(t, "Same customer label")
	if aID == bID {
		t.Fatal("independent customer identifiers unexpectedly equal")
	}
	a.assertCatalog(t, []customerProcessRow{{aID, "Same customer label", 1}})
	b.assertCatalog(t, []customerProcessRow{{bID, "Same customer label", 1}})

	// A caller using B's valid session cannot use A's customer ID as a rename
	// capability. The attempted write must neither create nor change B's catalog.
	status, _, _ := b.request(t, "POST", "/api/customers/"+aID, map[string]any{"name": "Foreign rename", "expectedRevision": 1}, b.cookie, b.csrf)
	if status != http.StatusConflict {
		t.Fatal("foreign customer identifier was not rejected")
	}
	b.assertCatalog(t, []customerProcessRow{{bID, "Same customer label", 1}})
	status, _, _ = a.request(t, "POST", "/api/customers/"+bID, map[string]any{"name": "Foreign rename", "expectedRevision": 1}, a.cookie, a.csrf)
	if status != http.StatusConflict {
		t.Fatal("reverse foreign customer identifier was not rejected")
	}

	// Both transports trust the intended server. These failures therefore test
	// session/CSRF separation, rather than relying on the separate CA rejection.
	for _, pair := range [][2]*customerManagerProcess{{a, b}, {b, a}} {
		source, target := pair[0], pair[1]
		status, _, _ = target.request(t, "GET", "/api/customers", nil, source.cookie, "")
		if status != http.StatusUnauthorized {
			t.Fatal("foreign operator session accepted")
		}
		status, _, _ = target.request(t, "POST", "/api/customers", map[string]any{"name": "Foreign CSRF", "expectedRevision": 0}, target.cookie, source.csrf)
		if status != http.StatusForbidden {
			t.Fatal("foreign CSRF token accepted")
		}
		status, _, _ = target.request(t, "POST", "/api/auth/login", map[string]string{"password": source.password}, nil, "")
		if status != http.StatusUnauthorized {
			t.Fatal("foreign operator password accepted")
		}
		assertCustomerServerTrustRejected(t, source, target)
		assertCustomerAgentTrustSeparation(t, source, target)
	}

	status, _, _ = a.request(t, "POST", "/api/customers/"+aID, map[string]any{"name": "Only instance A changed", "expectedRevision": 1}, a.cookie, a.csrf)
	if status != http.StatusOK {
		t.Fatal("own customer rename failed")
	}
	aRows := []customerProcessRow{{aID, "Only instance A changed", 2}}
	bRows := []customerProcessRow{{bID, "Same customer label", 1}}
	a.assertCatalog(t, aRows)
	b.assertCatalog(t, bRows)
	a.assertNoEnrollmentGrant(t)
	b.assertNoEnrollmentGrant(t)
	aCookie, bCookie := a.cookie, b.cookie
	a.stop(t)
	b.stop(t)

	// Copy only cleanly stopped, bounded private fixture trees into two distinct
	// private backup directories. Reject links/special files, retain byte parity,
	// and prove copies do not alias the live tree or each other's key/state files.
	aBackup := filepath.Join(t.TempDir(), "instance-a")
	bBackup := filepath.Join(t.TempDir(), "instance-b")
	aSnapshot := copyCustomerPrivateFixture(t, a.root, aBackup)
	bSnapshot := copyCustomerPrivateFixture(t, b.root, bBackup)
	assertCustomerBackupSeparation(t, a, b, aBackup, bBackup)

	a.start(t)
	b.start(t)
	for _, item := range []struct {
		manager *customerManagerProcess
		old     *http.Cookie
	}{{a, aCookie}, {b, bCookie}} {
		status, _, _ = item.manager.request(t, "GET", "/api/customers", nil, item.old, "")
		if status != http.StatusUnauthorized {
			t.Fatal("stopped-manager session survived restart")
		}
		item.manager.login(t)
		item.manager.assertNoEnrollmentGrant(t)
	}
	a.assertCatalog(t, aRows)
	b.assertCatalog(t, bRows)
	a.stop(t)
	b.stop(t)
	if !reflect.DeepEqual(aSnapshot, customerPrivateManifest(t, aBackup)) || !reflect.DeepEqual(bSnapshot, customerPrivateManifest(t, bBackup)) {
		t.Fatal("independent restart changed a stopped backup")
	}
}

type customerProcessRow struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision uint64 `json:"revision"`
}

type customerManagerProcess struct {
	binary, root, configPath, enrollmentPath, password string
	config                                             lanconfig.Config
	enrollment                                         enrollmentconfig.Config
	roots                                              *x509.CertPool
	client                                             *http.Client
	cmd                                                *exec.Cmd
	done                                               chan error
	cookie                                             *http.Cookie
	csrf                                               string
}

func newCustomerManagerProcess(t *testing.T, binary, digit string) *customerManagerProcess {
	t.Helper()
	m, enrolled, enrollmentPath := guidedFixture(t, lanconfig.TLS)
	p := &customerManagerProcess{binary: binary, root: filepath.Dir(enrollmentPath), enrollmentPath: enrollmentPath, config: m.Config, password: "disposable-customer-separation-" + digit}
	// testing.T.TempDir's numbered child can be 0755 under its private parent.
	// Make this newly created disposable fixture root explicitly private before
	// starting either process; never alter an existing deployment path.
	if os.Chmod(p.root, 0700) != nil {
		t.Fatal("customer separation private fixture root")
	}
	p.configPath = filepath.Join(p.root, "lan.json")
	raw, err := os.ReadFile(enrollmentPath)
	if err != nil || json.Unmarshal(raw, &p.enrollment) != nil {
		t.Fatal("customer separation fixture enrollment read")
	}
	p.enrollment.InstanceID = "manager_" + strings.Repeat(digit, 32)
	raw, err = json.Marshal(p.enrollment)
	if err != nil || os.WriteFile(enrollmentPath, raw, 0600) != nil {
		t.Fatal("customer separation fixture enrollment write")
	}
	salt := make([]byte, 24)
	if _, err = rand.Read(salt); err != nil {
		t.Fatal("customer separation fixture salt")
	}
	hash := argon2.IDKey([]byte(p.password), salt, 2, 65536, 1, 32)
	verifier := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	raw, err = json.Marshal(map[string]string{"schemaVersion": "tracebolt.operator-auth.v1", "profile": "tls", "passwordHash": verifier})
	if err != nil || os.WriteFile(p.config.OperatorAuthFile, raw, 0600) != nil {
		t.Fatal("customer separation fixture operator material")
	}
	p.roots = x509.NewCertPool()
	if !p.roots.AppendCertsFromPEM([]byte(enrolled.ServerCAPEM())) {
		t.Fatal("customer separation explicit server roots")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: p.roots, MinVersion: tls.VersionTLS13}}
	p.client = &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() {
		p.stop(t)
		transport.CloseIdleConnections()
	})
	return p
}

func (p *customerManagerProcess) start(t *testing.T) {
	t.Helper()
	if p.cmd != nil {
		t.Fatal("customer separation duplicate manager start")
	}
	p.cmd = exec.Command(p.binary, "--lan-config", p.configPath, "--enrollment-config", p.enrollmentPath)
	// The production binary needs only these explicit fixture files. Do not pass
	// the editing environment's credentials, proxy settings or provider variables.
	p.cmd.Env = []string{}
	// Nil output destinations discard child logs; no raw runtime state or fixture
	// secrets are printed even when a check fails.
	if p.cmd.Start() != nil {
		p.cmd = nil
		t.Fatal("customer separation manager start")
	}
	p.done = make(chan error, 1)
	cmd, done := p.cmd, p.done
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err := p.client.Get(p.config.OperatorOrigin + "/api/auth/session")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("customer separation manager readiness")
}

func (p *customerManagerProcess) stop(t *testing.T) {
	t.Helper()
	if p.cmd == nil {
		return
	}
	cmd, done := p.cmd, p.done
	p.cmd, p.done = nil, nil
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case err := <-done:
		if err != nil {
			t.Error("customer separation manager did not stop cleanly")
		}
	case <-time.After(8 * time.Second):
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("customer separation killed manager did not exit")
		}
		t.Error("customer separation manager shutdown timeout")
	}
	p.client.CloseIdleConnections()
}

func (p *customerManagerProcess) request(t *testing.T, method, path string, body any, cookie *http.Cookie, csrf string) (int, []byte, []*http.Cookie) {
	t.Helper()
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal("customer separation request encoding")
		}
	}
	r, err := http.NewRequest(method, p.config.OperatorOrigin+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal("customer separation request construction")
	}
	if method == http.MethodPost {
		r.Header.Set("Origin", p.config.OperatorOrigin)
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := p.client.Do(r)
	if err != nil {
		t.Fatal("customer separation request transport")
	}
	defer response.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(response.Body, 128*1024+1))
	if err != nil || len(raw) > 128*1024 {
		t.Fatal("customer separation response bound")
	}
	return response.StatusCode, raw, response.Cookies()
}

func (p *customerManagerProcess) login(t *testing.T) {
	t.Helper()
	status, raw, cookies := p.request(t, "POST", "/api/auth/login", map[string]string{"password": p.password}, nil, "")
	var session struct{ CSRFToken string }
	if status != http.StatusOK || len(cookies) != 1 || json.Unmarshal(raw, &session) != nil || session.CSRFToken == "" {
		t.Fatal("customer separation own operator login")
	}
	p.cookie, p.csrf = cookies[0], session.CSRFToken
}

func (p *customerManagerProcess) create(t *testing.T, name string) string {
	t.Helper()
	status, raw, _ := p.request(t, "POST", "/api/customers", map[string]any{"name": name, "expectedRevision": 0}, p.cookie, p.csrf)
	var catalog struct {
		SchemaVersion string               `json:"schemaVersion"`
		Customers     []customerProcessRow `json:"customers"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &catalog) != nil || catalog.SchemaVersion != "tracebolt.customers.v1" || len(catalog.Customers) != 1 || catalog.Customers[0].Name != name || catalog.Customers[0].Revision != 1 || !strings.HasPrefix(catalog.Customers[0].ID, "customer_") {
		t.Fatal("customer separation own customer creation")
	}
	return catalog.Customers[0].ID
}

func (p *customerManagerProcess) assertCatalog(t *testing.T, rows []customerProcessRow) {
	t.Helper()
	status, raw, _ := p.request(t, "GET", "/api/customers", nil, p.cookie, "")
	if rows == nil {
		if status != http.StatusUnauthorized {
			t.Fatal("customer catalog exposed without own session")
		}
		return
	}
	var catalog struct {
		SchemaVersion string               `json:"schemaVersion"`
		Customers     []customerProcessRow `json:"customers"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &catalog) != nil || catalog.SchemaVersion != "tracebolt.customers.v1" || !reflect.DeepEqual(catalog.Customers, rows) {
		t.Fatal("customer separation own catalog changed")
	}
}

func (p *customerManagerProcess) assertNoEnrollmentGrant(t *testing.T) {
	t.Helper()
	status, raw, _ := p.request(t, "GET", "/api/enrollment", nil, p.cookie, "")
	var enrollment struct{ Items []json.RawMessage }
	if status != http.StatusOK || json.Unmarshal(raw, &enrollment) != nil || enrollment.Items == nil || len(enrollment.Items) != 0 {
		t.Fatal("customer metadata created an enrollment record")
	}
	status, raw, _ = p.request(t, "GET", "/api/devices", nil, p.cookie, "")
	var devices struct {
		Total *int
		Items []json.RawMessage
	}
	if status != http.StatusOK || json.Unmarshal(raw, &devices) != nil || devices.Total == nil || *devices.Total != 0 || devices.Items == nil || len(devices.Items) != 0 {
		t.Fatal("customer metadata created a device")
	}
}

func assertCustomerServerTrustRejected(t *testing.T, source, target *customerManagerProcess) {
	t.Helper()
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: source.roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get(target.config.OperatorOrigin + "/api/auth/session")
	if response != nil {
		response.Body.Close()
	}
	var authorityError x509.UnknownAuthorityError
	if err == nil || !errors.As(err, &authorityError) {
		t.Fatal("foreign operator server trust did not fail certificate verification")
	}
}

// A locally issued fixture client proves the TLS trust edge without enrolling
// an endpoint or granting collection. Its own issuer reaches HTTP; the other
// manager rejects the same certificate before application admission.
func assertCustomerAgentTrustSeparation(t *testing.T, source, target *customerManagerProcess) {
	t.Helper()
	issuerPEM, err := os.ReadFile(source.enrollment.IssuerCertificateFile)
	if err != nil {
		t.Fatal("customer separation issuer certificate")
	}
	issuerBlock, _ := pem.Decode(issuerPEM)
	if issuerBlock == nil {
		t.Fatal("customer separation issuer encoding")
	}
	issuer, err := x509.ParseCertificate(issuerBlock.Bytes)
	if err != nil {
		t.Fatal("customer separation issuer parsing")
	}
	keyPEM, err := os.ReadFile(source.enrollment.IssuerPrivateKeyFile)
	if err != nil {
		t.Fatal("customer separation issuer key read")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("customer separation issuer key encoding")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal("customer separation issuer key parsing")
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("customer separation temporary client key")
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(900), Subject: pkix.Name{CommonName: "Disposable unregistered separation probe"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, pub, key)
	if err != nil {
		t.Fatal("customer separation temporary client certificate")
	}
	certificate := tls.Certificate{Certificate: [][]byte{der, issuer.Raw}, PrivateKey: private}
	for _, own := range []bool{true, false} {
		manager := target
		if own {
			manager = source
		}
		transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: manager.roots, MinVersion: tls.VersionTLS13, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &certificate, nil }}}
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		response, requestErr := client.Get(manager.config.AgentOrigin + "/api/customer-separation-probe")
		if response != nil {
			response.Body.Close()
		}
		transport.CloseIdleConnections()
		if own && (requestErr != nil || response == nil) {
			t.Fatal("own issuer did not pass the client TLS boundary")
		}
		if !own {
			var remoteError *net.OpError
			if requestErr == nil || !errors.As(requestErr, &remoteError) || remoteError.Op != "remote error" {
				t.Fatal("foreign endpoint issuer did not receive a remote TLS rejection")
			}
		}
	}
}

func assertCustomerManagerMaterialSeparation(t *testing.T, a, b *customerManagerProcess) {
	t.Helper()
	if a.root == b.root || a.config.StateDirectory == b.config.StateDirectory || a.enrollment.InstanceID == b.enrollment.InstanceID || a.config.OperatorOrigin == b.config.OperatorOrigin || a.config.AgentOrigin == b.config.AgentOrigin || a.enrollment.ExpectedIssuerFingerprint == b.enrollment.ExpectedIssuerFingerprint {
		t.Fatal("manager fixture bindings are not independent")
	}
	for _, paths := range [][2]string{{a.config.TLSPrivateKeyFile, b.config.TLSPrivateKeyFile}, {a.config.TLSCertificateFile, b.config.TLSCertificateFile}, {a.config.OperatorAuthFile, b.config.OperatorAuthFile}, {a.enrollment.IssuerPrivateKeyFile, b.enrollment.IssuerPrivateKeyFile}, {a.enrollment.IssuerRootFile, b.enrollment.IssuerRootFile}, {a.enrollment.BootstrapServerCAFile, b.enrollment.BootstrapServerCAFile}, {a.config.AgentClientCAFile, b.config.AgentClientCAFile}} {
		left, e1 := os.ReadFile(paths[0])
		right, e2 := os.ReadFile(paths[1])
		li, e3 := os.Stat(paths[0])
		ri, e4 := os.Stat(paths[1])
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || bytes.Equal(left, right) || os.SameFile(li, ri) || li.Mode().Perm() != 0600 || ri.Mode().Perm() != 0600 {
			t.Fatal("manager key, trust or operator files share material")
		}
	}
}

func customerPrivateManifest(t *testing.T, root string) map[string][32]byte {
	t.Helper()
	manifest := map[string][32]byte{}
	total := int64(0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if info.Mode().Perm() != 0700 {
				t.Fatal("customer fixture directory is not private")
			}
			return nil
		}
		stat, hasStat := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !hasStat || stat.Nlink != 1 || info.Mode().Perm() != 0600 || info.Size() > 16*1024*1024 || len(manifest) >= 128 {
			t.Fatal("customer private fixture file outside bounded regular-file policy")
		}
		total += info.Size()
		if total > 32*1024*1024 {
			t.Fatal("customer private fixture exceeds backup bound")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		manifest[relative] = sha256.Sum256(data)
		return nil
	})
	if err != nil || len(manifest) == 0 {
		t.Fatal("customer private fixture manifest failed")
	}
	return manifest
}

func copyCustomerPrivateFixture(t *testing.T, source, target string) map[string][32]byte {
	t.Helper()
	before := customerPrivateManifest(t, source)
	if os.Mkdir(target, 0700) != nil {
		t.Fatal("customer backup root creation")
	}
	for relative, expected := range before {
		from, to := filepath.Join(source, relative), filepath.Join(target, relative)
		if os.MkdirAll(filepath.Dir(to), 0700) != nil {
			t.Fatal("customer backup private parent creation")
		}
		data, err := os.ReadFile(from)
		if err != nil || sha256.Sum256(data) != expected {
			t.Fatal("customer stopped fixture changed during backup")
		}
		file, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("customer backup exclusive file creation")
		}
		_, writeErr := file.Write(data)
		syncErr, closeErr := file.Sync(), file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			t.Fatal("customer backup file copy")
		}
		original, e1 := os.Stat(from)
		copied, e2 := os.Stat(to)
		if e1 != nil || e2 != nil || os.SameFile(original, copied) {
			t.Fatal("customer backup aliased original file")
		}
	}
	if !reflect.DeepEqual(before, customerPrivateManifest(t, source)) || !reflect.DeepEqual(before, customerPrivateManifest(t, target)) {
		t.Fatal("customer backup bytes differ from stopped fixture")
	}
	return before
}

func assertCustomerBackupSeparation(t *testing.T, a, b *customerManagerProcess, aBackup, bBackup string) {
	t.Helper()
	if aBackup == bBackup || aBackup == a.root || bBackup == b.root {
		t.Fatal("customer backup roots alias")
	}
	for _, paths := range [][2]string{{a.config.TLSPrivateKeyFile, b.config.TLSPrivateKeyFile}, {a.enrollment.IssuerPrivateKeyFile, b.enrollment.IssuerPrivateKeyFile}, {a.config.OperatorAuthFile, b.config.OperatorAuthFile}, {a.enrollmentPath, b.enrollmentPath}, {filepath.Join(a.config.StateDirectory, enrollmentconfig.ModeFile), filepath.Join(b.config.StateDirectory, enrollmentconfig.ModeFile)}} {
		aRelative, e1 := filepath.Rel(a.root, paths[0])
		bRelative, e2 := filepath.Rel(b.root, paths[1])
		left, e3 := os.ReadFile(filepath.Join(aBackup, aRelative))
		right, e4 := os.ReadFile(filepath.Join(bBackup, bRelative))
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || bytes.Equal(left, right) {
			t.Fatal("customer backup contains shared identity or authentication material")
		}
	}
}
