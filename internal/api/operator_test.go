package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"golang.org/x/crypto/argon2"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const operatorFixturePassword = "synthetic-operator-fixture-only"

var operatorHashOnce sync.Once
var operatorFixtureHash string

func testOperatorHash() string {
	operatorHashOnce.Do(func() {
		salt := []byte("test-operator-salt")
		hash := argon2.IDKey([]byte(operatorFixturePassword), salt, 2, 65536, 1, 32)
		operatorFixtureHash = "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	})
	return operatorFixtureHash
}
func operatorCertificates(t *testing.T) ([]byte, tls.Certificate, []byte, *x509.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ephemeral test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("fixture CA failed")
	}
	ca, _ := x509.ParseCertificate(der)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	makeLeaf := func(serial int64, usage x509.ExtKeyUsage) (tls.Certificate, []byte, *x509.Certificate) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		raw, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal("fixture leaf failed")
		}
		cert, _ := x509.ParseCertificate(raw)
		return tls.Certificate{Certificate: [][]byte{raw, der}, PrivateKey: key, Leaf: cert}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), cert
	}
	server, _, _ := makeLeaf(2, x509.ExtKeyUsageServerAuth)
	_, clientPEM, clientCert := makeLeaf(3, x509.ExtKeyUsageClientAuth)
	return caPEM, server, clientPEM, clientCert
}

type operatorFixture struct {
	app        *Server
	server     *httptest.Server
	client     *http.Client
	registry   *lantrust.Registry
	clientPEM  []byte
	clientCert *x509.Certificate
}

func newOperatorFixture(t *testing.T, ttl time.Duration) operatorFixture {
	t.Helper()
	app := setup(t)
	caPEM, serverPair, clientPEM, clientCert := operatorCertificates(t)
	registry, err := lantrust.NewRegistry(context.Background(), caPEM, lantrust.NewMemoryStore())
	if err != nil {
		t.Fatal("fixture registry failed")
	}
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: testOperatorHash(), TTL: ttl})
	if err != nil {
		t.Fatal("fixture auth failed")
	}
	server := httptest.NewUnstartedServer(nil)
	handler, err := NewLANOperatorHandler(app, LANOperatorConfig{Origin: "https://" + server.Listener.Addr().String(), Auth: auth, Registry: registry, Devices: func() ([]model.Device, error) { return []model.Device{}, nil }})
	if err != nil {
		t.Fatal("fixture operator boundary failed")
	}
	server.Config.Handler = handler
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair}}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	client.Timeout = 5 * time.Second
	_ = os.WriteFile(filepath.Join(app.web, "index.html"), []byte("fixture app shell"), 0600)
	return operatorFixture{app, server, client, registry, clientPEM, clientCert}
}
func (o operatorFixture) call(t *testing.T, method, path string, body any, csrf string, change func(*http.Request)) (*http.Response, map[string]any) {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	r, err := http.NewRequest(method, o.server.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal("request setup failed")
	}
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", o.server.URL)
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
	}
	if change != nil {
		change(r)
	}
	response, err := o.client.Do(r)
	if err != nil {
		t.Fatal("TLS fixture request failed")
	}
	defer response.Body.Close()
	var value map[string]any
	_ = json.NewDecoder(response.Body).Decode(&value)
	return response, value
}
func (o operatorFixture) login(t *testing.T) (*http.Response, map[string]any) {
	t.Helper()
	r, v := o.call(t, "POST", "/api/auth/login", map[string]string{"password": operatorFixturePassword}, "", nil)
	if r.StatusCode != 200 {
		t.Fatal("fixture login rejected", r.StatusCode)
	}
	return r, v
}
func TestLANOperatorRealTLSLoginCookieCSRFAndLogout(t *testing.T) {
	o := newOperatorFixture(t, 0)
	_, v := o.call(t, "GET", "/api/auth/session", nil, "", nil)
	if v["mode"] != "lan" || v["authenticationRequired"] != true || v["authenticated"] != false || v["csrfToken"] != nil {
		t.Fatal("unauthenticated bootstrap not explicit")
	}
	if r, _ := o.call(t, "GET", "/api/devices", nil, "", nil); r.StatusCode != 401 {
		t.Fatal("unauthenticated API readable")
	}
	login, v := o.login(t)
	csrf := v["csrfToken"].(string)
	cookies := login.Cookies()
	if len(cookies) != 1 || cookies[0].Name != operatorauth.CookieName || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" || cookies[0].Domain != "" {
		t.Fatal("session cookie policy incorrect")
	}
	serialized, _ := json.Marshal(v)
	if strings.Contains(string(serialized), cookies[0].Value) || strings.Contains(string(serialized), operatorFixturePassword) {
		t.Fatal("credential leaked in JSON")
	}
	if v["serverNow"] == nil || v["expiresAt"] == nil || v["expiresInSeconds"].(float64) <= 0 {
		t.Fatal("expiry semantics missing")
	}
	if r, v := o.call(t, "GET", "/api/devices", nil, "", nil); r.StatusCode != 200 || v["total"] != float64(0) {
		t.Fatal("LAN device source fell back to demo/local data")
	}
	if r, _ := o.call(t, "POST", "/api/cases/case-demo-win-01-service/notes", map[string]string{"text": "fixture operator note"}, o.app.csrf, nil); r.StatusCode != 403 {
		t.Fatal("development CSRF accepted on LAN")
	}
	if r, _ := o.call(t, "POST", "/api/cases/case-demo-win-01-service/notes", map[string]string{"text": "fixture operator note"}, csrf, nil); r.StatusCode != 200 {
		t.Fatal("authenticated mutation failed")
	}
	if r, _ := o.call(t, "POST", "/api/dev/telemetry", map[string]any{}, csrf, nil); r.StatusCode != 404 {
		t.Fatal("developer ingress reachable on LAN")
	}
	logout, v := o.call(t, "POST", "/api/auth/logout", map[string]any{}, csrf, nil)
	if logout.StatusCode != 200 || v["authenticated"] != false || logout.Cookies()[0].MaxAge != -1 {
		t.Fatal("logout did not clear session")
	}
	o.client.Jar = nil
	if r, _ := o.call(t, "GET", "/api/devices", nil, "", func(r *http.Request) { r.AddCookie(cookies[0]) }); r.StatusCode != 401 {
		t.Fatal("logged-out session reused")
	}
}
func TestLANOperatorOriginCookieAmbiguityAndNoDevBypass(t *testing.T) {
	o := newOperatorFixture(t, 0)
	if r, _ := o.call(t, "POST", "/api/auth/login", map[string]string{"password": operatorFixturePassword}, "", func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }); r.StatusCode != 403 {
		t.Fatal("foreign login origin accepted")
	}
	if r, _ := o.call(t, "POST", "/api/auth/login", map[string]string{"password": operatorFixturePassword}, "", func(r *http.Request) {
		r.Header.Set("Cookie", operatorauth.CookieName+"=a; "+operatorauth.CookieName+"=b")
	}); r.StatusCode != 400 {
		t.Fatal("ambiguous cookies accepted")
	}
	direct := request(o.app, "GET", "/api/devices", "", nil)
	if direct.Code != 403 {
		t.Fatal("underlying dev handler bypassed LAN boundary")
	}
	r := httptest.NewRequest("GET", o.server.URL+"/api/auth/session", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Host = strings.TrimPrefix(o.server.URL, "https://")
	w := httptest.NewRecorder()
	o.server.Config.Handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("forwarded header substituted for real TLS")
	}
}
func TestLANOperatorPublicCertificateApprovalRequiresFingerprint(t *testing.T) {
	o := newOperatorFixture(t, 0)
	_, v := o.login(t)
	csrf := v["csrfToken"].(string)
	body := map[string]string{"certificatePEM": string(o.clientPEM), "label": "Fixture Linux agent", "expectedFingerprintSHA256": strings.Repeat("0", 64)}
	if r, _ := o.call(t, "POST", "/api/lan/agents/approve", body, csrf, nil); r.StatusCode != 400 {
		t.Fatal("wrong fingerprint approval accepted")
	}
	body["expectedFingerprintSHA256"] = lantrust.Fingerprint(o.clientCert)
	r, agent := o.call(t, "POST", "/api/lan/agents/approve", body, csrf, nil)
	if r.StatusCode != 201 || !strings.HasPrefix(agent["id"].(string), "agent_") {
		t.Fatal("manual public certificate approval failed")
	}
	if r, _ := o.call(t, "POST", "/api/lan/agents/"+agent["id"].(string)+"/revoke", map[string]any{}, csrf, nil); r.StatusCode != 200 {
		t.Fatal("operator revocation failed")
	}
	if o.registry.List()[0].RevokedAt.IsZero() {
		t.Fatal("revocation not recorded")
	}
}
func TestLANOperatorExpiryAndFreshLoginRotation(t *testing.T) {
	o := newOperatorFixture(t, time.Second)
	first, _ := o.login(t)
	old := first.Cookies()[0]
	second, _ := o.login(t)
	if second.Cookies()[0].Value == old.Value {
		t.Fatal("login did not rotate cookie")
	}
	time.Sleep(1100 * time.Millisecond)
	r, v := o.call(t, "GET", "/api/auth/session", nil, "", nil)
	if r.StatusCode != 200 || v["authenticated"] != false {
		t.Fatal("expired session still authenticated")
	}
}
