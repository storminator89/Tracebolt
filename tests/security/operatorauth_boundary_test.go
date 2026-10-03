package security_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"localrmm/internal/api"
	"localrmm/internal/fixtures"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

const fakeOperatorPassword = "test-only-review-password-never-real"

var operatorReviewHashOnce sync.Once
var operatorReviewHash string

type reviewRevokingBody struct {
	reader io.Reader
	revoke func()
	once   sync.Once
}

func (b *reviewRevokingBody) Read(p []byte) (int, error) {
	b.once.Do(b.revoke)
	return b.reader.Read(p)
}
func (*reviewRevokingBody) Close() error { return nil }

func TestOperatorRejectsLogoutDuringBodyRead(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	devices, cases := fixtures.Seed(time.Now())
	if err = db.Seed(devices, cases); err != nil {
		t.Fatal(err)
	}
	app, err := api.New(db, 8787, t.TempDir(), model.Device{})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: reviewPasswordHash()})
	if err != nil {
		t.Fatal(err)
	}
	ca := makeReviewCA(t)
	registry, err := lantrust.NewRegistry(context.Background(), ca.pem, lantrust.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://operator.test"
	handler, err := api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: origin, Auth: auth, Registry: registry, Devices: func() ([]model.Device, error) { return []model.Device{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.Login(context.Background(), "127.0.0.1", fakeOperatorPassword)
	if err != nil {
		t.Fatal("fake session login failed")
	}
	r := httptest.NewRequest(http.MethodPost, origin+"/api/cases/"+cases[0].ID+"/status", nil)
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", session.CSRFToken)
	r.AddCookie(&http.Cookie{Name: operatorauth.CookieName, Value: session.Token})
	r.Body = &reviewRevokingBody{reader: strings.NewReader(`{"status":"resolved"}`), revoke: func() { auth.Logout(session.Token) }}
	reply := httptest.NewRecorder()
	handler.ServeHTTP(reply, r)
	if reply.Code != http.StatusUnauthorized {
		t.Fatalf("request authorized before body read performed mutation after logout: HTTP %d", reply.Code)
	}
}

func TestOperatorLogoutCancelsOwnedProviderRequest(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	devices, cases := fixtures.Seed(time.Now())
	if err = db.Seed(devices, cases); err != nil {
		t.Fatal(err)
	}
	app, err := api.New(db, 8787, t.TempDir(), model.Device{})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: reviewPasswordHash()})
	if err != nil {
		t.Fatal(err)
	}
	ca := makeReviewCA(t)
	registry, err := lantrust.NewRegistry(context.Background(), ca.pem, lantrust.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://operator.test"
	handler, err := api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: origin, Auth: auth, Registry: registry, Devices: func() ([]model.Device, error) { return []model.Device{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.Login(context.Background(), "127.0.0.1", fakeOperatorPassword)
	if err != nil {
		t.Fatal("fake session login failed")
	}
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, origin+path, bytes.NewReader(raw))
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", session.CSRFToken)
		r.AddCookie(&http.Cookie{Name: operatorauth.CookieName, Value: session.Token})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	started, canceled := make(chan struct{}), make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-time.After(3 * time.Second):
		}
	}))
	defer provider.Close()
	var config map[string]any
	initial := call("GET", "/api/ai/config", nil)
	if initial.Code != 200 || json.Unmarshal(initial.Body.Bytes(), &config) != nil {
		t.Fatal("config read failed")
	}
	saved := call("POST", "/api/ai/config", map[string]any{"expectedRevision": config["revision"], "baseURL": provider.URL + "/v1", "model": "synthetic-model", "apiKey": "", "approvedOrigin": provider.URL, "allowRemoteEvidence": false, "useLegacyMaxTokens": false})
	if saved.Code != 200 || json.Unmarshal(saved.Body.Bytes(), &config) != nil {
		t.Fatalf("fake config status %d", saved.Code)
	}
	completed := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		completed <- call("POST", "/api/cases/"+cases[0].ID+"/analyze", map[string]any{"configRevision": config["revision"]})
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("fake provider not called")
	}
	if loggedOut := call("POST", "/api/auth/logout", map[string]any{}); loggedOut.Code != 200 {
		t.Fatalf("logout status %d", loggedOut.Code)
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("logout left provider network context active")
	}
	select {
	case response := <-completed:
		if response.Code != 401 {
			t.Fatalf("revoked session received analysis response: %d", response.Code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("analysis did not finish after logout")
	}
}

func TestOperatorMutationLeaseLinearizesLogoutAndExpiry(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: reviewPasswordHash(), Now: func() time.Time { return time.Unix(0, clock.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.Login(context.Background(), "127.0.0.1", fakeOperatorPassword)
	if err != nil {
		t.Fatal("fake login failed")
	}
	release, err := session.BeginMutation(context.Background())
	if err != nil {
		t.Fatal("valid lease refused")
	}
	defer release()
	logoutReturned := make(chan struct{})
	go func() { auth.Logout(session.Token); close(logoutReturned) }()
	select {
	case <-session.Lifetime().Done():
	case <-time.After(time.Second):
		t.Fatal("revocation not published")
	}
	if next, e := session.BeginMutation(context.Background()); e == nil {
		next()
		t.Fatal("new mutation admitted after revocation")
	}
	select {
	case <-logoutReturned:
		t.Fatal("logout returned before admitted mutation was released")
	default:
	}
	secondLogoutReturned := make(chan struct{})
	go func() { auth.Logout(session.Token); close(secondLogoutReturned) }()
	select {
	case <-secondLogoutReturned:
		t.Fatal("concurrent logout returned while an admitted mutation was still pending")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	release()
	select {
	case <-logoutReturned:
	case <-time.After(time.Second):
		t.Fatal("logout did not complete after lease release")
	}
	select {
	case <-secondLogoutReturned:
	case <-time.After(time.Second):
		t.Fatal("concurrent logout did not complete after lease release")
	}
	session, err = auth.Login(context.Background(), "127.0.0.1", fakeOperatorPassword)
	if err != nil {
		t.Fatal("second fake login failed")
	}
	clock.Add(int64(operatorauth.DefaultTTL))
	if next, e := session.BeginMutation(context.Background()); e == nil {
		next()
		t.Fatal("expiry admitted mutation from previously looked-up session")
	}
}

func TestOperatorHTTPTestProfileIsExplicitAndCookieDistinct(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	app, err := api.New(db, 8787, t.TempDir(), model.Device{})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: reviewPasswordHash()})
	if err != nil {
		t.Fatal(err)
	}
	ca := makeReviewCA(t)
	registry, err := lantrust.NewRegistry(context.Background(), ca.pem, lantrust.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	origin := "http://127.0.0.1:18878"
	config := api.LANOperatorConfig{Origin: origin, Auth: auth, Registry: registry, Devices: func() ([]model.Device, error) { return []model.Device{}, nil }}
	if _, err = api.NewLANOperatorHandler(app, config); err == nil {
		t.Fatal("HTTP accepted without explicit test mode")
	}
	config.InsecureHTTPTest = true
	handler, err := api.NewLANOperatorHandler(app, config)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, body io.Reader, cookie *http.Cookie, asTLS bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, origin+path, body)
		r.RemoteAddr = "127.0.0.1:50123"
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if asTLS {
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := call("GET", "/api/auth/session", nil, nil, false)
	var view map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || view["transport"] != "http" || view["insecureTestMode"] != true || view["transportWarning"] != "unencrypted_lan_test" {
		t.Fatal("plaintext test warning missing before login")
	}
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HTTP test profile asserted HSTS")
	}
	body, _ := json.Marshal(map[string]string{"password": fakeOperatorPassword})
	w = call("POST", "/api/auth/login", bytes.NewReader(body), nil, false)
	if w.Code != 200 {
		t.Fatal("synthetic HTTP-test login failed")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing test session cookie")
	}
	cookie := cookies[0]
	if cookie.Name != "tracebolt-http-test-session" || cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Domain != "" {
		t.Fatal("plaintext cookie separation failed")
	}
	if call("GET", "/api/cases", nil, &http.Cookie{Name: operatorauth.CookieName, Value: cookie.Value}, false).Code != 401 {
		t.Fatal("TLS cookie name authorized HTTP test mode")
	}
	if call("GET", "/api/cases", nil, cookie, false).Code != 200 {
		t.Fatal("test cookie rejected")
	}
	if call("GET", "/api/auth/session", nil, cookie, true).Code != 403 {
		t.Fatal("HTTP test handler accepted TLS as fallback")
	}
}

func reviewPasswordHash() string {
	operatorReviewHashOnce.Do(func() {
		salt := []byte("fake-review-salt-")
		hash := argon2.IDKey([]byte(fakeOperatorPassword), salt, 2, 65536, 1, 32)
		operatorReviewHash = fmt.Sprintf("$argon2id$v=19$m=65536,t=2,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash))
	})
	return operatorReviewHash
}

func TestOperatorAuthPublicSecretsAndExpiry(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	config := operatorauth.Config{PasswordHash: reviewPasswordHash(), Now: func() time.Time { return time.Unix(0, clock.Load()) }}
	manager, err := operatorauth.New(config)
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.Login(context.Background(), "127.0.0.1", fakeOperatorPassword)
	if err != nil {
		t.Fatal("fake login failed")
	}
	for _, value := range []any{session, config, manager, reflect.ValueOf(manager).Elem().Interface()} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			formatted := fmt.Sprintf(format, value)
			if !strings.Contains(formatted, "secrets:redacted") {
				t.Errorf("secret-bearing type lacks value-safe formatter for %s", format)
			}
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), session.Token) || strings.Contains(string(raw), session.CSRFToken) || strings.Contains(string(raw), reviewPasswordHash()) {
			t.Fatal("secret exposed in public JSON")
		}
	}
	if found, err := manager.Lookup(session.Token); err != nil || found.Token != "" {
		t.Fatal("session map retained token or lookup failed")
	}
	clock.Add(int64(operatorauth.DefaultTTL))
	if _, err = manager.Lookup(session.Token); err == nil {
		t.Fatal("expired operator session remained valid")
	}
}

func TestOperatorSurfaceRealTLSCookieAndCSRFGates(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	devices, cases := fixtures.Seed(time.Now())
	if err = db.Seed(devices, cases); err != nil {
		t.Fatal(err)
	}
	app, err := api.New(db, 8787, t.TempDir(), model.Device{})
	if err != nil {
		t.Fatal(err)
	}
	devRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/api/session", nil)
	devRequest.RemoteAddr = "127.0.0.1:50000"
	devReply := httptest.NewRecorder()
	app.ServeHTTP(devReply, devRequest)
	var devSession map[string]string
	if err = json.Unmarshal(devReply.Body.Bytes(), &devSession); err != nil {
		t.Fatal(err)
	}
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: reviewPasswordHash()})
	if err != nil {
		t.Fatal(err)
	}
	ca := makeReviewCA(t)
	registry, err := lantrust.NewRegistry(context.Background(), ca.pem, lantrust.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	handler, err := api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: origin, Auth: auth, Registry: registry, Devices: func() ([]model.Device, error) { return []model.Device{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	pair, _ := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Time{})
	server.Config.Handler = handler
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.pem)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 3 * time.Second}
	call := func(method, path string, body any, csrf, selectedOrigin string) (*http.Response, map[string]any) {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, origin+path, bytes.NewReader(raw))
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if selectedOrigin != "" {
			req.Header.Set("Origin", selectedOrigin)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err = json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
		return response, result
	}
	if response, _ := call("GET", "/api/cases", nil, "", ""); response.StatusCode != 401 {
		t.Fatal("unauthenticated data access")
	}
	if response, _ := call("POST", "/api/auth/login", map[string]any{"password": fakeOperatorPassword}, "", ""); response.StatusCode != 403 {
		t.Fatal("login without exact origin")
	}
	if response, _ := call("POST", "/api/auth/login", map[string]any{"password": fakeOperatorPassword}, "", "https://evil.invalid"); response.StatusCode != 403 {
		t.Fatal("foreign origin login")
	}
	response, login := call("POST", "/api/auth/login", map[string]any{"password": fakeOperatorPassword}, "", origin)
	if response.StatusCode != 200 || login["authenticated"] != true {
		t.Fatal("valid fake TLS login failed")
	}
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatal("unexpected session cookie count")
	}
	cookie := cookies[0]
	if cookie.Name != operatorauth.CookieName || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Domain != "" || cookie.Path != "/" {
		t.Fatal("session cookie lacks required properties")
	}
	csrf, ok := login["csrfToken"].(string)
	if !ok || csrf == "" {
		t.Fatal("missing per-session CSRF")
	}
	if response, _ = call("GET", "/api/cases", nil, "", ""); response.StatusCode != 200 {
		t.Fatal("authenticated read failed")
	}
	path := "/api/cases/" + cases[0].ID + "/status"
	if response, _ = call("POST", path, map[string]any{"status": "investigating"}, devSession["csrfToken"], origin); response.StatusCode != 403 {
		t.Fatal("development CSRF token bypassed LAN session")
	}
	if response, _ = call("POST", path, map[string]any{"status": "investigating"}, csrf, ""); response.StatusCode != 403 {
		t.Fatal("write accepted absent origin")
	}
	if response, _ = call("POST", path, map[string]any{"status": "investigating"}, csrf, origin); response.StatusCode != 200 {
		t.Fatal("authenticated CSRF write failed")
	}
	if response, _ = call("GET", "/api/dev/telemetry/status", nil, "", ""); response.StatusCode != 404 {
		t.Fatal("dev telemetry exposed on operator surface")
	}
	// The original development handler must remain unusable after wrapping.
	disabled := httptest.NewRecorder()
	app.ServeHTTP(disabled, devRequest)
	if disabled.Code != 403 {
		t.Fatal("underlying dev handler bypassed operator boundary")
	}
	plain := httptest.NewRequest("GET", origin+"/api/cases", nil)
	plain.Host = server.Listener.Addr().String()
	plain.Header.Set("X-Forwarded-Proto", "https")
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, plain)
	if denied.Code != 403 {
		t.Fatal("forwarded header replaced actual TLS")
	}
	if response, _ = call("POST", "/api/auth/logout", map[string]any{}, csrf, origin); response.StatusCode != 200 {
		t.Fatal("logout failed")
	}
	if response, _ = call("GET", "/api/cases", nil, "", ""); response.StatusCode != 401 {
		t.Fatal("logout left protected data accessible")
	}
}
