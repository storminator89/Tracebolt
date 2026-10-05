package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const namedActorID = "operator_0123456789abcdef0123456789abcdef"
const namedDeviceID = "agent_0123456789abcdef0123456789abcdef"

func namedOperatorFixture(t *testing.T) (operatorFixture, *operatorauth.Manager) {
	t.Helper()
	o := newOperatorFixture(t, 0)
	auth, err := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.RestartService}}}})
	if err != nil {
		t.Fatal("named fixture auth rejected")
	}
	// The server has not received a request yet; install the alternative
	// immutable fixture manager before exercising the normal real TLS boundary.
	o.server.Config.Handler.(*operatorHandler).auth = auth
	return o, auth
}

func TestNamedLANLoginMetadataAndLegacyCompatibility(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	_, v := o.call(t, "GET", "/api/auth/session", nil, "", nil)
	if v["loginMode"] != "named" || v["actorId"] != nil || len(v["capabilities"].([]any)) != 0 {
		t.Fatal("anonymous named view disclosed identity or omitted mode")
	}
	if r, _ := o.call(t, "POST", "/api/auth/login", map[string]string{"password": operatorFixturePassword}, "", nil); r.StatusCode != 400 {
		t.Fatal("missing named username did not fail the strict request schema")
	}
	for _, body := range []map[string]any{
		{"username": "unknown", "password": operatorFixturePassword},
		{"username": "reader", "password": "incorrect-fixture-password"},
	} {
		r, v := o.call(t, "POST", "/api/auth/login", body, "", nil)
		if r.StatusCode != 401 || len(r.Cookies()) != 0 {
			t.Fatal("invalid named login succeeded or issued cookie", r.StatusCode)
		}
		raw, _ := json.Marshal(v)
		if strings.Contains(string(raw), "reader") || strings.Contains(string(raw), "unknown") {
			t.Fatal("credential error disclosed account existence")
		}
	}
	for _, field := range []string{"actorId", "capabilities", "role"} {
		body := map[string]any{"username": "reader", "password": operatorFixturePassword, field: "admin"}
		if r, _ := o.call(t, "POST", "/api/auth/login", body, "", nil); r.StatusCode != 400 {
			t.Fatal("client-supplied authority accepted")
		}
	}
	r, v := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	if r.StatusCode != 200 || v["actorId"] != namedActorID || v["loginMode"] != "named" || len(v["capabilities"].([]any)) != 2 {
		t.Fatal("named login did not return server-derived identity", r.StatusCode)
	}
	if len(r.Cookies()) != 1 || !r.Cookies()[0].Secure || !r.Cookies()[0].HttpOnly {
		t.Fatal("named auth weakened cookie protection")
	}
	_, view := o.call(t, "GET", "/api/auth/session", nil, "", nil)
	if view["actorId"] != namedActorID || view["csrfToken"] != v["csrfToken"] {
		t.Fatal("lookup did not preserve named session authority")
	}
	if r, _ := o.call(t, "GET", "/api/devices", nil, "", nil); r.StatusCode != 200 {
		t.Fatal("named read capability could not read")
	}
	if r, _ := o.call(t, "POST", "/api/auth/logout", map[string]any{}, v["csrfToken"].(string), nil); r.StatusCode != 200 {
		t.Fatal("named account could not log out")
	}
	if r, _ := o.call(t, "GET", "/api/devices", nil, "", nil); r.StatusCode != 401 {
		t.Fatal("named logout did not revoke access")
	}
	legacy := newOperatorFixture(t, 0)
	_, shared := legacy.login(t)
	if shared["loginMode"] != "shared" || shared["actorId"] != nil || len(shared["capabilities"].([]any)) != 1 || shared["capabilities"].([]any)[0] != "read" {
		t.Fatal("legacy login gained named action authority")
	}
}

func TestNamedReadRoutesDenyAdministrativeWritesButKeepQueries(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	_, v := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	csrf := v["csrfToken"].(string)
	for _, path := range []string{
		"/api/lan/agents/approve", "/api/lan/agents/" + namedDeviceID + "/revoke",
		"/api/enrollment/invitations", "/api/ai/config", "/api/ai/config/clear",
		"/api/cases/case-demo-win-01-service/notes", "/api/cases/case-demo-win-01-service/analyze",
		"/api/security/cves/sync", "/api/security/cves/import", "/api/security/catalog/import",
		"/api/devices/" + namedDeviceID + "/journal/create", "/api/devices/" + namedDeviceID + "/journal/cancel",
		"/api/devices/" + namedDeviceID + "/health/acknowledge", "/api/devices/" + namedDeviceID + "/health/services",
		"/api/devices/" + namedDeviceID + "/inventory/system/query/extra",
	} {
		r, body := o.call(t, "POST", path, map[string]any{}, csrf, nil)
		if r.StatusCode != 403 {
			t.Fatal("named account gained an unrelated administrative operation", path, r.StatusCode, body)
		}
	}
	for _, path := range []string{
		"/api/devices/" + namedDeviceID + "/journal/query",
		"/api/devices/" + namedDeviceID + "/inventory/system/query",
		"/api/devices/" + namedDeviceID + "/inventory/overview/query",
		"/api/devices/" + namedDeviceID + "/inventory/packages/query",
		"/api/devices/" + namedDeviceID + "/inventory/complete-updates/query",
	} {
		// Fixture lacks enrolled data. Reaching the specific handler's 409 is
		// evidence this exact read-only POST was allowed by the role boundary.
		if r, _ := o.call(t, "POST", path, map[string]any{}, csrf, nil); r.StatusCode != 409 {
			t.Fatal("read-only named query was not routed", path, r.StatusCode)
		}
	}
	// The classifier never mistakes a write or arbitrary path suffix for read.
	for _, method := range []string{"PUT", "DELETE", "PATCH"} {
		if namedReadRoute(httptest.NewRequest(method, "/api/devices/"+namedDeviceID+"/journal/query", nil)) {
			t.Fatal("non-read method classified as read")
		}
	}
}

func TestNamedCapabilitySeamRequiresCSRFCurrentSessionAndServerActor(t *testing.T) {
	o, auth := namedOperatorFixture(t)
	s, err := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
	if err != nil {
		t.Fatal("fixture login failed")
	}
	request := func(session operatorauth.Session, active func() bool) *http.Request {
		r := httptest.NewRequest("POST", o.server.URL+"/api/actions/future-only", strings.NewReader(`{}`))
		r.Header.Set("Origin", o.server.URL)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", session.CSRFToken)
		return r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{session: session, origin: o.server.URL, active: active}))
	}
	active := func() bool { _, err := auth.Lookup(s.Token); return err == nil }
	r := request(s, active)
	actor, release, ok := o.app.beginOperatorCapability(httptest.NewRecorder(), r, operatorauth.RestartService)
	if !ok || actor != namedActorID || release == nil {
		t.Fatal("explicit named capability admission failed")
	}
	release()
	for _, cap := range []operatorauth.Capability{operatorauth.ExecuteUpdates, operatorauth.PlanUpdates, operatorauth.Read, "admin"} {
		w := httptest.NewRecorder()
		if _, _, ok := o.app.beginOperatorCapability(w, r, cap); ok || w.Code != 403 {
			t.Fatal("ungranted or non-maintenance capability admitted")
		}
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		func(r *http.Request) { r.Header.Set("Origin", "https://elsewhere.test") },
		func(r *http.Request) { r.Header.Add("X-CSRF-Token", s.CSRFToken) },
	} {
		bad := request(s, active)
		change(bad)
		w := httptest.NewRecorder()
		if _, _, ok := o.app.beginOperatorCapability(w, bad, operatorauth.RestartService); ok || w.Code != 403 {
			t.Fatal("capability bypassed origin or CSRF boundary")
		}
	}
	if _, _, ok := o.app.beginOperatorCapability(httptest.NewRecorder(), httptest.NewRequest("POST", o.server.URL, nil), operatorauth.RestartService); ok {
		t.Fatal("development/missing operator context admitted maintenance")
	}
	auth.Logout(s.Token)
	w := httptest.NewRecorder()
	if _, _, ok := o.app.beginOperatorCapability(w, r, operatorauth.RestartService); ok || w.Code != 401 {
		t.Fatal("revoked capability admitted")
	}
}

func TestNamedHTTPTestKeepsSeparateCookieAndPlaintextWarning(t *testing.T) {
	o, auth := namedOperatorFixture(t)
	h, err := NewLANOperatorHandler(o.app, LANOperatorConfig{Origin: "http://operator.test", Auth: auth, Registry: o.registry, InsecureHTTPTest: true, Devices: func() ([]model.Device, error) { return []model.Device{}, nil }})
	if err != nil {
		t.Fatal("named HTTP-test handler rejected")
	}
	r := httptest.NewRequest("POST", "http://operator.test/api/auth/login", strings.NewReader(`{"username":"reader","password":"`+operatorFixturePassword+`"}`))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Origin", "http://operator.test")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var view authView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || view.LoginMode != "named" || view.Transport != "http" || !view.InsecureTestMode || view.TransportWarning == nil || *view.TransportWarning != "unencrypted_lan_test" {
		t.Fatal("named HTTP-test profile lost visible security warning")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "tracebolt-http-test-session" || cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatal("HTTP-test cookie profile changed")
	}
	wrongCookie := httptest.NewRequest("GET", "http://operator.test/api/devices", nil)
	wrongCookie.AddCookie(&http.Cookie{Name: operatorauth.CookieName, Value: cookies[0].Value})
	denied := httptest.NewRecorder()
	h.ServeHTTP(denied, wrongCookie)
	if denied.Code != 401 {
		t.Fatal("production-named cookie accepted on HTTP-test surface")
	}
	production := o.server.Config.Handler
	plain := httptest.NewRequest("GET", o.server.URL+"/api/auth/session", nil)
	plain.TLS = nil
	denied = httptest.NewRecorder()
	production.ServeHTTP(denied, plain)
	if denied.Code != 403 {
		t.Fatal("production named auth downgraded to HTTP")
	}
}

func TestNamedReadRouteShapeAndCapabilityExpiry(t *testing.T) {
	for _, path := range []string{"/api/devices/not-an-agent/journal/query", "/api/devices/" + namedDeviceID + "/inventory/cached-updates/query", "/api/devices/" + namedDeviceID + "/journal/query/extra"} {
		if namedReadRoute(httptest.NewRequest("POST", path, nil)) {
			t.Fatal("unreviewed query shape classified as read")
		}
	}
	// Expiry must be checked at the admission boundary, not only at request
	// authentication. This exercises a stale context with active lookup bypassed.
	now := time.Now()
	auth, err := operatorauth.New(operatorauth.Config{Now: func() time.Time { return now }, Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.RestartService}}}})
	if err != nil {
		t.Fatal("fixture config")
	}
	s, err := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
	if err != nil {
		t.Fatal("fixture login")
	}
	now = now.Add(operatorauth.DefaultTTL)
	r := httptest.NewRequest("POST", "https://operator.test/api/actions/future-only", nil)
	r.Header.Set("Origin", "https://operator.test")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", s.CSRFToken)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{session: s, origin: "https://operator.test", active: func() bool { return true }}))
	w := httptest.NewRecorder()
	if _, _, ok := setup(t).beginOperatorCapability(w, r, operatorauth.RestartService); ok || w.Code != 401 {
		t.Fatal("expired capability survived authentication-to-dispatch gap")
	}
}
