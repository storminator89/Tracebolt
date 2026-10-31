package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"localrmm/internal/operatorauth"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sessionManagementFixture(t *testing.T) (operatorFixture, *operatorauth.Manager, operatorauth.Session, operatorauth.Session) {
	t.Helper()
	o := newOperatorFixture(t, 0)
	auth, err := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{
		{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read}},
		{ID: "operator_11111111111111111111111111111111", Username: "session-admin", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ManageSessions}},
	}})
	if err != nil {
		t.Fatal("session fixture configuration rejected")
	}
	o.server.Config.Handler.(*operatorHandler).auth = auth
	reader, err := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
	if err != nil {
		t.Fatal("reader fixture login rejected")
	}
	admin, err := auth.LoginNamed(context.Background(), "127.0.0.2", "session-admin", operatorFixturePassword)
	if err != nil {
		t.Fatal("administrator fixture login rejected")
	}
	return o, auth, reader, admin
}

func sessionCookie(s operatorauth.Session) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: operatorauth.CookieName, Value: s.Token}) }
}

func TestSessionManagementRequiresAuthenticationAndScopesViews(t *testing.T) {
	o, _, reader, admin := sessionManagementFixture(t)
	if r, _ := o.call(t, "GET", "/api/auth/sessions", nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous session listing admitted")
	}
	_, view := o.call(t, "GET", "/api/auth/sessions", nil, "", sessionCookie(reader))
	items, ok := view["items"].([]any)
	if !ok || len(items) != 1 || items[0].(map[string]any)["id"] != reader.ID || view["canManageAll"] != false || view["globalLimit"] != float64(operatorauth.MaxSessions) || view["perActorLimit"] != float64(operatorauth.MaxSessionsPerActor) {
		t.Fatal("reader session view was not account-scoped")
	}
	raw, _ := json.Marshal(view)
	for _, secret := range []string{reader.Token, reader.CSRFToken, admin.Token, admin.ActorID(), admin.ID, "session-admin", testOperatorHash()} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("session view disclosed credential or unrelated account")
		}
	}
	_, all := o.call(t, "GET", "/api/auth/sessions", nil, "", sessionCookie(admin))
	if all["canManageAll"] != true || len(all["items"].([]any)) != 2 {
		t.Fatal("explicit session grant not honored")
	}
	if r, _ := o.call(t, "POST", "/api/auth/sessions", map[string]any{}, reader.CSRFToken, sessionCookie(reader)); r.StatusCode != 405 {
		t.Fatal("unsupported session method admitted")
	}
}

func TestSessionManagementRevocationRequiresExactBodyCSRFAndGrant(t *testing.T) {
	o, auth, reader, admin := sessionManagementFixture(t)
	path := "/api/auth/sessions/revoke"
	body := map[string]string{"sessionId": admin.ID}
	if r, _ := o.call(t, "POST", path, body, "", sessionCookie(reader)); r.StatusCode != 403 {
		t.Fatal("CSRF-free revocation admitted")
	}
	if r, _ := o.call(t, "POST", path, body, reader.CSRFToken, func(r *http.Request) { sessionCookie(reader)(r); r.Header.Set("Origin", "https://other.invalid") }); r.StatusCode != 403 {
		t.Fatal("cross-origin revocation admitted")
	}
	if r, v := o.call(t, "POST", path, body, reader.CSRFToken, sessionCookie(reader)); r.StatusCode != 200 || v["revoked"] != false {
		t.Fatal("reader could revoke or distinguish another account's session")
	}
	if _, err := auth.Lookup(admin.Token); err != nil {
		t.Fatal("denied cross-account revocation changed state")
	}
	for _, invalid := range []map[string]any{
		{"sessionId": reader.ID, "actorId": admin.ActorID()},
		{"sessionId": reader.ID, "manageAll": true},
		{"sessionId": "../" + reader.ID},
		{"sessionId": nil},
		{},
	} {
		if r, _ := o.call(t, "POST", path, invalid, admin.CSRFToken, sessionCookie(admin)); r.StatusCode != 400 {
			t.Fatal("noncanonical or authority-supplying revoke body admitted")
		}
	}
	if r, v := o.call(t, "POST", path, map[string]string{"sessionId": reader.ID}, admin.CSRFToken, sessionCookie(admin)); r.StatusCode != 200 || v["revoked"] != true {
		t.Fatal("session administrator could not revoke exact target")
	}
	if r, _ := o.call(t, "GET", "/api/devices", nil, "", sessionCookie(reader)); r.StatusCode != 401 {
		t.Fatal("revoked cookie retained access")
	}
	if r, v := o.call(t, "POST", path, map[string]string{"sessionId": reader.ID}, admin.CSRFToken, sessionCookie(admin)); r.StatusCode != 200 || v["revoked"] != false {
		t.Fatal("repeated revoke did not reconcile without replay")
	}
	if r, v := o.call(t, "POST", path, map[string]string{"sessionId": admin.ID}, admin.CSRFToken, sessionCookie(admin)); r.StatusCode != 200 || v["revoked"] != true || len(r.Cookies()) != 1 || r.Cookies()[0].MaxAge != -1 {
		t.Fatal("self revocation failed or retained browser cookie")
	}
}

func TestSessionLoginPeerDoesNotTrustForwardedHeaders(t *testing.T) {
	o := newOperatorFixture(t, 0)
	for i := 0; i < 6; i++ {
		r, _ := o.call(t, "POST", "/api/auth/login", map[string]string{"password": "invalid-password-only"}, "", func(r *http.Request) { r.Header.Set("X-Forwarded-For", "192.0.2."+string(rune('1'+i))) })
		if i < 5 && r.StatusCode != 401 || i == 5 && r.StatusCode != 429 {
			t.Fatal("forwarded headers bypassed RemoteAddr-derived peer limit")
		}
	}
}

func TestSessionManagementLegacySharedBoundsAndSelfRevoke(t *testing.T) {
	o := newOperatorFixture(t, 0)
	auth := o.server.Config.Handler.(*operatorHandler).auth
	session, err := auth.Login(context.Background(), "127.0.0.1", operatorFixturePassword)
	if err != nil {
		t.Fatal("shared fixture login failed")
	}
	_, view := o.call(t, "GET", "/api/auth/sessions", nil, "", sessionCookie(session))
	items := view["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["actorId"] != nil || view["perActorLimit"] != float64(operatorauth.MaxSessions) || view["firstSessionReserve"] != float64(0) || view["canManageAll"] != false {
		t.Fatal("shared mode limits or actor mapping changed")
	}
	if r, v := o.call(t, "POST", "/api/auth/sessions/revoke", map[string]string{"sessionId": session.ID}, session.CSRFToken, sessionCookie(session)); r.StatusCode != 200 || v["revoked"] != true {
		t.Fatal("shared account could not revoke itself")
	}
}

func TestSessionRevocationAfterBodyReadRechecksRequestersAuthority(t *testing.T) {
	o, auth, reader, admin := sessionManagementFixture(t)
	h := o.server.Config.Handler.(*operatorHandler)
	r := httptest.NewRequest(http.MethodPost, o.server.URL+"/api/auth/sessions/revoke", nil)
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	r.Header.Set("Origin", o.server.URL)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", admin.CSRFToken)
	sessionCookie(admin)(r)
	body := &gatedAlarmBody{started: make(chan struct{}), allow: make(chan struct{}), reader: strings.NewReader(`{"sessionId":"` + reader.ID + `"}`)}
	r.Body = body
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.ServeHTTP(w, r); close(done) }()
	select {
	case <-body.started:
	case <-time.After(5 * time.Second):
		t.Fatal("revocation body was not read")
	}
	auth.Logout(admin.Token) // Must not block behind a slow, untrusted body reader.
	close(body.allow)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("revoked request did not finish")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatal("request revoked during body read retained authority")
	}
	if _, err := auth.Lookup(reader.Token); err != nil {
		t.Fatal("delayed unauthorized request revoked target")
	}
}
