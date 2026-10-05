//go:build linux

package main

import (
	"crypto/tls"
	"encoding/json"
	"localrmm/internal/lanconfig"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparedNamedOperatorProfilesAndRestartRevocation(t *testing.T) {
	for _, profile := range []string{lanconfig.TLS, lanconfig.HTTPTest} {
		t.Run(profile, func(t *testing.T) {
			material, _, _, _ := fixture(t, profile)
			configPath := filepath.Join(filepath.Dir(material.Config.OperatorAuthFile), "lan.json")
			const actor = "operator_0123456789abcdef0123456789abcdef"
			raw, err := json.Marshal(map[string]any{"schemaVersion": "tracebolt.operator-auth.v2", "profile": profile, "operators": []any{map[string]any{"id": actor, "username": "reader", "passwordHash": material.PasswordHash, "capabilities": []string{"read", "restart_service"}}}})
			if err != nil || os.WriteFile(material.Config.OperatorAuthFile, raw, 0600) != nil {
				t.Fatal("synthetic v2 fixture write failed")
			}
			material, err = lanconfig.Load(configPath)
			if err != nil || len(material.Operators) != 1 || material.PasswordHash != "" {
				t.Fatal("protected named material failed to load")
			}
			p, err := prepare(material)
			if err != nil {
				t.Fatal("named profile preparation failed")
			}
			defer p.close()
			call := func(handler http.Handler, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, material.Config.OperatorOrigin+path, strings.NewReader(body))
				r.RemoteAddr = "127.0.0.1:12345"
				if profile == lanconfig.TLS {
					r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
				}
				r.Header.Set("Origin", material.Config.OperatorOrigin)
				r.Header.Set("Content-Type", "application/json")
				if cookie != nil {
					r.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			login := call(p.operator, "POST", "/api/auth/login", `{"username":"reader","password":"fixture-password-only"}`, nil)
			var view struct {
				ActorID      string   `json:"actorId"`
				LoginMode    string   `json:"loginMode"`
				Capabilities []string `json:"capabilities"`
			}
			if login.Code != 200 || json.Unmarshal(login.Body.Bytes(), &view) != nil || view.ActorID != actor || view.LoginMode != "named" || len(view.Capabilities) != 2 {
				t.Fatal("prepared named manager did not authenticate expected actor")
			}
			cookies := login.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Secure != (profile == lanconfig.TLS) {
				t.Fatal("named manager lost profile-specific cookie security")
			}
			if call(p.operator, "GET", "/api/devices", "", cookies[0]).Code != 200 {
				t.Fatal("named read denied")
			}
			p.close()
			restarted, err := prepare(material)
			if err != nil {
				t.Fatal("named manager restart failed")
			}
			defer restarted.close()
			if call(restarted.operator, "GET", "/api/devices", "", cookies[0]).Code != 401 {
				t.Fatal("old named cookie survived manager restart")
			}
		})
	}
}
