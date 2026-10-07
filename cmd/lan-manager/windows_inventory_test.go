//go:build linux

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanconfig"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The handler is called directly. No manager listener or Windows host is started.
func windowsOperatorCall(t *testing.T, p *prepared, m lanconfig.Material, method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, m.Config.OperatorOrigin+path, bytes.NewReader(raw))
	r.RequestURI = path
	r.RemoteAddr = "127.0.0.1:44000"
	if m.Config.Profile == lanconfig.TLS {
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	} else {
		r.TLS = nil
	}
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", m.Config.OperatorOrigin)
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	p.operator.ServeHTTP(w, r)
	return w
}
func TestWindowsManagerExplicitSidecarProfileAndOperatorConsent(t *testing.T) {
	for _, profile := range []string{lanconfig.TLS, lanconfig.HTTPTest} {
		t.Run(profile, func(t *testing.T) {
			m, _, configPath := guidedFixture(t, profile)
			var cfg enrollmentconfig.Config
			raw, _ := os.ReadFile(configPath)
			if json.Unmarshal(raw, &cfg) != nil {
				t.Fatal("fixture config")
			}
			cfg.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
			raw, _ = json.Marshal(cfg)
			if os.WriteFile(configPath, raw, 0600) != nil {
				t.Fatal("fixture write")
			}
			material, err := enrollmentconfig.Load(configPath, m, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			p, err := prepareWithEnrollment(m, &material)
			if err != nil {
				t.Fatal("Linux primary setup", err)
			}
			if _, err = os.Stat(filepath.Join(m.Config.StateDirectory, enrollmentconfig.WindowsDatabaseFile)); !os.IsNotExist(err) {
				t.Fatal("Windows scope created without opt-in")
			}
			p.close()
			before, _ := os.ReadFile(filepath.Join(m.Config.StateDirectory, enrollmentconfig.ModeFile))
			m.Config.WindowsInventoryEnabled = true
			material, err = enrollmentconfig.Load(configPath, m, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			p, err = prepareWithEnrollment(m, &material)
			if err != nil {
				t.Fatal("Windows sidecar setup", err)
			}
			defer p.close()
			after, _ := os.ReadFile(filepath.Join(m.Config.StateDirectory, enrollmentconfig.ModeFile))
			if !bytes.Equal(before, after) {
				t.Fatal("Windows opt-in changed Linux authority marker")
			}
			if material.StoreConfig().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
				t.Fatal("Linux profile reinterpreted")
			}
			if _, err = os.Stat(filepath.Join(m.Config.StateDirectory, enrollmentconfig.WindowsDatabaseFile)); err != nil {
				t.Fatal("separate Windows store missing")
			}
			if w := windowsOperatorCall(t, p, m, "GET", "/api/windows/enrollment", nil, nil, ""); w.Code != 401 {
				t.Fatal("Windows enrollment bypassed session", w.Code)
			}
			login := windowsOperatorCall(t, p, m, "POST", "/api/auth/login", map[string]string{"password": "fixture-password-only"}, nil, "")
			if login.Code != 200 {
				t.Fatal("fixture login", login.Code)
			}
			var auth map[string]any
			if json.Unmarshal(login.Body.Bytes(), &auth) != nil {
				t.Fatal("fixture auth")
			}
			cookie := login.Result().Cookies()[0]
			csrf := auth["csrfToken"].(string)
			listing := windowsOperatorCall(t, p, m, "GET", "/api/windows/enrollment", nil, cookie, "")
			var list map[string]any
			if listing.Code != 200 || json.Unmarshal(listing.Body.Bytes(), &list) != nil || list["enabled"] != true || list["collectionProfile"] != enrollmentcrypto.CollectionProfileWindowsInventory || list["collectionPrivacy"] != "windows_inventory_metadata_may_be_sensitive" {
				t.Fatal("Windows consent profile not exposed", listing.Code)
			}
			body := map[string]any{"requestId": fmt.Sprintf("request_%032x", 10), "platform": "windows", "collectionAcknowledged": true, "insecureHTTPAcknowledged": profile == lanconfig.HTTPTest}
			if w := windowsOperatorCall(t, p, m, "POST", "/api/windows/enrollment/invitations", body, cookie, ""); w.Code != 403 {
				t.Fatal("Windows creation bypassed CSRF", w.Code)
			}
			body["collectionAcknowledged"] = false
			if w := windowsOperatorCall(t, p, m, "POST", "/api/windows/enrollment/invitations", body, cookie, csrf); w.Code != 400 {
				t.Fatal("Windows collection consent bypassed", w.Code)
			}
			body["collectionAcknowledged"] = true
			body["insecureHTTPAcknowledged"] = profile != lanconfig.HTTPTest
			if w := windowsOperatorCall(t, p, m, "POST", "/api/windows/enrollment/invitations", body, cookie, csrf); w.Code != 400 {
				t.Fatal("Windows exact transport acknowledgement bypassed", w.Code)
			}
			body["insecureHTTPAcknowledged"] = profile == lanconfig.HTTPTest
			created := windowsOperatorCall(t, p, m, "POST", "/api/windows/enrollment/invitations", body, cookie, csrf)
			if created.Code != 201 {
				t.Fatal("Windows invitation failed", created.Code, created.Body.String())
			}
			var response struct {
				Snapshot struct {
					Platform string
					Binding  struct {
						CollectionProfile string `json:"collectionProfile"`
					}
				}
				Bootstrap struct {
					CollectionProfile string `json:"collectionProfile"`
				}
			}
			if json.Unmarshal(created.Body.Bytes(), &response) != nil || response.Snapshot.Platform != "windows" || response.Snapshot.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || response.Bootstrap.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
				t.Fatal("Windows response profile binding lost")
			}
			old := windowsOperatorCall(t, p, m, "GET", "/api/enrollment", nil, cookie, "")
			var primary map[string]any
			if old.Code != 200 || json.Unmarshal(old.Body.Bytes(), &primary) != nil || primary["collectionProfile"] != enrollmentcrypto.CollectionProfileComplete || len(primary["items"].([]any)) != 0 {
				t.Fatal("Windows invitation entered Linux store")
			}
			if w := windowsOperatorCall(t, p, m, "GET", "/api/devices/agent_00000000000000000000000000000001/windows-inventory", nil, nil, ""); w.Code != 401 {
				t.Fatal("inventory read bypassed session", w.Code)
			}
			p.close()
			p, err = prepareWithEnrollment(m, &material)
			if err != nil {
				t.Fatal("Windows store reopen", err)
			}
			p.close()
		})
	}
}

func TestWindowsInventoryCannotReplacePrimaryEnrollmentBinding(t *testing.T) {
	for _, profile := range []string{lanconfig.TLS, lanconfig.HTTPTest} {
		m, _, path := guidedFixture(t, profile)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var c enrollmentconfig.Config
		if json.Unmarshal(raw, &c) != nil {
			t.Fatal("fixture config")
		}
		c.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
		raw, _ = json.Marshal(c)
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("fixture config write")
		}
		for _, enabled := range []bool{false, true} {
			m.Config.WindowsInventoryEnabled = enabled
			if _, err = enrollmentconfig.Load(path, m, time.Now().UTC()); err == nil {
				t.Fatal("Windows profile admitted as primary authority")
			}
		}
		if _, err = os.Stat(filepath.Join(m.Config.StateDirectory, enrollmentconfig.WindowsDatabaseFile)); !os.IsNotExist(err) {
			t.Fatal("rejected primary config initialized Windows state")
		}
	}
}
