//go:build linux

package main

import (
	"encoding/json"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanconfig"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAISettingsPreparedKeylessSetupAndOrdinaryRestart(t *testing.T) {
	m, _, path := guidedFixture(t, lanconfig.HTTPTest)
	raw, err := os.ReadFile(path)
	var config enrollmentconfig.Config
	if err != nil || json.Unmarshal(raw, &config) != nil {
		t.Fatal("fixture config")
	}
	config.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	raw, _ = json.Marshal(config)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	enrolled, err := enrollmentconfig.Load(path, m, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	p, err := prepareWithEnrollment(m, &enrolled)
	if err != nil {
		t.Fatal(err)
	}
	var prior string
	for attempt := 0; attempt < 2; attempt++ {
		origin := m.Config.OperatorOrigin
		login := httptest.NewRequest("POST", origin+"/api/auth/login", strings.NewReader(`{"password":"fixture-password-only"}`))
		login.Header.Set("Origin", origin)
		login.Header.Set("Content-Type", "application/json")
		login.RemoteAddr = "127.0.0.1:32100"
		response := httptest.NewRecorder()
		p.operator.ServeHTTP(response, login)
		if response.Code != 200 || len(response.Result().Cookies()) != 1 {
			p.close()
			t.Fatal("fixture login", response.Code)
		}
		var session map[string]any
		if json.Unmarshal(response.Body.Bytes(), &session) != nil {
			p.close()
			t.Fatal("fixture session")
		}
		cookie, csrf := response.Result().Cookies()[0], session["csrfToken"].(string)
		call := func(method, path string, body any) map[string]any {
			t.Helper()
			var raw []byte
			if body != nil {
				raw, _ = json.Marshal(body)
			}
			req := httptest.NewRequest(method, origin+path, strings.NewReader(string(raw)))
			req.AddCookie(cookie)
			req.Header.Set("Origin", origin)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", csrf)
			res := httptest.NewRecorder()
			p.operator.ServeHTTP(res, req)
			var value map[string]any
			if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &value) != nil {
				p.close()
				t.Fatal("fixture request", res.Code, res.Body.String())
			}
			return value
		}
		view := call("GET", "/api/ai/config", nil)
		if view["persistenceAvailable"] != true || view["persistentKeyAllowed"] != false {
			p.close()
			t.Fatal("controller not wired", view)
		}
		if attempt == 0 {
			if view["configured"] != false {
				p.close()
				t.Fatal("default provider active")
			}
			saved := call("POST", "/api/ai/config/persistent", map[string]any{"expectedRevision": view["revision"], "baseURL": "http://127.0.0.1:11434/v1", "model": "fixture-model", "apiKey": "", "approvedOrigin": "http://127.0.0.1:11434", "allowRemoteEvidence": false, "useLegacyMaxTokens": false, "acknowledgeKeyStorage": false})
			prior = saved["revision"].(string)
			p.close()
			p, err = prepareWithEnrollment(m, &enrolled)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			if view["configured"] != true || view["storage"] != "protected-file" || view["resetsOnRestart"] != false || view["revision"] != prior {
				p.close()
				t.Fatal("ordinary restart lost saved provider", view)
			}
			scope := call("GET", "/api/ai/proactive", nil)
			if scope["enabled"] != false || scope["resetsOnRestart"] != false {
				p.close()
				t.Fatal("provider restore granted scope", scope)
			}
		}
	}
	p.close()
}
