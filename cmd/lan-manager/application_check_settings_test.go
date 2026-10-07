//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/lanconfig"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestApplicationCheckSettingsPreparedHTTPReviewAndRestart(t *testing.T) {
	m, _, _, _ := fixture(t, lanconfig.HTTPTest)
	p, err := prepare(m)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	origin := m.Config.OperatorOrigin
	login := httptest.NewRequest("POST", origin+"/api/auth/login", strings.NewReader(`{"password":"fixture-password-only"}`))
	login.Header.Set("Origin", origin)
	login.Header.Set("Content-Type", "application/json")
	login.RemoteAddr = "127.0.0.1:32100"
	response := httptest.NewRecorder()
	p.operator.ServeHTTP(response, login)
	if response.Code != 200 || len(response.Result().Cookies()) != 1 {
		t.Fatal("fixture login", response.Code)
	}
	var session map[string]any
	if json.Unmarshal(response.Body.Bytes(), &session) != nil {
		t.Fatal("fixture session")
	}
	cookie, csrf := response.Result().Cookies()[0], session["csrfToken"].(string)
	call := func(method string, input any) (int, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(input)
		if input == nil {
			raw = nil
		}
		r := httptest.NewRequest(method, origin+"/api/application-checks/settings", strings.NewReader(string(raw)))
		r.AddCookie(cookie)
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		p.operator.ServeHTTP(w, r)
		var v map[string]any
		if json.Unmarshal(w.Body.Bytes(), &v) != nil {
			t.Fatal("fixture response")
		}
		return w.Code, v
	}
	code, v := call(http.MethodGet, nil)
	if code != 200 || v["mode"] != "managed" || v["enabled"] != false {
		t.Fatal("initial settings", code)
	}
	code, v = call(http.MethodPost, map[string]any{"expectedRevision": v["revision"], "operation": "save", "intervalSeconds": 60, "targets": []any{map[string]any{"kind": "dns", "id": "fixture", "host": "fixture.example.test", "allowedAddresses": []string{"8.8.8.8"}, "allowPrivateLAN": false}}})
	if code != 200 || v["enabled"] != false || v["configured"] != true {
		t.Fatal("save not inert", code)
	}
	enable := map[string]any{"expectedRevision": v["revision"], "operation": "enable", "checksFromManagerAcknowledged": true, "destinationsAcknowledged": true}
	if code, _ = call(http.MethodPost, enable); code != 400 {
		t.Fatal("HTTP-test enabled without plaintext review", code)
	}
	enable["plaintextAcknowledged"] = true
	code, v = call(http.MethodPost, enable)
	if code != 200 || v["enabled"] != true {
		t.Fatal("explicit HTTP-test enable failed", code)
	}
	// Preparation and API changes do not run a supervisor. No DNS or other
	// target work is permitted in this fixture, even after desired enable.
	for _, item := range p.applicationChecks.Status().Items {
		if item.ObservedAt != nil {
			t.Fatal("API performed network work")
		}
	}
	code, v = call(http.MethodPost, map[string]any{"expectedRevision": v["revision"], "operation": "disable"})
	if code != 200 || v["enabled"] != false || v["configured"] != true {
		t.Fatal("disable lost draft", code)
	}
	revision := v["revision"]
	p.close()
	restarted, err := prepare(m)
	if err != nil {
		t.Fatal("restart failed", err)
	}
	defer restarted.close()
	view := restarted.applicationChecks.View()
	if view.Revision != revision || view.Enabled || !view.Configured || len(view.Targets) != 1 {
		t.Fatal("restart lost disabled reviewed draft")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- restarted.applicationChecks.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("supervisor shutdown", err)
		}
	case <-time.After(time.Second):
		t.Fatal("disabled supervisor failed to join")
	}
}
