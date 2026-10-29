package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func providerTestBody(t *testing.T, revision string, approved bool) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"configRevision": revision, "acknowledgeTest": approved})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

const providerFixtureFindings = `{"observedEvidenceIDs":["fixture-connectivity-observation"],"hypotheses":[],"counterevidence":[],"missingData":[],"nextCheck":"none"}`

func TestAIProviderTestRequiresExplicitRevisionAndSendsOnlyFixture(t *testing.T) {
	s := setup(t)
	const note = "PRIVATE-NOTE-MUST-NOT-BE-EXPORTED"
	const key = "SYNTHETIC-PROVIDER-KEY"
	if _, err := s.store.Mutate("case-demo-win-01-service", "note", note); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var leaked atomic.Bool
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if r.Header.Get("Authorization") != "Bearer "+key || !strings.Contains(string(body), "fixture-connectivity-observation") || strings.Contains(string(body), key) || strings.Contains(string(body), note) || strings.Contains(string(body), "demo-win-01") || strings.Contains(string(body), "BER-DC-01") {
			leaked.Store(true)
		}
		completion(w, providerFixtureFindings)
	}))
	defer fake.Close()
	view := configure(t, s, fake.URL+"/v1", key)
	for _, tc := range []struct {
		body   string
		change func(*http.Request)
		code   int
	}{
		{providerTestBody(t, view.Revision, false), nil, 400},
		{providerTestBody(t, "stale", true), nil, 409},
		{`{"configRevision":"` + view.Revision + `","acknowledgeTest":true,"deviceId":"private"}`, nil, 400},
		{providerTestBody(t, view.Revision, true), func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{providerTestBody(t, view.Revision, true), func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, 403},
	} {
		w := request(s, "POST", "/api/ai/test", tc.body, tc.change)
		if w.Code != tc.code {
			t.Fatal("unexpected rejection", w.Code, w.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unapproved test contacted provider")
	}
	w := request(s, "POST", "/api/ai/test", providerTestBody(t, view.Revision, true), nil)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"schemaVersion":"tracebolt.ai-provider-test.v1","configRevision":"`+view.Revision+`","status":"passed"}` || calls.Load() != 1 || leaked.Load() {
		t.Fatal("invalid fixture test", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "fixture-connectivity-observation") || strings.Contains(w.Body.String(), key) {
		t.Fatal("test leaked fixture or model output")
	}
}

func TestAIProviderTestBusyAndSafeFailures(t *testing.T) {
	for _, mode := range []string{"invalid", "unavailable", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			s := setup(t)
			fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "invalid":
					completion(w, `{"unexpected":"private provider text"}`)
				case "unavailable":
					http.Error(w, "private upstream details", 500)
				case "timeout":
					select {
					case <-r.Context().Done():
					case <-time.After(3 * time.Second):
					}
				}
			}))
			defer fake.Close()
			if mode == "timeout" {
				s.ai.timeout = 50 * time.Millisecond
			}
			view := configure(t, s, fake.URL+"/v1", "")
			s.ai.mu.Lock()
			s.ai.busy = true
			s.ai.mu.Unlock()
			w := request(s, "POST", "/api/ai/test", providerTestBody(t, view.Revision, true), nil)
			if w.Code != 409 {
				t.Fatal("shared budget bypass", w.Code)
			}
			s.ai.mu.Lock()
			s.ai.busy = false
			s.ai.mu.Unlock()
			w = request(s, "POST", "/api/ai/test", providerTestBody(t, view.Revision, true), nil)
			want := map[string]string{"invalid": "invalid_response", "unavailable": "unavailable", "timeout": "timeout"}[mode]
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"`+want+`"`) || strings.Contains(w.Body.String(), "private") {
				t.Fatal("unsafe test result", w.Code, w.Body.String())
			}
		})
	}
}

func TestAIProviderTestConfigurationChangeCancelsAndDiscards(t *testing.T) {
	s := setup(t)
	entered := make(chan struct{}, 1)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer fake.Close()
	view := configure(t, s, fake.URL+"/v1", "")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- request(s, "POST", "/api/ai/test", providerTestBody(t, view.Revision, true), nil) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("test did not reach provider")
	}
	current := aiView(t, s)
	changed := request(s, "POST", "/api/ai/config", configBody(t, current.Revision, "http://127.0.0.1:11434/v1", "new-fixture", "", false), nil)
	if changed.Code != 200 {
		t.Fatal("configuration replacement failed", changed.Code)
	}
	select {
	case w := <-done:
		if w.Code != 409 || !strings.Contains(w.Body.String(), "config_revision_mismatch") {
			t.Fatal("old result accepted", w.Code, w.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test not canceled")
	}
	s.ai.mu.Lock()
	busy := s.ai.busy
	s.ai.mu.Unlock()
	if busy {
		t.Fatal("shared busy slot leaked")
	}
}

func TestAIProviderTestRequiresSharedAdministrator(t *testing.T) {
	o := newOperatorFixture(t, 0)
	body := map[string]any{"configRevision": "fixture", "acknowledgeTest": true}
	response, _ := o.call(t, "POST", "/api/ai/test", body, "", nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("anonymous test accepted", response.StatusCode)
	}
	_, session := o.login(t)
	response, _ = o.call(t, "POST", "/api/ai/test", body, "", nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("missing csrf accepted", response.StatusCode)
	}
	_, view := o.call(t, "GET", "/api/ai/config", nil, "", nil)
	body["configRevision"] = view["revision"]
	response, _ = o.call(t, "POST", "/api/ai/test", body, session["csrfToken"].(string), nil)
	if response.StatusCode != http.StatusConflict {
		t.Fatal("unconfigured test should be rejected", response.StatusCode)
	}
	named, _ := namedOperatorFixture(t)
	login, value := named.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	if login.StatusCode != http.StatusOK {
		t.Fatal("fixture login", login.StatusCode)
	}
	response, _ = named.call(t, "POST", "/api/ai/test", body, value["csrfToken"].(string), nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("named operator obtained test permission", response.StatusCode)
	}
}

func TestAIProviderTestLogoutCancelsAndDiscards(t *testing.T) {
	o := newOperatorFixture(t, 0)
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	_, view := o.call(t, "GET", "/api/ai/config", nil, "", nil)
	entered := make(chan struct{}, 1)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer fake.Close()
	body := map[string]any{"expectedRevision": view["revision"], "baseURL": fake.URL + "/v1", "model": "fixture-model", "apiKey": "", "approvedOrigin": fake.URL, "allowRemoteEvidence": false, "useLegacyMaxTokens": false}
	response, saved := o.call(t, "POST", "/api/ai/config", body, csrf, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatal("provider setup", response.StatusCode)
	}
	testBody := map[string]any{"configRevision": saved["revision"], "acknowledgeTest": true}
	done := make(chan int, 1)
	go func() {
		response, _ := o.call(t, "POST", "/api/ai/test", testBody, csrf, nil)
		done <- response.StatusCode
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("test did not reach provider")
	}
	response, _ = o.call(t, "POST", "/api/auth/logout", map[string]any{}, csrf, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatal("logout failed", response.StatusCode)
	}
	select {
	case status := <-done:
		if status == http.StatusOK {
			t.Fatal("logged-out test result accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test was not canceled")
	}
}
