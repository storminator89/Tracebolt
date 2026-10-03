package api

import (
	"encoding/json"
	"fmt"
	"localrmm/internal/analysis"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func aiView(t *testing.T, s *Server) publicAIConfig {
	t.Helper()
	w := request(s, "GET", "/api/ai/config", "", nil)
	if w.Code != 200 {
		t.Fatal("read config failed", w.Code)
	}
	var view publicAIConfig
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view
}
func configBody(t *testing.T, revision, base, model, key string, remote bool) string {
	t.Helper()
	origin := strings.TrimSuffix(base, "/v1")
	b, err := json.Marshal(aiConfigRequest{ExpectedRevision: revision, BaseURL: base, Model: model, APIKey: key, ApprovedOrigin: origin, AllowRemoteEvidence: remote})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func configure(t *testing.T, s *Server, base, key string) publicAIConfig {
	t.Helper()
	view := aiView(t, s)
	w := request(s, "POST", "/api/ai/config", configBody(t, view.Revision, base, "fixture-model", key, false), nil)
	if w.Code != 200 {
		t.Fatal("configuration rejected", w.Code, w.Body.String())
	}
	if key != "" && strings.Contains(w.Body.String(), key) {
		t.Fatal("secret leaked in write response")
	}
	return aiView(t, s)
}
func analyze(t *testing.T, s *Server, revision string) *httptest.ResponseRecorder {
	t.Helper()
	return request(s, "POST", "/api/cases/case-demo-win-01-service/analyze", `{"configRevision":"`+revision+`"}`, nil)
}
func result(t *testing.T, w *httptest.ResponseRecorder) caseAnalysisResponse {
	t.Helper()
	if w.Code != 200 {
		t.Fatal("analysis route failed", w.Code, w.Body.String())
	}
	var value caseAnalysisResponse
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func fakeFindings() string {
	return `{"observedEvidenceIDs":["demo-win-01-service-state"],"hypotheses":[{"statement":"Der Dienst ist laut Evidenz gestoppt; die Ursache bleibt offen.","evidenceIDs":["demo-win-01-service-state"]}],"counterevidence":[],"missingData":[],"nextCheck":"service"}`
}
func completion(w http.ResponseWriter, content string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": content}}}})
}

func TestAIUnconfiguredAndMemoryOnlyConfiguration(t *testing.T) {
	s := setup(t)
	view := aiView(t, s)
	if view.Configured || view.KeyConfigured || view.Storage != "memory-only" || !view.ResetsOnRestart {
		t.Fatal("wrong default state")
	}
	value := result(t, analyze(t, s, view.Revision))
	if value.AI.Status != "not_configured" || value.AI.Findings != nil || value.RootCauseConfirmed || value.ConfigRevision != view.Revision {
		t.Fatal("unconfigured result invented AI")
	}
	var calls atomic.Int64
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); completion(w, fakeFindings()) }))
	defer fake.Close()
	const secret = "synthetic-key-never-a-real-credential"
	saved := configure(t, s, fake.URL+"/v1", secret)
	if !saved.Configured || !saved.KeyConfigured || saved.Revision == view.Revision || calls.Load() != 0 {
		t.Fatal("save contacted provider or failed")
	}
	read := request(s, "GET", "/api/ai/config", "", nil)
	if strings.Contains(read.Body.String(), secret) || strings.Contains(read.Body.String(), `"apiKey"`) {
		t.Fatal("secret exposed on readback")
	}
	replacement, err := New(s.store, 8787, s.web, s.sampleDevice())
	if err != nil {
		t.Fatal(err)
	}
	fresh := aiView(t, replacement)
	if fresh.Configured || fresh.KeyConfigured || fresh.Model != "" {
		t.Fatal("key persisted across server restart")
	}
	if got := fmt.Sprintf("%+v", aiConfigRequest{APIKey: secret}); strings.Contains(got, secret) {
		t.Fatal("request formatter exposed key")
	}
}

func TestAIOnlyExplicitAnalyzeSendsBoundedCaseEvidence(t *testing.T) {
	s := setup(t)
	const note = "private-note-not-for-the-model"
	if _, err := s.store.Mutate("case-demo-win-01-service", "note", note); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	var bad atomic.Bool
	const secret = "synthetic-only-test-bearer-token"
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer "+secret {
			bad.Store(true)
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			bad.Store(true)
		}
		encoded, _ := json.Marshal(body)
		if strings.Contains(string(encoded), note) || strings.Contains(string(encoded), "BER-DC-01") {
			bad.Store(true)
		}
		completion(w, fakeFindings())
	}))
	defer fake.Close()
	view := configure(t, s, fake.URL+"/v1", secret)
	_ = aiView(t, s)
	if calls.Load() != 0 {
		t.Fatal("read/save contacted provider")
	}
	value := result(t, analyze(t, s, view.Revision))
	if value.AI.Status != "completed" || value.AI.Findings == nil || value.RootCauseConfirmed || value.Superseded || calls.Load() != 1 || bad.Load() {
		t.Fatal("analysis contract failed")
	}
	if value.AI.Provenance.EndpointOrigin != fake.URL || value.AI.Provenance.Model != "fixture-model" || value.ID == "" || value.GeneratedAt.IsZero() {
		t.Fatal("analysis provenance missing")
	}
	if value.Baseline.Provenance.Method != "rules" || value.AI.Provenance.Method != "ai" {
		t.Fatal("AI baseline separation lost")
	}
}

func TestAIConfigStrictInputAndCSRF(t *testing.T) {
	s := setup(t)
	view := aiView(t, s)
	valid := configBody(t, view.Revision, "http://127.0.0.1:11434/v1", "fixture-model", "", false)
	tests := []struct {
		name, body string
		modify     func(*http.Request)
		want       int
	}{
		{"missing csrf", valid, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, 403},
		{"missing origin", valid, func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"duplicate csrf", valid, func(r *http.Request) { r.Header.Add("X-CSRF-Token", s.csrf) }, 403},
		{"duplicate field", strings.Replace(valid, `"model":"fixture-model"`, `"model":"fixture-model","model":"other"`, 1), nil, 400},
		{"unknown field", strings.TrimSuffix(valid, "}") + `,"endpoint":"http://evil.invalid"}`, nil, 400},
		{"null field", strings.Replace(valid, `"apiKey":""`, `"apiKey":null`, 1), nil, 400},
		{"wrong type", strings.Replace(valid, `"model":"fixture-model"`, `"model":[]`, 1), nil, 400},
		{"invalid surrogate", strings.Replace(valid, `"model":"fixture-model"`, `"model":"\ud800"`, 1), nil, 400},
		{"oversized", strings.Replace(valid, `"apiKey":""`, `"apiKey":"`+strings.Repeat("z", 9000)+`"`, 1), nil, 413},
		{"wrong revision", strings.Replace(valid, view.Revision, "cfg-stale", 1), nil, 409},
		{"private target", configBody(t, view.Revision, "https://192.168.1.2/v1", "fixture-model", "fake-key", true), nil, 400},
		{"http LAN", configBody(t, view.Revision, "http://192.168.1.2/v1", "fixture-model", "fake-key", true), nil, 400},
		{"metadata", configBody(t, view.Revision, "https://169.254.169.254/v1", "fixture-model", "fake-key", true), nil, 400},
		{"remote no consent", configBody(t, view.Revision, "https://provider.example.invalid/v1", "fixture-model", "fake-key", false), nil, 400},
		{"remote no fresh key", configBody(t, view.Revision, "https://provider.example.invalid/v1", "fixture-model", "", true), nil, 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := request(s, "POST", "/api/ai/config", tt.body, tt.modify)
			if w.Code != tt.want {
				t.Fatalf("status=%d expected=%d", w.Code, tt.want)
			}
			if aiView(t, s).Revision != view.Revision {
				t.Fatal("rejected config changed current state")
			}
		})
	}
	// Constructor acceptance only: reserved invalid DNS name is never contacted.
	remote := configBody(t, view.Revision, "https://provider.example.invalid/v1", "fixture-model", "fake-public-secret", true)
	if w := request(s, "POST", "/api/ai/config", remote, nil); w.Code != 200 {
		t.Fatal("explicit trusted HTTPS config rejected", w.Code)
	}
}

func TestAIAnalyzeDoesNotAcceptProviderOrEvidenceOverrides(t *testing.T) {
	s := setup(t)
	view := aiView(t, s)
	for _, body := range []string{`{}`, `{"configRevision":"` + view.Revision + `","baseURL":"http://evil.invalid"}`, `{"configRevision":"` + view.Revision + `","evidence":[]}`, `{"configRevision":"` + view.Revision + `","configRevision":"` + view.Revision + `"}`} {
		w := request(s, "POST", "/api/cases/case-demo-win-01-service/analyze", body, nil)
		if w.Code != 400 {
			t.Fatal("override accepted", w.Code)
		}
	}
	if w := analyze(t, s, "stale"); w.Code != 409 {
		t.Fatal("stale configuration accepted")
	}
	if w := request(s, "GET", "/api/cases/case-demo-win-01-service/analyze", "", nil); w.Code == 200 {
		t.Fatal("GET can analyze")
	}
}

func TestAIReplacementCancelsOldRequestAndKeepsGlobalSlot(t *testing.T) {
	s := setup(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		close(started)
		<-release
		completion(w, fakeFindings())
	}))
	defer fake.Close()
	defer close(release)
	view := configure(t, s, fake.URL+"/v1", "old-synthetic-secret")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- analyze(t, s, view.Revision) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("provider was not invoked")
	}
	if w := analyze(t, s, view.Revision); w.Code != 409 {
		t.Fatal("parallel analysis accepted")
	}
	if !aiView(t, s).Busy {
		t.Fatal("busy state missing")
	}
	clear := request(s, "POST", "/api/ai/config/clear", `{"expectedRevision":"`+view.Revision+`"}`, nil)
	if clear.Code != 200 {
		t.Fatal("clear rejected")
	}
	cleared := aiView(t, s)
	if cleared.Configured || cleared.KeyConfigured {
		t.Fatal("clear retained credentials")
	}
	var old caseAnalysisResponse
	select {
	case response := <-done:
		old = result(t, response)
	case <-time.After(2 * time.Second):
		t.Fatal("old analysis did not cancel")
	}
	if old.AI.Status != "canceled" || !old.Superseded || old.ConfigRevision != view.Revision || calls.Load() != 1 {
		t.Fatal("old configuration result not marked canceled/superseded")
	}
	if aiView(t, s).Busy {
		t.Fatal("global slot not released")
	}
	if value := result(t, analyze(t, s, cleared.Revision)); value.AI.Status != "not_configured" {
		t.Fatal("cleared service still active")
	}
}

func TestAITimeoutAndInvalidProviderResponsesAreExplicit(t *testing.T) {
	for _, kind := range []string{"timeout", "invalid_response", "unavailable"} {
		t.Run(kind, func(t *testing.T) {
			s := setup(t)
			s.ai.timeout = 30 * time.Millisecond
			fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "timeout":
					time.Sleep(100 * time.Millisecond)
					completion(w, fakeFindings())
				case "invalid_response":
					completion(w, `{"observedEvidenceIDs":["absent"],"hypotheses":[],"counterevidence":[],"missingData":[],"nextCheck":"none"}`)
				case "unavailable":
					w.WriteHeader(401)
					_, _ = w.Write([]byte("upstream secret-looking data must not be returned"))
				}
			}))
			defer fake.Close()
			view := configure(t, s, fake.URL+"/v1", "fixture-failure-secret")
			response := analyze(t, s, view.Revision)
			value := result(t, response)
			if value.AI.Status != kind || value.AI.Findings != nil || strings.Contains(response.Body.String(), "upstream secret-looking") {
				t.Fatal("provider failure incorrectly exposed or classified")
			}
		})
	}
}

func TestAIConfiguredProviderIsNotPersistedIntoCases(t *testing.T) {
	s := setup(t)
	before, _ := s.store.Cases()
	configure(t, s, "http://127.0.0.1:11434/v1", "fake-key-nopersist")
	after, _ := s.store.Cases()
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if string(a) != string(b) {
		t.Fatal("provider settings altered stored case state")
	}
	_ = analysis.ResultVersion
}
