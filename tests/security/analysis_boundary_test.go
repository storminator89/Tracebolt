package security_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/analysis"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

const fakeReviewKey = "test-only-not-a-real-key-security-sentinel"

func TestAnalysisRejectsDangerousConfiguration(t *testing.T) {
	for _, base := range []string{
		"http://localhost:11434/v1", "http://127.0.0.1.evil.test/v1",
		"https://169.254.169.254/v1", "https://168.63.129.16/v1",
		"https://100.100.100.200/v1", "https://10.0.0.1/v1",
		"https://[::ffff:127.0.0.1]/v1", "https://[fd00:ec2::254]/v1",
		"http://127.0.0.1:11434/v1?key=not-a-secret",
		"https://user:password@example.test/v1", "http://127.0.0.1:11434/v1#fragment",
		"http://127.0.0.1:11434/%2e%2e/v1", "http://127.0.0.1:11434/v1/../admin",
	} {
		t.Run(base, func(t *testing.T) {
			origin := strings.TrimSuffix(base, "/v1")
			_, err := analysis.NewOpenAIProvider(analysis.OpenAIConfig{BaseURL: base, Model: "test-model", AllowedHTTPSOrigins: []string{origin}})
			if err == nil {
				t.Fatal("dangerous or ambiguous endpoint accepted")
			}
		})
	}
	_, err := analysis.NewOpenAIProvider(analysis.OpenAIConfig{
		BaseURL: "https://models.example.test/v1", Model: "test-model", APIKey: fakeReviewKey,
		APIKeyOrigin: "https://other.example.test", AllowedHTTPSOrigins: []string{"https://models.example.test"},
	})
	if err == nil {
		t.Fatal("key was accepted for a different origin")
	}
}

func TestAnalysisSecretFormattingAndJSON(t *testing.T) {
	cfg := analysis.OpenAIConfig{BaseURL: "http://127.0.0.1:11434/v1", Model: "test-model", APIKey: fakeReviewKey, APIKeyOrigin: "http://127.0.0.1:11434"}
	provider, err := analysis.NewOpenAIProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil || strings.Contains(string(encoded), fakeReviewKey) {
		t.Fatal("config JSON leaked a secret")
	}
	// Reflection models diagnostic formatting of a value without a static lock-copy operation.
	value := reflect.ValueOf(provider).Elem().Interface()
	for _, item := range []any{cfg, &cfg, provider, value} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, item), fakeReviewKey) {
				t.Errorf("secret leaked through %s diagnostic formatting", format)
			}
		}
	}
}

func reviewProviderRequest() analysis.ProviderRequest {
	return analysis.ProviderRequest{Messages: []analysis.Message{{Role: "system", Content: "Return the schema."}, {Role: "user", Content: "Synthetic test evidence only."}}, Schema: analysis.OutputSchema()}
}

func TestAnalysisNeverFollowsProviderRedirect(t *testing.T) {
	var calls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "should not reach target", 500)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/capture", http.StatusFound)
	}))
	defer source.Close()
	provider, err := analysis.NewOpenAIProvider(analysis.OpenAIConfig{BaseURL: source.URL + "/v1", Model: "test-model", APIKey: fakeReviewKey, APIKeyOrigin: source.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Generate(context.Background(), reviewProviderRequest()); err == nil {
		t.Fatal("redirect was accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("redirect caused an outbound request")
	}
}

func TestAnalysisDiscardsUpstreamSecretEcho(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+fakeReviewKey {
			t.Error("expected fake local test key")
		}
		w.Header().Set("Content-Type", "application/json")
		content := `{"observedEvidenceIDs":[],"hypotheses":[],"counterevidence":[],"missingData":["` + fakeReviewKey + `"],"nextCheck":"none"}`
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": content}}}})
	}))
	defer server.Close()
	provider, err := analysis.NewOpenAIProvider(analysis.OpenAIConfig{BaseURL: server.URL + "/v1", Model: "test-model", APIKey: fakeReviewKey, APIKeyOrigin: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Generate(context.Background(), reviewProviderRequest())
	if !errors.Is(err, analysis.ErrInvalidResponse) || result != nil {
		t.Fatal("secret echo was not discarded")
	}
	if strings.Contains(fmt.Sprint(err), fakeReviewKey) {
		t.Fatal("error leaked a key")
	}
}
