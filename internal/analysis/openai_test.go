package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fakeCompletion(content string) string {
	raw, _ := json.Marshal(map[string]any{"id": "fixture-completion", "model": "test-model", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": content}}}})
	return string(raw)
}

func providerInput() ProviderRequest {
	return ProviderRequest{Messages: []Message{{Role: "system", Content: "Return JSON."}, {Role: "user", Content: `{"evidence":[]}`}}, Schema: OutputSchema()}
}

func fakeHTTPProvider(t *testing.T, handler http.HandlerFunc, timeout time.Duration) (*OpenAIProvider, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	p, err := NewOpenAIProvider(OpenAIConfig{BaseURL: server.URL + "/v1", Model: "test-model", Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return p, server
}

func TestOpenAICompatibleFakeServerSuccessAndWireBoundary(t *testing.T) {
	const fakeKey = "fixture-only-not-a-real-api-key"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "POST" || r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer "+fakeKey || r.Header.Get("Content-Type") != "application/json" {
			t.Error("unexpected request authority/auth/method")
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
		if len(raw) > MaxRequestBytes || strings.Contains(string(raw), fakeKey) {
			t.Error("request body exceeded bounds or included the key")
		}
		var body map[string]json.RawMessage
		if json.Unmarshal(raw, &body) != nil {
			t.Error("request is not JSON")
		}
		for _, absent := range []string{"tools", "tool_choice", "functions", "apiKey", "max_tokens"} {
			if _, exists := body[absent]; exists {
				t.Errorf("unexpected request field %s", absent)
			}
		}
		if string(body["stream"]) != "false" || string(body["store"]) != "false" || string(body["n"]) != "1" || string(body["max_completion_tokens"]) != "1024" {
			t.Error("unsafe request controls")
		}
		var typed completionRequest
		if json.Unmarshal(raw, &typed) != nil || typed.ResponseFormat.Type != "json_schema" || !typed.ResponseFormat.JSONSchema.Strict || !json.Valid(typed.ResponseFormat.JSONSchema.Schema) {
			t.Error("missing strict output schema")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fakeCompletion(validFindings))
	}))
	defer server.Close()
	p, err := NewOpenAIProvider(OpenAIConfig{BaseURL: server.URL + "/v1", Model: "test-model", APIKey: fakeKey, APIKeyOrigin: server.URL})
	if err != nil || requests.Load() != 0 {
		t.Fatalf("constructor made a network call or failed: %v", err)
	}
	c, e := sampleCase()
	result, err := NewService(p).Analyze(context.Background(), c, e)
	if err != nil || result.AI.Status != "completed" || result.AI.Findings == nil || requests.Load() != 1 {
		t.Fatalf("adapter failed: %#v %v requests=%d", result, err, requests.Load())
	}
	if result.AI.Provenance.EndpointOrigin != server.URL || result.AI.Provenance.Destination != "loopback-server" || result.AI.Provenance.Model != "test-model" {
		t.Fatal("missing destination/model provenance")
	}
	resultJSON, _ := json.Marshal(result)
	if strings.Contains(string(resultJSON), fakeKey) {
		t.Fatal("key leaked into result")
	}
}

func TestProviderConfigurationAndSecretFormatting(t *testing.T) {
	const fakeKey = "fixture-key-never-a-real-credential"
	cfg := OpenAIConfig{BaseURL: "http://127.0.0.1:11434/v1", Model: "test-model", APIKey: fakeKey, APIKeyOrigin: "http://127.0.0.1:11434"}
	p, err := NewOpenAIProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	for _, rendered := range []string{string(raw), fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", &cfg), fmt.Sprintf("%#v", cfg), fmt.Sprintf("%+v", p), fmt.Sprintf("%#v", p), fmt.Sprintf("%+v", *p), fmt.Sprintf("%#v", *p)} {
		if strings.Contains(rendered, fakeKey) {
			t.Fatal("config/provider formatting leaked key")
		}
	}
	badConfigs := []OpenAIConfig{
		{BaseURL: cfg.BaseURL, Model: cfg.Model, APIKey: fakeKey},
		{BaseURL: cfg.BaseURL, Model: cfg.Model, APIKey: fakeKey, APIKeyOrigin: "https://other.example.com"},
		{BaseURL: cfg.BaseURL, Model: "unsafe\nmodel"},
		{BaseURL: cfg.BaseURL, Model: cfg.Model, APIKey: "fake\nheader", APIKeyOrigin: cfg.APIKeyOrigin},
		{BaseURL: cfg.BaseURL, Model: cfg.Model, APIKey: strings.Repeat("x", 4097), APIKeyOrigin: cfg.APIKeyOrigin},
		{BaseURL: cfg.BaseURL, Model: cfg.Model, Timeout: -time.Second},
		{BaseURL: cfg.BaseURL, Model: cfg.Model, Timeout: MaxTimeout + time.Second},
	}
	for _, bad := range badConfigs {
		if _, err := NewOpenAIProvider(bad); !errors.Is(err, ErrInvalidConfig) || strings.Contains(err.Error(), fakeKey) {
			t.Fatalf("unsafe config accepted or error leaked: %v", err)
		}
	}
	remote := OpenAIConfig{BaseURL: "https://models.example.com/v1", Model: "test-model", APIKey: fakeKey, APIKeyOrigin: "https://models.example.com", AllowedHTTPSOrigins: []string{"https://models.example.com"}}
	p, err = NewOpenAIProvider(remote)
	if err != nil || p.Identity().Destination != "operator-allowlisted-https" {
		t.Fatalf("explicit HTTPS configuration failed: %v", err)
	}
	transport := p.client.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableCompression || !transport.DisableKeepAlives || transport.MaxResponseHeaderBytes > 8*1024 {
		t.Fatal("unbounded/redirectable transport configuration")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "another.example.com:443"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("dial target escaped configured origin")
	}
}

func TestProviderRejectsBadResponsesWithoutRetries(t *testing.T) {
	cases := map[string]string{
		"outer not JSON":       "not JSON",
		"outer duplicate key":  `{"choices":[],"choices":[]}`,
		"outer trailing value": fakeCompletion(validFindings) + "{}",
		"missing choices":      `{}`,
		"empty choices":        `{"choices":[]}`,
		"length stop":          strings.Replace(fakeCompletion(validFindings), `"finish_reason":"stop"`, `"finish_reason":"length"`, 1),
		"wrong role":           strings.Replace(fakeCompletion(validFindings), `"role":"assistant"`, `"role":"user"`, 1),
		"refusal":              `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"{}","refusal":"no"}}]}`,
		"tool call":            `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"{}","tool_calls":[{"function":{"name":"shell"}}]}}]}`,
		"legacy function":      `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"{}","function_call":{"name":"shell"}}}]}`,
		"null content":         `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":null}}]}`,
		"content bytes":        fakeCompletion(strings.Repeat("x", MaxResponseBytes+1)),
		"response bytes":       strings.Repeat(" ", MaxProviderBytes) + fakeCompletion(validFindings),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			p, _ := fakeHTTPProvider(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
			}, 0)
			_, err := p.Generate(context.Background(), providerInput())
			if !errors.Is(err, ErrInvalidResponse) && !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("bad response accepted: %v", err)
			}
			if requests.Load() != 1 {
				t.Fatal("unexpected retries")
			}
		})
	}
}

func TestProviderRejectsWrongContentTypeEncodingAndErrors(t *testing.T) {
	cases := []struct {
		name        string
		code        int
		contentType string
		encoding    string
		want        error
	}{
		{"upstream error", 500, "application/json", "", ErrUnavailable},
		{"unauthorized", 401, "application/json", "", ErrUnavailable},
		{"HTML", 200, "text/html", "", ErrInvalidResponse},
		{"compressed", 200, "application/json", "gzip", ErrInvalidResponse},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := fakeHTTPProvider(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				if tt.encoding != "" {
					w.Header().Set("Content-Encoding", tt.encoding)
				}
				w.WriteHeader(tt.code)
				_, _ = io.WriteString(w, "private-error-containing-credentials")
			}, 0)
			_, err := p.Generate(context.Background(), providerInput())
			if !errors.Is(err, tt.want) || strings.Contains(err.Error(), "credentials") {
				t.Fatalf("unsafe upstream response: %v", err)
			}
		})
	}
}

func TestProviderBlocksRedirectsAndDoesNotForwardKeys(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationCalls.Add(1)
		t.Error("redirect target was contacted")
	}))
	defer destination.Close()
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			p, server := fakeHTTPProvider(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, destination.URL+"/v1/chat/completions", status)
			}, 0)
			p.apiKey = "fixture-key"
			_, err := p.Generate(context.Background(), providerInput())
			if !errors.Is(err, ErrUnavailable) || destinationCalls.Load() != 0 {
				t.Fatalf("redirect escaped: %v", err)
			}
			server.Close()
		})
	}
}

func TestProviderIgnoresEnvironmentProxy(t *testing.T) {
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalls.Add(1)
		t.Error("environment proxy received request")
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	p, _ := fakeHTTPProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fakeCompletion(validFindings))
	}, 0)
	if _, err := p.Generate(context.Background(), providerInput()); err != nil || proxyCalls.Load() != 0 {
		t.Fatalf("proxy affected local request: %v", err)
	}
}

func TestProviderTimeoutCancellationAndBusy(t *testing.T) {
	for _, flush := range []bool{false, true} {
		t.Run(fmt.Sprintf("timeout-flush-%v", flush), func(t *testing.T) {
			p, _ := fakeHTTPProvider(t, func(w http.ResponseWriter, r *http.Request) {
				if flush {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, "{")
					w.(http.Flusher).Flush()
				}
				select {
				case <-r.Context().Done():
				case <-time.After(200 * time.Millisecond):
				}
			}, 20*time.Millisecond)
			if _, err := p.Generate(context.Background(), providerInput()); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("timeout not classified: %v", err)
			}
		})
	}
	started := make(chan struct{})
	p, _ := fakeHTTPProvider(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}, 0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := p.Generate(ctx, providerInput()); done <- err }()
	<-started
	if _, err := p.Generate(context.Background(), providerInput()); !errors.Is(err, ErrBusy) {
		t.Fatalf("provider concurrency escaped: %v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not propagated: %v", err)
	}
}

func TestProviderDropsReflectedSecret(t *testing.T) {
	for _, content := range []string{
		strings.Replace(validFindings, "Die Kapazität könnte knapp sein; die Ursache ist offen.", "fixture-key", 1),
		strings.Replace(validFindings, "Die Kapazität könnte knapp sein; die Ursache ist offen.", `fixture-\u006bey`, 1),
	} {
		p, _ := fakeHTTPProvider(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, fakeCompletion(content))
		}, 0)
		p.apiKey = "fixture-key"
		if _, err := p.Generate(context.Background(), providerInput()); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("reflected secret accepted: %v", err)
		}
	}
}

func TestProviderExplicitLegacyTokenCompatibility(t *testing.T) {
	p, _ := fakeHTTPProvider(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&body) != nil || string(body["max_tokens"]) != "1024" || body["max_completion_tokens"] != nil {
			t.Error("legacy token limit contract not honored")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fakeCompletion(validFindings))
	}, 0)
	p.legacyTokens = true
	if _, err := p.Generate(context.Background(), providerInput()); err != nil {
		t.Fatal(err)
	}
}

func TestProviderRejectsOversizedRequestsBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	p, _ := fakeHTTPProvider(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }, 0)
	in := providerInput()
	in.Messages[1].Content = strings.Repeat("x", MaxRequestBytes+1)
	if _, err := p.Generate(context.Background(), in); !errors.Is(err, ErrInvalidPacket) || calls.Load() != 0 {
		t.Fatal("oversized input reached provider")
	}
}
