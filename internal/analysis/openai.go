package analysis

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

const MaxCompletionTokens = 1024

// OpenAIConfig is trusted server configuration, never a model-controlled or
// per-analysis request payload. It is deliberately not a settings-storage API.
// An operator must approve the evidence destination before enabling a provider.
type OpenAIConfig struct {
	BaseURL string `json:"baseURL"`
	Model   string `json:"model"`
	// APIKey is never marshaled or formatted. Store secrets using a separately
	// reviewed secret mechanism; this adapter retains it in process memory only.
	APIKey string `json:"-"`
	// A nonempty key must be explicitly bound to the exact configured origin.
	// Changing a base URL must not silently reuse a saved key for another origin.
	APIKeyOrigin        string        `json:"-"`
	AllowedHTTPSOrigins []string      `json:"-"`
	Timeout             time.Duration `json:"-"`
	// Compatibility is an explicit operator choice, never an automatic retry.
	UseLegacyMaxTokens bool `json:"useLegacyMaxTokens"`
}

func (OpenAIConfig) String() string   { return "analysis.OpenAIConfig{secrets:redacted}" }
func (OpenAIConfig) GoString() string { return "analysis.OpenAIConfig{secrets:redacted}" }

// OpenAIProvider implements the Chat Completions structured-JSON subset. It has
// no model management, tool execution, discovery, retries or cloud fallback.
// A loopback server may itself forward requests: local transport is not proof
// of local inference. The operator controls that server's egress and retention.
type OpenAIProvider struct {
	endpoint     endpointPolicy
	model        string
	apiKey       string
	legacyTokens bool
	client       *http.Client
	busy         *atomic.Bool
}

// Value receivers also protect accidental formatting of a dereferenced provider.
// The concurrency guard is shared by pointer, so formatting/copying this value
// does not copy an atomic lock or create an independent concurrency allowance.
func (OpenAIProvider) String() string   { return "analysis.OpenAIProvider{secrets:redacted}" }
func (OpenAIProvider) GoString() string { return "analysis.OpenAIProvider{secrets:redacted}" }

// NewOpenAIProvider validates configuration without DNS lookup or any network
// request. A missing model is an explicit disabled/not-configured result.
func NewOpenAIProvider(cfg OpenAIConfig) (*OpenAIProvider, error) {
	if cfg.Model == "" {
		return nil, ErrNotConfigured
	}
	if len(cfg.Model) > 128 || !headerToken(cfg.Model) || len(cfg.APIKey) > 4096 || (cfg.APIKey != "" && !headerToken(cfg.APIKey)) || cfg.Timeout < 0 || cfg.Timeout > MaxTimeout {
		return nil, ErrInvalidConfig
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://127.0.0.1:11434/v1"
	}
	endpoint, err := parseEndpoint(cfg.BaseURL, cfg.AllowedHTTPSOrigins)
	if err != nil {
		return nil, err
	}
	if cfg.APIKey != "" && cfg.APIKeyOrigin != endpoint.origin {
		return nil, ErrInvalidConfig
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	p := &OpenAIProvider{endpoint: endpoint, model: cfg.Model, apiKey: cfg.APIKey, legacyTokens: cfg.UseLegacyMaxTokens, busy: &atomic.Bool{}}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxConnsPerHost: 1,
		MaxResponseHeaderBytes: 8 * 1024, ResponseHeaderTimeout: cfg.Timeout, TLSHandshakeTimeout: 3 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != net.JoinHostPort(endpoint.host, endpoint.port) {
				return nil, ErrUnavailable
			}
			target, err := endpoint.resolveTarget(ctx, net.DefaultResolver.LookupNetIP)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, "tcp", target)
		},
	}
	p.client = &http.Client{Transport: transport, Timeout: cfg.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("model provider redirects are disabled") }}
	return p, nil
}

func headerToken(s string) bool {
	if s == "" {
		return false
	}
	for _, b := range []byte(s) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func (p *OpenAIProvider) Identity() ProviderIdentity {
	destination := "operator-allowlisted-https"
	if p.endpoint.loopback {
		destination = "loopback-server"
	}
	return ProviderIdentity{Name: "openai-compatible", Model: p.model, Destination: destination, EndpointOrigin: p.endpoint.origin}
}

type completionRequest struct {
	Model          string    `json:"model"`
	Messages       []Message `json:"messages"`
	ResponseFormat struct {
		Type       string `json:"type"`
		JSONSchema struct {
			Name   string          `json:"name"`
			Strict bool            `json:"strict"`
			Schema json.RawMessage `json:"schema"`
		} `json:"json_schema"`
	} `json:"response_format"`
	Stream              bool `json:"stream"`
	Store               bool `json:"store"`
	N                   int  `json:"n"`
	MaxCompletionTokens int  `json:"max_completion_tokens,omitempty"`
	MaxTokens           int  `json:"max_tokens,omitempty"`
}

func (p *OpenAIProvider) Generate(ctx context.Context, input ProviderRequest) ([]byte, error) {
	if p == nil || p.client == nil {
		return nil, ErrNotConfigured
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !p.busy.CompareAndSwap(false, true) {
		return nil, ErrBusy
	}
	defer p.busy.Store(false)
	if len(input.Messages) != 2 || input.Messages[0].Role != "system" || input.Messages[1].Role != "user" || len(input.Schema) > 8*1024 {
		return nil, ErrInvalidPacket
	}
	for _, m := range input.Messages {
		if !bounded(m.Content, MaxRequestBytes) {
			return nil, ErrInvalidPacket
		}
	}
	body := completionRequest{Model: p.model, Messages: input.Messages, N: 1}
	body.ResponseFormat.Type = "json_schema"
	body.ResponseFormat.JSONSchema.Name = "tracebolt_diagnostics_v1"
	body.ResponseFormat.JSONSchema.Strict = true
	body.ResponseFormat.JSONSchema.Schema = input.Schema
	if p.legacyTokens {
		body.MaxTokens = MaxCompletionTokens
	} else {
		body.MaxCompletionTokens = MaxCompletionTokens
	}
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded) > MaxRequestBytes {
		return nil, ErrInvalidPacket
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint.url, bytes.NewReader(encoded))
	if err != nil {
		return nil, ErrUnavailable
	}
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrUnavailable
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" || (resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity") {
		return nil, ErrInvalidResponse
	}
	if resp.ContentLength > MaxProviderBytes {
		return nil, ErrResponseTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxProviderBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, ErrUnavailable
	}
	if len(raw) > MaxProviderBytes {
		return nil, ErrResponseTooLarge
	}
	if err := checkJSON(raw); err != nil {
		return nil, ErrInvalidResponse
	}
	var envelope struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Role         string            `json:"role"`
				Content      *string           `json:"content"`
				Refusal      *string           `json:"refusal"`
				ToolCalls    []json.RawMessage `json:"tool_calls"`
				FunctionCall json.RawMessage   `json:"function_call"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Choices) != 1 {
		return nil, ErrInvalidResponse
	}
	choice := envelope.Choices[0]
	m := choice.Message
	if choice.FinishReason != "stop" || m.Role != "assistant" || m.Content == nil || len(m.ToolCalls) != 0 || (len(m.FunctionCall) > 0 && string(m.FunctionCall) != "null") || (m.Refusal != nil && *m.Refusal != "") {
		return nil, ErrInvalidResponse
	}
	if len(*m.Content) > MaxResponseBytes {
		return nil, ErrResponseTooLarge
	}
	// Do not reflect a configured key if a hostile/broken upstream echoes it.
	if p.apiKey != "" && (bytes.Contains(raw, []byte(p.apiKey)) || strings.Contains(*m.Content, p.apiKey) || jsonContainsSecret([]byte(*m.Content), p.apiKey)) {
		return nil, ErrInvalidResponse
	}
	return []byte(*m.Content), nil
}

func jsonContainsSecret(raw []byte, secret string) bool {
	if checkJSON(raw) != nil {
		return false
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	var contains func(any) bool
	contains = func(v any) bool {
		switch x := v.(type) {
		case string:
			return strings.Contains(x, secret)
		case []any:
			for _, item := range x {
				if contains(item) {
					return true
				}
			}
		case map[string]any:
			for key, item := range x {
				if strings.Contains(key, secret) || contains(item) {
					return true
				}
			}
		}
		return false
	}
	return contains(v)
}
