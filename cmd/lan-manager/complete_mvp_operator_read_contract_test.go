//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"localrmm/internal/model"
	"net/http"
	"strings"
	"testing"
	"time"
)

const completeMVPBusyJSON = `{"error":{"code":"storage_busy","message":"Stored overview is busy; retry shortly."}}`

func completeMVPOperatorResponse(status int, body, retry string) *http.Response {
	header := make(http.Header)
	if retry != "" {
		header.Set("Retry-After", retry)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}

func TestCompleteMVPOperatorReadExactBusyThenCertificateDTO(t *testing.T) {
	calls, waits := 0, 0
	var deadline time.Time
	client := &http.Client{Transport: completeMVPOperatorTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		current, ok := r.Context().Deadline()
		if !ok || r.Method != http.MethodGet || r.URL.String() != "http://fixture.invalid/api/devices" || r.Body != nil {
			t.Fatal("read request or deadline changed")
		}
		if calls == 1 {
			deadline = current
			if remaining := time.Until(deadline); remaining <= 0 || remaining > 5*time.Second {
				t.Fatal("original five-second read bound changed")
			}
			return completeMVPOperatorResponse(429, completeMVPBusyJSON, "2"), nil
		}
		if calls != 2 || current != deadline {
			t.Fatal("retry extended deadline or repeated more than once")
		}
		return completeMVPOperatorResponse(200, `{"items":[{"id":"agent_fixture","agentCertificate":{"source":"guided-enrollment","checkedAt":"2026-10-05T00:00:00Z","expiresAt":"2026-11-05T00:00:00Z"}}]}`, ""), nil
	})}
	var devices struct{ Items []model.Device }
	result := completeMVPOperatorGet(context.Background(), client, "http://fixture.invalid", "/api/devices", &devices, func(ctx context.Context, delay time.Duration) error {
		waits++
		actual, _ := ctx.Deadline()
		if delay != 2*time.Second || actual != deadline {
			t.Fatal("backpressure wait changed original deadline or Retry-After")
		}
		return nil
	})
	if result.failure != "" || !result.retried || calls != 2 || waits != 1 || len(devices.Items) != 1 || devices.Items[0].ID != "agent_fixture" || devices.Items[0].AgentCertificate == nil || devices.Items[0].AgentCertificate.ExpiresAt == nil || devices.Items[0].AgentCertificate.Source != "guided-enrollment" {
		t.Fatal("valid bounded retry or certificate DTO rejected")
	}
}

func TestCompleteMVPOperatorReadRejectsNonRetryableContractFailures(t *testing.T) {
	for _, test := range []struct {
		name                 string
		status               int
		body, retry, failure string
	}{
		{"unauthorized", 401, completeMVPBusyJSON, "2", "http_401"},
		{"forbidden", 403, completeMVPBusyJSON, "2", "http_403"},
		{"expired", 409, completeMVPBusyJSON, "2", "http_409"},
		{"unavailable", 503, completeMVPBusyJSON, "2", "http_503"},
		{"different_busy", 429, `{"error":{"code":"other"}}`, "2", "http_429"},
		{"invalid_busy", 429, `{"error":`, "2", "http_429"},
		{"duplicate_code", 429, `{"error":{"code":"authentication_required","code":"storage_busy","message":"fixture"}}`, "2", "http_429"},
		{"duplicate_code_same", 429, `{"error":{"code":"storage_busy","code":"storage_busy","message":"fixture"}}`, "2", "http_429"},
		{"aliased_code", 429, `{"error":{"code":"authentication_required","Code":"storage_busy","message":"fixture"}}`, "2", "http_429"},
		{"aliased_outer", 429, `{"Error":{"code":"storage_busy","message":"fixture"}}`, "2", "http_429"},
		{"duplicate_outer", 429, `{"error":{"code":"authentication_required","message":"fixture"},"error":{"code":"storage_busy","message":"fixture"}}`, "2", "http_429"},
		{"extra_outer", 429, `{"error":{"code":"storage_busy","message":"fixture"},"extra":true}`, "2", "http_429"},
		{"extra_inner", 429, `{"error":{"code":"storage_busy","message":"fixture","extra":true}}`, "2", "http_429"},
		{"missing_message", 429, `{"error":{"code":"storage_busy"}}`, "2", "http_429"},
		{"missing_code", 429, `{"error":{"message":"fixture"}}`, "2", "http_429"},
		{"nonstring_message", 429, `{"error":{"code":"storage_busy","message":7}}`, "2", "http_429"},
		{"null_message", 429, `{"error":{"code":"storage_busy","message":null}}`, "2", "http_429"},
		{"duplicate_message", 429, `{"error":{"code":"storage_busy","message":"one","message":"two"}}`, "2", "http_429"},
		{"trailing_busy", 429, completeMVPBusyJSON + `{}`, "2", "http_429"},
		{"missing_backoff", 429, completeMVPBusyJSON, "", "http_429"},
		{"different_backoff", 429, completeMVPBusyJSON, "20", "http_429"},
		{"oversized_busy", 429, completeMVPBusyJSON + strings.Repeat(" ", 4096), "2", "http_429"},
		{"invalid_dto", 200, `{"count":"wrong-type"}`, "", "decode"},
		{"trailing_dto", 200, `{"count":0}{"count":1}`, "", "decode"},
		{"oversized_dto", 200, strings.Repeat(" ", completeMVPOperatorReadLimit+1), "", "oversize"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: completeMVPOperatorTransport(func(*http.Request) (*http.Response, error) {
				calls++
				return completeMVPOperatorResponse(test.status, test.body, test.retry), nil
			})}
			var value struct{ Count int }
			result := completeMVPOperatorGet(context.Background(), client, "http://fixture.invalid", "/api/devices/agent_fixture/inventory/overview", &value, func(context.Context, time.Duration) error { t.Fatal("nonretryable response caused wait"); return nil })
			if result.failure != test.failure || result.retried || calls != 1 {
				t.Fatal("nonretryable failure was hidden or retried")
			}
		})
	}
}

func TestCompleteMVPOperatorReadStopsAfterOneBusyRetry(t *testing.T) {
	for _, last := range []struct {
		status        int
		body, failure string
	}{
		{429, completeMVPBusyJSON, "http_429"},
		{401, `{"error":{"code":"authentication_required"}}`, "http_401"},
		{200, `{"count":"wrong"}`, "decode"},
	} {
		calls, waits := 0, 0
		client := &http.Client{Transport: completeMVPOperatorTransport(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return completeMVPOperatorResponse(429, completeMVPBusyJSON, "2"), nil
			}
			return completeMVPOperatorResponse(last.status, last.body, "2"), nil
		})}
		var value struct{ Count int }
		result := completeMVPOperatorGet(context.Background(), client, "http://fixture.invalid", "/api/devices", &value, func(context.Context, time.Duration) error { waits++; return nil })
		if result.failure != last.failure || !result.retried || calls != 2 || waits != 1 {
			t.Fatal("retry loop hid failure or changed attempt bound")
		}
	}
}

func TestCompleteMVPOperatorReadCancellationAndOriginalParentDeadline(t *testing.T) {
	for _, cancelDuringWait := range []bool{false, true} {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
		parentDeadline, _ := ctx.Deadline()
		calls := 0
		client := &http.Client{Transport: completeMVPOperatorTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			deadline, _ := r.Context().Deadline()
			if deadline != parentDeadline {
				t.Fatal("parent deadline extended")
			}
			return completeMVPOperatorResponse(429, completeMVPBusyJSON, "2"), nil
		})}
		var value any
		result := completeMVPOperatorGet(ctx, client, "http://fixture.invalid", "/api/devices", &value, func(waitCtx context.Context, _ time.Duration) error {
			cancel()
			if cancelDuringWait {
				return completeMVPOperatorWait(waitCtx, 2*time.Second)
			}
			return nil // Even a returning wait cannot revive a canceled read.
		})
		cancel()
		if result.failure != "deadline" || !result.retried || calls != 1 {
			t.Fatal("canceled backoff sent another request")
		}
	}
}

func TestCompleteMVPOperatorReadTransportFailureHasNoRawDiagnostic(t *testing.T) {
	client := &http.Client{Transport: completeMVPOperatorTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("private-fixture-url-token") })}
	var value any
	result := completeMVPOperatorGet(context.Background(), client, "http://fixture.invalid", "/api/devices", &value, completeMVPOperatorWait)
	if result.failure != "transport" || result.retried {
		t.Fatal("transport error escaped fixed classification")
	}
	for path, want := range map[string]string{
		"/api/enrollment": "enrollment", "/api/devices": "devices", "/api/devices/private-fixture/operational": "operational",
		"/api/devices/private-fixture/inventory/packages": "packages", "/api/devices/private-fixture/inventory/system": "system",
		"/api/devices/private-fixture/inventory/endpoint-identity": "endpoint_identity", "/api/devices/private-fixture/inventory/overview": "overview",
		"/private-fixture-url-token": "other", "/api/devices/private-fixture/inventory/overview?private-fixture": "other",
	} {
		if completeMVPOperatorResource(path) != want {
			t.Fatal("resource classification lost fixed vocabulary")
		}
	}
}

func TestCompleteMVPOperatorReadRejectsAmbiguousBackoffHeaders(t *testing.T) {
	for _, header := range []http.Header{
		{"Retry-After": {"2", "2"}},
		{"Retry-After": {"2", "20"}},
		{"Retry-After": {"20", "2"}},
		{"Retry-After": {"2, 2"}},
		{"Retry-After": {"2"}, "retry-after": {"2"}},
	} {
		calls := 0
		client := &http.Client{Transport: completeMVPOperatorTransport(func(*http.Request) (*http.Response, error) {
			calls++
			response := completeMVPOperatorResponse(429, completeMVPBusyJSON, "")
			response.Header = header
			return response, nil
		})}
		var value any
		result := completeMVPOperatorGet(context.Background(), client, "http://fixture.invalid", "/api/devices", &value, func(context.Context, time.Duration) error { t.Fatal("ambiguous Retry-After caused wait"); return nil })
		if result.failure != "http_429" || result.retried || calls != 1 {
			t.Fatal("ambiguous Retry-After was retried")
		}
	}
	if !completeMVPStorageBackoff(http.Header{"retry-after": {"2"}}) {
		t.Fatal("one case-insensitive HTTP header was rejected")
	}
}
