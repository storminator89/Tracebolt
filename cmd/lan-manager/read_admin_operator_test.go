//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const readAdminOperatorLimit = 128 << 10

type readAdminOperatorDiagnostic struct{ method, resource, status, failure, code string }

func (d readAdminOperatorDiagnostic) log(t *testing.T) {
	t.Helper()
	if d.failure != "" {
		// Only fixed labels leave private output; never paths, bodies or error text.
		t.Logf("native_operator method=%s resource=%s status=%s failure=%s code=%s", d.method, d.resource, d.status, d.failure, d.code)
	}
}

// Native acceptance only. Every operation retains the original five-second
// budget and 128-KiB body bound. Only a GET with the exact server backpressure
// contract can wait once; POSTs are never replayed, including journal/create.
func readAdminOperatorRequest(ctx context.Context, client *http.Client, origin, path, method string, body []byte, csrf string, wait func(context.Context, time.Duration) error) (int, []byte, readAdminOperatorDiagnostic) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d := readAdminOperatorDiagnostic{method: "get", resource: readAdminOperatorResource(path), status: "not_received", code: "none"}
	if method == http.MethodPost {
		d.method = "post"
	}
	fail := func(f string) (int, []byte, readAdminOperatorDiagnostic) { d.failure = f; return 0, nil, d }
	for attempt := 0; attempt < 2; attempt++ {
		request, err := http.NewRequestWithContext(ctx, method, origin+path, bytes.NewReader(body))
		if err != nil {
			return fail("request")
		}
		if method == http.MethodPost {
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", origin)
			if csrf != "" {
				request.Header.Set("X-CSRF-Token", csrf)
			}
		}
		response, err := client.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return fail("deadline")
			}
			return fail("transport")
		}
		d.status = readAdminOperatorStatus(response.StatusCode)
		raw, err := io.ReadAll(io.LimitReader(response.Body, readAdminOperatorLimit+1))
		response.Body.Close()
		if ctx.Err() != nil {
			clear(raw)
			return fail("deadline")
		}
		if err != nil {
			clear(raw)
			return fail("body")
		}
		if len(raw) > readAdminOperatorLimit {
			clear(raw)
			return fail("oversize")
		}
		if response.StatusCode == 200 || response.StatusCode == 201 {
			return response.StatusCode, raw, d
		}
		d.code = readAdminOperatorCode(raw)
		busy := d.code == "storage_busy" || d.resource == "journal" && d.code == "journal_busy"
		if attempt == 0 && method == http.MethodGet && response.StatusCode == 429 && busy && completeMVPStorageBackoff(response.Header) {
			clear(raw)
			if wait(ctx, 2*time.Second) != nil || ctx.Err() != nil {
				return fail("deadline")
			}
			d.status, d.code = "not_received", "none"
			continue
		}
		d.failure = "status"
		return response.StatusCode, raw, d
	}
	return fail("status")
}

func readAdminOperatorDecode(raw []byte, out any, d readAdminOperatorDiagnostic) readAdminOperatorDiagnostic {
	if json.Unmarshal(raw, out) != nil {
		d.failure = "decode"
	}
	return d
}

func readAdminOperatorCode(raw []byte) string {
	code := completeMVPOperatorErrorCode(raw)
	switch code {
	case "":
		return "invalid"
	case "storage_busy", "journal_busy", "authentication_required", "journal_not_configured", "invalid_journal_request", "journal_conflict", "journal_unavailable", "journal_generation_stale", "journal_not_ready", "journal_not_found", "not_found", "method_not_allowed", "forbidden", "invalid_request":
		return code
	default:
		return "unknown"
	}
}

func readAdminOperatorStatus(status int) string {
	switch status {
	case 200:
		return "http_200"
	case 201:
		return "http_201"
	case 405:
		return "http_405"
	case 500:
		return "http_500"
	default:
		return completeMVPOperatorStatus(status)
	}
}

func readAdminOperatorResource(path string) string {
	switch path {
	case "/api/auth/login":
		return "auth"
	case "/api/enrollment/invitations":
		return "invitation"
	}
	parts := strings.Split(path, "/")
	if len(parts) == 5 && parts[1] == "api" && parts[2] == "enrollment" && parts[4] == "approve" {
		return "approval"
	}
	if len(parts) >= 5 && parts[1] == "api" && parts[2] == "devices" {
		if len(parts) == 5 && parts[4] == "packages" {
			return "packages"
		}
		if len(parts) == 7 && parts[4] == "inventory" && parts[5] == "system" && parts[6] == "query" {
			return "system_query"
		}
		if parts[4] == "journal" {
			if len(parts) == 5 {
				return "journal"
			}
			if len(parts) == 6 {
				switch parts[5] {
				case "create":
					return "journal_create"
				case "query":
					return "journal_query"
				}
			}
		}
	}
	switch label := completeMVPOperatorResource(path); label {
	case "enrollment", "devices", "operational", "system", "packages":
		return label
	default:
		return "other"
	}
}
