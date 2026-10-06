//go:build linux

package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestReadAdminOperatorContract(t *testing.T) {
	journalBusy := `{"error":{"code":"journal_busy","message":"invented private content"}}`
	for _, tc := range []struct {
		name, method, path, body, backoff string
		status, calls                     int
		code, failure                     string
	}{
		{"journal retry", "GET", "/api/devices/private-id/journal", journalBusy, "2", 429, 2, "none", ""},
		{"system retry", "GET", "/api/devices/private-id/inventory/system", completeMVPBusyJSON, "2", 429, 2, "none", ""},
		{"mutation never retries", "POST", "/api/devices/private-id/journal/create", journalBusy, "2", 429, 1, "journal_busy", "status"},
		{"wrong route", "GET", "/api/devices/private-id/inventory/system", journalBusy, "2", 429, 1, "journal_busy", "status"},
		{"missing backoff", "GET", "/api/devices/private-id/journal", journalBusy, "", 429, 1, "journal_busy", "status"},
		{"different backoff", "GET", "/api/devices/private-id/journal", journalBusy, "3", 429, 1, "journal_busy", "status"},
		{"not ready", "GET", "/api/devices/private-id/journal", `{"error":{"code":"journal_not_ready","message":"private"}}`, "2", 409, 1, "journal_not_ready", "status"},
		{"auth fail", "GET", "/api/devices/private-id/journal", `{"error":{"code":"authentication_required","message":"private"}}`, "2", 401, 1, "authentication_required", "status"},
		{"unknown error", "GET", "/api/devices/private-id/journal", `{"error":{"code":"private-secret","message":"private"}}`, "2", 429, 1, "unknown", "status"},
		{"duplicate code", "GET", "/api/devices/private-id/journal", `{"error":{"code":"journal_busy","code":"journal_busy","message":"private"}}`, "2", 429, 1, "invalid", "status"},
		{"oversize", "GET", "/api/devices/private-id/journal", strings.Repeat("x", readAdminOperatorLimit+1), "", 200, 1, "none", "oversize"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, waits := 0, 0
			var deadline time.Time
			client := &http.Client{Transport: completeMVPOperatorTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				current, _ := r.Context().Deadline()
				if calls == 1 {
					deadline = current
				} else if current != deadline {
					t.Fatal("retry extended original deadline")
				}
				if r.Method != tc.method {
					t.Fatal("method changed")
				}
				if r.Method == "GET" && (r.Body != nil && r.Body != http.NoBody || r.ContentLength != 0 || r.Header.Get("Origin") != "" || r.Header.Get("Content-Type") != "" || r.Header.Get("X-CSRF-Token") != "") {
					t.Fatal("GET acquired mutation body or headers")
				}
				if r.Method == "POST" && (r.Header.Get("Origin") != "https://fixture.invalid" || r.Header.Get("X-CSRF-Token") != "invented-fixture-csrf") {
					t.Fatal("mutation boundary changed")
				}
				if calls == 2 {
					return completeMVPOperatorResponse(200, `{"expectedFloor":"0"}`, ""), nil
				}
				return completeMVPOperatorResponse(tc.status, tc.body, tc.backoff), nil
			})}
			var body []byte
			if tc.method == "POST" {
				body = []byte(`{}`)
			}
			_, raw, d := readAdminOperatorRequest(context.Background(), client, "https://fixture.invalid", tc.path, tc.method, body, "invented-fixture-csrf", func(ctx context.Context, delay time.Duration) error {
				waits++
				if delay != 2*time.Second {
					t.Fatal("incorrect server delay")
				}
				actual, _ := ctx.Deadline()
				if actual != deadline {
					t.Fatal("wait deadline changed")
				}
				return nil
			})
			defer clear(raw)
			if calls != tc.calls || waits != tc.calls-1 || d.failure != tc.failure || d.code != tc.code {
				t.Fatalf("contract calls=%d waits=%d failure=%s code=%s", calls, waits, d.failure, d.code)
			}
		})
	}
}

func TestReadAdminOperatorFailureBounds(t *testing.T) {
	for _, cancelWait := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		deadline, _ := ctx.Deadline()
		calls := 0
		client := &http.Client{Transport: completeMVPOperatorTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			actual, _ := r.Context().Deadline()
			if actual != deadline {
				t.Fatal("parent budget extended")
			}
			return completeMVPOperatorResponse(429, completeMVPBusyJSON, "2"), nil
		})}
		_, raw, d := readAdminOperatorRequest(ctx, client, "https://fixture.invalid", "/api/devices", "GET", nil, "", func(context.Context, time.Duration) error {
			if cancelWait {
				cancel()
				return context.Canceled
			}
			return nil
		})
		clear(raw)
		cancel()
		if cancelWait && (calls != 1 || d.failure != "deadline") || !cancelWait && (calls != 2 || d.failure != "status" || d.code != "storage_busy") {
			t.Fatal("retry/cancellation bound changed")
		}
	}
	client := &http.Client{Transport: completeMVPOperatorTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("private URL and credentials") })}
	_, _, d := readAdminOperatorRequest(context.Background(), client, "https://fixture.invalid", "/api/devices", "GET", nil, "", completeMVPOperatorWait)
	if d.failure != "transport" || d.status != "not_received" || d.code != "none" {
		t.Fatal("transport diagnostic not closed")
	}
	d = readAdminOperatorDecode([]byte(`{"expectedFloor":7}`), &struct{ ExpectedFloor string }{}, readAdminOperatorDiagnostic{status: "http_200", code: "none"})
	if d.failure != "decode" || d.status != "http_200" || d.code != "none" {
		t.Fatal("decode diagnostic lost")
	}
	for path, want := range map[string]string{"/api/devices/private-id/journal": "journal", "/api/devices/private-id/journal/create": "journal_create", "/api/devices/private-id/journal/query": "journal_query", "/api/devices/private-id/inventory/system/query": "system_query", "/api/enrollment/private-id/approve": "approval", "/api/devices/private-id/secret": "other"} {
		if readAdminOperatorResource(path) != want {
			t.Fatal("route diagnostic not closed")
		}
	}
}
