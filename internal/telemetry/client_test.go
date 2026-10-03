package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientTargetFailsClosed(t *testing.T) {
	for _, target := range []string{"", "http://localhost:8787", "http://example.com:8787", "https://127.0.0.1:8787", "http://127.1:8787", "http://127.0.0.2:8787", "http://[::1]:8787", "http://0.0.0.0:8787", "http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:08787", "http://user:pass@127.0.0.1:8787", "http://127.0.0.1:8787/path", "http://127.0.0.1:8787?", "http://127.0.0.1:8787?x=y", "http://127.0.0.1:8787#x", "http://127.0.0.1:8787/%2f"} {
		t.Run(target, func(t *testing.T) {
			if _, err := NewClient(target, time.Second); err == nil {
				t.Fatal("unsafe endpoint accepted")
			}
		})
	}
	if _, err := NewClient("http://127.0.0.1:8787", 50*time.Millisecond); err == nil {
		t.Fatal("unbounded timeout")
	}
	if _, err := NewClient("http://127.0.0.1:8787", 11*time.Second); err == nil {
		t.Fatal("long timeout accepted")
	}
}
func TestClientOneShotRealHTTP(t *testing.T) {
	raw := sample(t, time.Now().UTC())
	state := NewState()
	var requests atomic.Int32
	token := strings.Repeat("a", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Origin") != "http://"+r.Host {
			t.Error("missing same origin")
		}
		if len(r.Cookies()) != 0 {
			t.Error("unexpected cookies")
		}
		switch r.URL.Path {
		case "/api/session":
			if r.Method != "GET" {
				t.Error("wrong session method")
			}
			json.NewEncoder(w).Encode(map[string]string{"csrfToken": token})
		case "/api/dev/telemetry":
			if r.Method != "POST" || r.Header.Get("X-CSRF-Token") != token || r.Header.Get("Content-Type") != "application/json" || r.ContentLength != int64(len(raw)) || len(r.TransferEncoding) != 0 {
				t.Errorf("bad mutation headers: %+v", r)
			}
			body, _ := io.ReadAll(r.Body)
			receipt, err := state.Accept(body, time.Now().UTC())
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			json.NewEncoder(w).Encode(receipt)
		default:
			t.Error("unexpected request")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	// No environment proxy is consulted, including when both bypass settings are empty.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	client, err := NewClient(server.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.Send(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Sequence != 1 || requests.Load() != 2 || state.Status(time.Now()).State != "fresh" {
		t.Fatalf("bad receipt: %+v", receipt)
	}
}
func TestClientFailureBoundaries(t *testing.T) {
	raw := sample(t, time.Now().UTC())
	token := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"redirect session", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://127.0.0.1:1/forbidden")
			w.WriteHeader(302)
		}},
		{"oversize session", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, strings.Repeat("x", MaxResponseBytes+1))
		}},
		{"missing session", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{}`) }},
		{"duplicate session", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"csrfToken":"a","csrfToken":"b"}`) }},
		{"invalid token", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"csrfToken":"not-token"}`) }},
		{"redirect post", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/session" {
				json.NewEncoder(w).Encode(map[string]string{"csrfToken": token})
			} else {
				w.Header().Set("Location", "http://127.0.0.1:1/forbidden")
				w.WriteHeader(307)
			}
		}},
		{"oversize receipt", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/session" {
				json.NewEncoder(w).Encode(map[string]string{"csrfToken": token})
			} else {
				io.WriteString(w, strings.Repeat("x", MaxResponseBytes+1))
			}
		}},
		{"invalid receipt", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/session" {
				json.NewEncoder(w).Encode(map[string]string{"csrfToken": token})
			} else {
				io.WriteString(w, `{}`)
			}
		}},
		{"manager rejects", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()
			client, _ := NewClient(server.URL, time.Second)
			if _, err := client.Send(context.Background(), raw); err == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		defer server.Close()
		client, _ := NewClient(server.URL, 100*time.Millisecond)
		start := time.Now()
		if _, err := client.Send(context.Background(), raw); err == nil {
			t.Fatal("timeout accepted")
		}
		if time.Since(start) > time.Second {
			t.Fatal("timeout not bounded")
		}
	})
	t.Run("offline", func(t *testing.T) {
		server := httptest.NewServer(http.NotFoundHandler())
		url := server.URL
		server.Close()
		client, _ := NewClient(url, time.Second)
		if _, err := client.Send(context.Background(), raw); err == nil {
			t.Fatal("offline manager accepted")
		}
	})
	t.Run("invalid outbound data", func(t *testing.T) {
		client, _ := NewClient("http://127.0.0.1:1", time.Second)
		if _, err := client.Send(context.Background(), []byte(`{}`)); code(err) != "invalid_bundle" {
			t.Fatal(err)
		}
	})
}
