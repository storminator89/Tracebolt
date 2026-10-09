package lanclient

import (
	"context"
	"encoding/json"
	"io"
	"localrmm/internal/windowssetup"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWindowsSetupCompatibilityResponseBoundedAndExact(t *testing.T) {
	for _, kind := range []string{"exact", "old", "mismatch", "large", "encoding", "cookie", "type", "redirect", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			want := windowssetup.Expected("manager_00000000000000000000000000000001", "https://manager.example", "https://agent.example")
			body, _ := json.Marshal(want)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != windowssetup.CapabilitiesPath || r.Method != "GET" || r.ContentLength != 0 || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("unsafe request")
				}
				w.Header().Set("Content-Type", "application/json")
				switch kind {
				case "old":
					w.WriteHeader(404)
				case "mismatch":
					body = []byte(strings.ReplaceAll(string(body), "agent.example", "other.example"))
				case "large":
					body = []byte(strings.Repeat("x", 2049))
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
				case "cookie":
					w.Header().Set("Set-Cookie", "fixture")
				case "type":
					w.Header().Set("Content-Type", "text/html")
				case "redirect":
					w.Header().Set("Location", "https://other.example")
					w.WriteHeader(307)
				case "duplicate":
					body = []byte(strings.Replace(string(body), `"schemaVersion":`, `"schemaVersion":"fixture","schemaVersion":`, 1))
				}
				w.Write(body)
			}))
			defer server.Close()
			c := server.Client()
			c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			err := checkWindowsSetupManager(context.Background(), c, server.URL, want)
			if (err == nil) != (kind == "exact") {
				t.Fatal("wrong result", kind, err)
			}
		})
	}
}
func TestWindowsSetupTransportDoesNotBroadenProofTransport(t *testing.T) {
	calls := 0
	next := setupRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
	})
	transport := &publicBootstrapTransport{origin: "https://manager.example", authority: "manager.example", path: windowssetup.CapabilitiesPath, next: next}
	for _, path := range []string{windowssetup.CapabilitiesPath, "/v2/windows/enrollment/claim", "/v2/enrollment/bootstrap/invite_00000000000000000000000000000001"} {
		r, _ := http.NewRequest("GET", "https://manager.example"+path, nil)
		resp, e := transport.RoundTrip(r)
		if resp != nil {
			resp.Body.Close()
		}
		if (e == nil) != (path == windowssetup.CapabilitiesPath) {
			t.Fatal("route widened")
		}
	}
	if calls != 1 {
		t.Fatal("invalid reached network")
	}
	if c, e := NewWindowsSetupHTTPClient("http://127.0.0.1", "tls", nil); e == nil {
		c.CloseIdleConnections()
		t.Fatal("HTTP accepted")
	}
}

type setupRoundTripFunc func(*http.Request) (*http.Response, error)

func (f setupRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWindowsSetupExplicitHTTPProfileKeepsOriginalTransport(t *testing.T) {
	var origin string
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		raw, _ := json.Marshal(windowssetup.Expected("manager_00000000000000000000000000000001", origin, origin))
		w.Write(raw)
	}))
	defer server.Close()
	origin = server.URL
	expected := windowssetup.Expected("manager_00000000000000000000000000000001", origin, origin)
	if CheckWindowsSetupManager(context.Background(), origin, "http-test", nil, expected) != nil || calls != 1 {
		t.Fatal("explicit HTTP test not supported")
	}
	for _, profile := range []string{"tls", "", "unknown"} {
		if CheckWindowsSetupManager(context.Background(), origin, profile, nil, expected) == nil {
			t.Fatal("implicit downgrade accepted")
		}
	}
	if CheckWindowsSetupManager(context.Background(), origin, "http-test", []byte("CA"), expected) == nil {
		t.Fatal("HTTP accepted mixed TLS trust")
	}
	if calls != 1 {
		t.Fatal("invalid selection reached network")
	}
}
