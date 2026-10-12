package lanclient

import (
	"context"
	"encoding/json"
	"io"
	"localrmm/internal/windowssetup"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Exercise the exported entry point, including its exact route constructor.
// Calling checkWindowsSetupManager with a fake client misses constructor drift.
func TestWindowsSetupAllContractsReachExactPublicRoute(t *testing.T) {
	constructors := []func(string, string, string) windowssetup.Capabilities{
		windowssetup.Expected, windowssetup.ExpectedReadAdmin,
		windowssetup.ExpectedReadAdminV2, windowssetup.ExpectedReadAdminV3,
		windowssetup.ExpectedReadAdminV4, windowssetup.ExpectedReadAdminV5,
		windowssetup.ExpectedReadAdminV6, windowssetup.ExpectedReadAdminV7,
		windowssetup.ExpectedReadAdminV8, windowssetup.ExpectedReadAdminV9,
		windowssetup.ExpectedReadAdminV10,
	}
	for _, expected := range constructors {
		t.Run(expected("manager", "origin", "origin").SetupContract, func(t *testing.T) {
			for _, mismatch := range []bool{false, true} {
				var calls atomic.Int32
				var want windowssetup.Capabilities
				var path string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.URL.Path != path || r.Method != http.MethodGet || r.ContentLength != 0 || r.Header.Get("Accept") != "application/json" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
						t.Error("unsafe compatibility request")
					}
					response := want
					if mismatch {
						response.ManagerInstanceID = "other-manager"
					}
					w.Header().Set("Content-Type", "application/json")
					raw, _ := json.Marshal(response)
					_, _ = w.Write(raw)
				}))
				want = expected("manager", server.URL, server.URL)
				path, _ = windowssetup.CapabilityPath(want)
				err := CheckWindowsSetupManager(context.Background(), server.URL, "http-test", nil, want)
				server.Close()
				if (err == nil) == mismatch || calls.Load() != 1 {
					t.Fatalf("constructor failed exact route/identity binding: mismatch=%v calls=%d err=%v", mismatch, calls.Load(), err)
				}
			}
		})
	}
}

func TestWindowsSetupCurrentRoutesKeepExactTransportGuards(t *testing.T) {
	paths := []string{windowssetup.CapabilitiesPath, windowssetup.ReadAdminCapabilitiesPath,
		windowssetup.ReadAdminCapabilitiesPathV2, windowssetup.ReadAdminCapabilitiesPathV3,
		windowssetup.ReadAdminCapabilitiesPathV4, windowssetup.ReadAdminCapabilitiesPathV5,
		windowssetup.ReadAdminCapabilitiesPathV6, windowssetup.ReadAdminCapabilitiesPathV7,
		windowssetup.ReadAdminCapabilitiesPathV8, windowssetup.ReadAdminCapabilitiesPathV9,
		windowssetup.ReadAdminCapabilitiesPathV10}
	for _, selected := range paths[7:] {
		t.Run(selected, func(t *testing.T) {
			c, err := newWindowsSetupHTTPClient("http://127.0.0.1", "http-test", nil, selected)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseIdleConnections()
			transport := c.Transport.(*publicBootstrapTransport)
			calls := 0
			transport.next = setupRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody}, nil
			})
			for _, path := range append(append([]string{}, paths...), "/v1/windows/read-admin-setup-capabilities-v11", "/v2/windows/enrollment/claim", PublicBootstrapPathPrefix+publicFixtureInvite) {
				r, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
				response, err := transport.RoundTrip(r)
				if response != nil {
					response.Body.Close()
				}
				if (err == nil) != (path == selected) {
					t.Fatal("transport accepted another route")
				}
			}
			for _, mutation := range []string{"method", "body", "query", "origin", "authorization", "cookie"} {
				r, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1"+selected, nil)
				switch mutation {
				case "method":
					r.Method = http.MethodPost
				case "body":
					r.Body = io.NopCloser(strings.NewReader("fixture"))
				case "query":
					r.URL.RawQuery = "fixture=true"
				case "origin":
					r.URL.Host = "other.example"
				case "authorization":
					r.Header.Set("Authorization", "fixture")
				case "cookie":
					r.Header.Set("Cookie", "fixture")
				}
				if response, err := transport.RoundTrip(r); err == nil {
					response.Body.Close()
					t.Fatalf("accepted mutated request: %s", mutation)
				}
			}
			if calls != 1 {
				t.Fatal("rejected request reached network")
			}
		})
	}
	for _, path := range []string{"", "/arbitrary", windowssetup.ReadAdminCapabilitiesPathV10 + "/", windowssetup.ReadAdminCapabilitiesPathV10 + "?", "/v1/windows/read-admin-setup-capabilities-v11"} {
		if c, err := newWindowsSetupHTTPClient("http://127.0.0.1", "http-test", nil, path); err == nil {
			c.CloseIdleConnections()
			t.Fatal("unrecognized route admitted")
		}
	}
}
