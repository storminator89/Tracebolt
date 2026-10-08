package lanclient

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type bootstrapRouteSink func(*http.Request) (*http.Response, error)

func (f bootstrapRouteSink) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBootstrapRouteFamiliesRemainIsolated(t *testing.T) {
	for _, windows := range []bool{false, true} {
		constructor := NewBootstrapHTTPClient
		prefix, other := "/v2/enrollment/", "/v2/windows/enrollment/"
		if windows {
			constructor = NewWindowsBootstrapHTTPClient
			prefix, other = other, prefix
		}
		client, err := constructor("http://127.0.0.1:1", "http-test", nil)
		if err != nil {
			t.Fatal("constructor failed")
		}
		defer client.CloseIdleConnections()
		tr := client.Transport.(*bootstrapTransport)
		calls := 0
		tr.next = bootstrapRouteSink(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
		})
		for _, verb := range []string{"challenge", "claim", "status", "credential", "activate"} {
			req, _ := http.NewRequest("POST", "http://127.0.0.1:1"+prefix+verb, bytes.NewReader([]byte(`{}`)))
			res, err := client.Do(req)
			if err != nil {
				t.Fatal("fixed route rejected")
			}
			res.Body.Close()
			req, _ = http.NewRequest("POST", "http://127.0.0.1:1"+other+verb, bytes.NewReader([]byte(`{}`)))
			if _, err = client.Do(req); !errors.Is(err, errDestination) {
				t.Fatal("other family accepted")
			}
		}
		if calls != 5 {
			t.Fatal("unexpected sink call count")
		}
	}
}

func TestWindowsBootstrapRouteBoundariesRemainClosed(t *testing.T) {
	const origin = "http://127.0.0.1:1"
	const path = "/v2/windows/enrollment/challenge"
	variants := []struct {
		name string
		edit func(*http.Request)
	}{
		{"method", func(r *http.Request) { r.Method = "GET" }},
		{"origin", func(r *http.Request) { r.URL.Host = "127.0.0.1:2" }},
		{"host", func(r *http.Request) { r.Host = "elsewhere.invalid" }},
		{"scheme", func(r *http.Request) { r.URL.Scheme = "https" }},
		{"query", func(r *http.Request) { r.URL.RawQuery = "x=1" }},
		{"empty_query", func(r *http.Request) { r.URL.ForceQuery = true }},
		{"fragment", func(r *http.Request) { r.URL.Fragment = "x" }},
		{"encoded", func(r *http.Request) { r.URL.RawPath = "/v2/windows/enrollment/%63hallenge" }},
		{"trailing", func(r *http.Request) { r.URL.Path = path + "/" }},
		{"unknown", func(r *http.Request) { r.URL.Path = "/v2/windows/enrollment/unknown" }},
		{"prefix", func(r *http.Request) { r.URL.Path = "/extra" + path }},
		{"dot", func(r *http.Request) { r.URL.Path = "/v2/windows/enrollment/../enrollment/challenge" }},
		{"body", func(r *http.Request) { r.ContentLength = 16385 }},
		{"unknown_body", func(r *http.Request) { r.ContentLength = -1 }},
		{"transfer", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }},
	}
	for _, header := range []string{"Cookie", "Origin", "Authorization", "Proxy-Authorization", "Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		variants = append(variants, struct {
			name string
			edit func(*http.Request)
		}{header, func(r *http.Request) { r.Header.Set(header, "fixed-public-value") }})
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			client, err := NewWindowsBootstrapHTTPClient(origin, "http-test", nil)
			if err != nil {
				t.Fatal("constructor")
			}
			defer client.CloseIdleConnections()
			tr := client.Transport.(*bootstrapTransport)
			tr.next = bootstrapRouteSink(func(*http.Request) (*http.Response, error) { t.Fatal("rejected request reached sink"); return nil, nil })
			req, _ := http.NewRequest("POST", origin+path, bytes.NewReader([]byte(`{}`)))
			v.edit(req)
			if _, err := tr.RoundTrip(req); !errors.Is(err, errDestination) {
				t.Fatal("invalid request accepted")
			}
		})
	}
	if _, err := NewWindowsBootstrapHTTPClient("http://8.8.8.8", "http-test", nil); err == nil {
		t.Fatal("public HTTP origin accepted")
	}
	if _, err := NewWindowsBootstrapHTTPClient("https://127.0.0.1", "tls", nil); err == nil {
		t.Fatal("ambient TLS trust accepted")
	}
}
