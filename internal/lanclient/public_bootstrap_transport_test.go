package lanclient

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const publicFixtureInvite = "invite_00000000000000000000000000000001"

func TestPublicBootstrapTransportPinsOneBodylessPublicRoute(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte(`{}`)) }))
	defer server.Close()
	client, e := NewPublicBootstrapHTTPClient(server.URL, "http-test", nil, publicFixtureInvite)
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	exact := server.URL + PublicBootstrapPathPrefix + publicFixtureInvite
	req, _ := http.NewRequest("GET", exact, nil)
	resp, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	for _, test := range []string{"method", "body", "length", "transfer", "trailer", "host", "origin", "path", "other-id", "query", "empty-query", "fragment", "userinfo", "escaped", "encoding", "range", "cookie", "authorization", "forwarded", "content-type"} {
		t.Run(test, func(t *testing.T) {
			r, _ := http.NewRequest("GET", exact, nil)
			switch test {
			case "method":
				r.Method = "POST"
			case "body":
				r.Body = io.NopCloser(bytes.NewReader(nil))
			case "length":
				r.ContentLength = 1
			case "transfer":
				r.TransferEncoding = []string{"chunked"}
			case "trailer":
				r.Trailer = http.Header{"X-Test": []string{"yes"}}
			case "host":
				r.Host = "other.local"
			case "origin":
				r.URL.Host = "localhost:1"
			case "path":
				r.URL.Path = "/v2/enrollment/challenge"
			case "other-id":
				r.URL.Path = PublicBootstrapPathPrefix + "invite_00000000000000000000000000000002"
			case "query":
				r.URL.RawQuery = "token=fixture"
			case "empty-query":
				r.URL.ForceQuery = true
			case "fragment":
				r.URL.Fragment = "fragment"
			case "userinfo":
				r.URL.User = url.User("user")
			case "escaped":
				r.URL.RawPath = strings.Replace(r.URL.Path, "invite", "%69nvite", 1)
			case "encoding":
				r.Header.Set("Accept-Encoding", "gzip")
			case "range":
				r.Header.Set("Range", "bytes=0-1")
			case "cookie":
				r.Header.Set("Cookie", "fixture-only")
			case "authorization":
				r.Header.Set("Authorization", "fixture-only")
			case "forwarded":
				r.Header.Set("Forwarded", "for=127.0.0.1")
			case "content-type":
				r.Header.Set("Content-Type", "application/json")
			}
			if resp, e := client.Transport.RoundTrip(r); e == nil {
				resp.Body.Close()
				t.Fatal("unbound request permitted")
			}
		})
	}
	if calls.Load() != 1 {
		t.Fatal("rejected request reached server")
	}
}
func TestPublicBootstrapRedirectIsNeverFollowed(t *testing.T) {
	var elsewhere atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere.Add(1) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+PublicBootstrapPathPrefix+publicFixtureInvite, 307)
	}))
	defer server.Close()
	client, e := NewPublicBootstrapHTTPClient(server.URL, "http-test", nil, publicFixtureInvite)
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	r, _ := http.NewRequestWithContext(context.Background(), "GET", server.URL+PublicBootstrapPathPrefix+publicFixtureInvite, nil)
	resp, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 307 || elsewhere.Load() != 0 {
		t.Fatal("redirect followed")
	}
}
func TestPublicBootstrapTransportUsesSharedDNSVetting(t *testing.T) {
	client, e := NewPublicBootstrapHTTPClient("https://manager.example", "tls", nil, publicFixtureInvite)
	if e == nil {
		client.CloseIdleConnections()
		t.Fatal("implicit TLS trust")
	}
	for _, ip := range []string{"169.254.169.254", "100.100.100.200", "168.63.129.16", "fd00:ec2::254", "::", "fe80::1", "224.0.0.1", "192.0.2.1"} {
		addr := netip.MustParseAddr(ip)
		if vettedAddresses([]netip.Addr{netip.MustParseAddr("127.0.0.1"), addr}, false) || vettedAddresses([]netip.Addr{addr}, true) {
			t.Fatal("unsafe or mixed DNS answer accepted")
		}
	}
	for _, origin := range []string{"http://169.254.169.254", "http://8.8.8.8", "http://127.0.0.1:080", "http://127.0.0.1/", "http://localhost?", "http://127.0.0.1#x"} {
		if c, e := NewPublicBootstrapHTTPClient(origin, "http-test", nil, publicFixtureInvite); e == nil {
			c.CloseIdleConnections()
			t.Fatal("invalid origin accepted")
		}
	}
}

func TestPublicBootstrapRejectsNoncanonicalHeaderMapKeys(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	client, e := NewPublicBootstrapHTTPClient(server.URL, "http-test", nil, publicFixtureInvite)
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	for _, name := range []string{"cookie", "aUtHoRiZaTiOn", "x-forwarded-for", "X-FoRwArDeD-Proto", "X-Real-IP", "content-length", "unknown-header"} {
		r, _ := http.NewRequest("GET", server.URL+PublicBootstrapPathPrefix+publicFixtureInvite, nil)
		r.Header = map[string][]string{name: {"fixture"}}
		if resp, e := client.Transport.RoundTrip(r); e == nil {
			resp.Body.Close()
			t.Fatal("raw header passed", name)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("raw credential header sent")
	}
}
