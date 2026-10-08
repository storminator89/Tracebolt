package lanclient

import (
	"localrmm/internal/lantrust"
	"net/http"
	"net/netip"
)

// NewBootstrapHTTPClient provides the same vetted/pinned destination policy as
// the native sender, without a client certificate before enrollment. Trust is
// explicit local bootstrap input. This constructor performs no DNS/network I/O.
// The wrapper restricts requests to the exact enrollment origin and fixed paths.
func NewBootstrapHTTPClient(origin, profile string, serverCAPEM []byte) (*http.Client, error) {
	return newBootstrapHTTPClient(origin, profile, serverCAPEM, "/v2/enrollment/")
}

// NewWindowsBootstrapHTTPClient pins only the five Windows inventory enrollment
// routes. It does not enable enrollment, create an identity, or grant consent.
// All destination, TLS, redirect, header and body restrictions are unchanged.
func NewWindowsBootstrapHTTPClient(origin, profile string, serverCAPEM []byte) (*http.Client, error) {
	return newBootstrapHTTPClient(origin, profile, serverCAPEM, "/v2/windows/enrollment/")
}

func newBootstrapHTTPClient(origin, profile string, serverCAPEM []byte, pathPrefix string) (*http.Client, error) {
	scheme := "https"
	if profile == "http-test" {
		scheme = "http"
	} else if profile != "tls" {
		return nil, ErrConfiguration
	}
	u, e := canonicalOrigin(origin, scheme)
	if e != nil {
		return nil, ErrConfiguration
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil && !vettedAddresses([]netip.Addr{ip}, profile == "http-test") {
		return nil, ErrConfiguration
	}
	var client *http.Client
	if profile == "tls" {
		config, e := lantrust.ServerTLSConfig(serverCAPEM, u.Hostname())
		if e != nil {
			return nil, ErrConfiguration
		}
		client = newHTTPClient(config, false)
	} else {
		if len(serverCAPEM) != 0 {
			return nil, ErrConfiguration
		}
		client = newHTTPClient(nil, true)
	}
	client.Transport = &bootstrapTransport{origin: origin, authority: u.Host, pathPrefix: pathPrefix, next: client.Transport}
	return client, nil
}

type bootstrapTransport struct {
	origin, authority, pathPrefix string
	next                          http.RoundTripper
}

func (t *bootstrapTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil || r.URL == nil || r.Method != "POST" || r.URL.Scheme+"://"+r.URL.Host != t.origin || r.URL.User != nil || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.RawFragment != "" || r.URL.Opaque != "" || r.URL.EscapedPath() != r.URL.Path || (r.Host != "" && r.Host != t.authority) {
		return nil, errDestination
	}
	switch r.URL.Path {
	case t.pathPrefix + "challenge", t.pathPrefix + "claim", t.pathPrefix + "status", t.pathPrefix + "credential", t.pathPrefix + "activate":
	default:
		return nil, errDestination
	}
	for _, h := range []string{"Cookie", "Origin", "Authorization", "Proxy-Authorization", "Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if len(r.Header.Values(h)) > 0 {
			return nil, errDestination
		}
	}
	if r.ContentLength < 0 || r.ContentLength > 16*1024 || len(r.TransferEncoding) > 0 {
		return nil, errDestination
	}
	return t.next.RoundTrip(r)
}
func (t *bootstrapTransport) CloseIdleConnections() {
	if closer, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
