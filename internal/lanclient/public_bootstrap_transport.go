package lanclient

import (
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lantrust"
	"net/http"
	"net/netip"
	"strings"
)

const PublicBootstrapPathPrefix = "/v2/enrollment/bootstrap/"

// NewPublicBootstrapHTTPClient permits only a bodyless GET for the exact public
// invitation ID at the selected origin. It does not extend the separate
// POST-only proof transport. Construction performs no DNS or network I/O.
func NewPublicBootstrapHTTPClient(origin, profile string, serverCAPEM []byte, invitationID string) (*http.Client, error) {
	if !enrollmentcrypto.ValidID(invitationID, "invite_") {
		return nil, ErrConfiguration
	}
	scheme := "https"
	if profile == "http-test" {
		scheme = "http"
	} else if profile != "tls" {
		return nil, ErrConfiguration
	}
	u, err := canonicalOrigin(origin, scheme)
	if err != nil {
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
	client.Transport = &publicBootstrapTransport{origin: origin, authority: u.Host, path: PublicBootstrapPathPrefix + invitationID, next: client.Transport}
	return client, nil
}

type publicBootstrapTransport struct {
	origin, authority, path string
	next                    http.RoundTripper
}

func (t *publicBootstrapTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil || r.URL == nil || r.Method != http.MethodGet || r.URL.Scheme+"://"+r.URL.Host != t.origin || r.URL.User != nil || r.URL.Path != t.path || r.URL.EscapedPath() != r.URL.Path || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.RawFragment != "" || r.URL.Opaque != "" || (r.Host != "" && r.Host != t.authority) || r.ContentLength != 0 || (r.Body != nil && r.Body != http.NoBody) || len(r.TransferEncoding) > 0 || len(r.Trailer) > 0 {
		return nil, errDestination
	}
	// The helper constructs only Accept. Check actual map keys so even a
	// directly constructed noncanonical http.Header cannot smuggle credentials.
	for name := range r.Header {
		if !strings.EqualFold(name, "Accept") {
			return nil, errDestination
		}
	}

	return t.next.RoundTrip(r)
}
func (t *publicBootstrapTransport) CloseIdleConnections() {
	if closer, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
