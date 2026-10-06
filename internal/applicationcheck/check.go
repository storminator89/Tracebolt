package applicationcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"
)

var errTLS = errors.New("tls_handshake_failed")
var errTLSVerification = errors.New("tls_verification_failed")
var errRetry = errors.New("connection_retry_blocked")

// All injection seams are private. Production always uses numeric TCP dialing
// and normal hostname/system-root certificate verification, including HTTP-test.
type probe struct {
	resolve func(context.Context, string) ([]netip.Addr, error)
	dial    func(context.Context, string, string) (net.Conn, error)
	roots   *x509.CertPool // nil in production; in-memory fixture CA in tests only
}

func newProbe() *probe {
	d := &net.Dialer{Timeout: CheckTimeout}
	return &probe{resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}, dial: d.DialContext}
}
func verifiedTLSConfig(host string, roots *x509.CertPool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: roots, NextProtos: []string{"http/1.1"}}
}
func (p *probe) checkHTTP(parent context.Context, t target, profile string, now time.Time) (result Result) {
	result = Result{ID: t.ID, State: "unknown", Reason: "not_checked", TLS: TLSResult{State: "unknown"}}
	u, e := parseURL(t.URL, profile, t.PlaintextHTTPAcknowledged)
	if e != nil {
		result.Reason = "invalid_configuration"
		return result
	}
	result.Scheme = u.Scheme
	if u.Scheme == "http" {
		result.TLS.State = "not_applicable"
	}
	defer func() {
		if parent.Err() != nil {
			result.State, result.Reason, result.HTTPStatus = "unknown", "cancelled", nil
			result.TLS = TLSResult{State: "unknown"}
			if result.Scheme == "http" {
				result.TLS.State = "not_applicable"
			}
		}
	}()
	if parent.Err() != nil {
		result.Reason = "cancelled"
		return result
	}
	ctx, cancel := context.WithTimeout(parent, CheckTimeout)
	defer cancel()
	host := u.Hostname()
	addresses, reason := p.resolveAllowed(ctx, host, t)
	if reason != "" {
		result.Reason = reason
		if reason == "dns_failed" || reason == "timeout" {
			result.State = "network_error"
		}
		return result
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	pinned := net.JoinHostPort(addresses[0].Unmap().String(), port)
	var dialed atomic.Bool
	verified := make(chan TLSResult, 1)
	connect := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != net.JoinHostPort(host, port) || !dialed.CompareAndSwap(false, true) {
			return nil, errRetry
		}
		conn, e := p.dial(ctx, "tcp", pinned)
		if e != nil {
			return nil, e
		}
		if conn == nil {
			return nil, errors.New("connection_failed")
		}
		deadline, _ := ctx.Deadline()
		if conn.SetDeadline(deadline) != nil {
			conn.Close()
			return nil, errors.New("connection_deadline_failed")
		}
		if u.Scheme == "http" {
			return conn, nil
		}
		tc := tls.Client(conn, verifiedTLSConfig(host, p.roots))
		if e = tc.HandshakeContext(ctx); e != nil {
			conn.Close()
			var certificateError *tls.CertificateVerificationError
			if errors.As(e, &certificateError) {
				return nil, errTLSVerification
			}
			return nil, errTLS
		}
		state := tc.ConnectionState()
		if !state.HandshakeComplete || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			tc.Close()
			return nil, errTLSVerification
		}
		expires := state.PeerCertificates[0].NotAfter.UTC()
		tlsResult := TLSResult{State: "valid", ExpiresAt: &expires}
		if !expires.After(now.Add(30 * 24 * time.Hour)) {
			tlsResult.State = "expiring"
		}
		verified <- tlsResult
		return tc, nil
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, MaxResponseHeaderBytes: MaxHeaderBytes, ResponseHeaderTimeout: CheckTimeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if u.Scheme != "http" {
				return nil, errTLS
			}
			return connect(ctx, network, address)
		},
		DialTLSContext: connect,
	}
	defer transport.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	if e != nil {
		result.Reason = "invalid_configuration"
		return result
	}
	req.Close = true
	req.Header.Set("User-Agent", "Tracebolt-ApplicationCheck/1")
	// RoundTrip, unlike Client.Do, never follows redirects. No cookie jar, auth,
	// arbitrary headers, body, proxy, or inherited environment is consulted.
	response, e := transport.RoundTrip(req)
	select {
	case observation := <-verified:
		result.TLS = observation
	default:
	}
	if e != nil {
		switch {
		case errors.Is(e, errTLSVerification):
			result.State = "tls_error"
			result.Reason = "tls_verification_failed"
		case errors.Is(e, errTLS):
			result.State = "tls_error"
			result.Reason = "tls_handshake_failed"
		case parent.Err() != nil:
			result.State = "unknown"
			result.Reason = "cancelled"
		case ctx.Err() != nil:
			result.State = "network_error"
			result.Reason = "timeout"
		default:
			result.State = "network_error"
			result.Reason = "request_failed"
		}
		return result
	}
	defer response.Body.Close()
	// Content is discarded, never retained or interpreted. A received status is
	// still a header/status observation when its optional response body is broken.
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, MaxResponseBytes))
	status := response.StatusCode
	result.HTTPStatus = &status
	if status >= 200 && status < 300 {
		result.State = "ok"
		result.Reason = "http_2xx"
	} else {
		result.State = "http_error"
		result.Reason = "http_status"
		if status >= 300 && status < 400 {
			result.Reason = "redirect_blocked"
		}
	}
	return result
}
