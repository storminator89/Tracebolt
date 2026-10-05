package alarmdelivery

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"
)

const webhookDeadline = 10 * time.Second

// These conservative exclusions include special-purpose services even where a
// registry marks some exceptions globally reachable. IPv6 must also fall in the
// ordinary global-unicast 2000::/3 allocation. IPv4-mapped addresses are checked
// against the IPv4 policy, never treated as an IPv6 bypass.
// Registry coverage checked 2026-10-05:
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
var webhookExcluded = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"), netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
}

func publicWebhookAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range webhookExcluded {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

type webhook struct {
	config Config
	// These narrow private seams permit deterministic in-memory tests. The
	// public constructor always installs public DNS and verified TLS dialing.
	resolve func(context.Context, string) ([]netip.Addr, error)
	dialTLS func(context.Context, string, string) (net.Conn, error)
}

func (*webhook) String() string   { return "alarmdelivery.webhook{redacted}" }
func (*webhook) GoString() string { return "alarmdelivery.webhook{redacted}" }

func NewWebhook(c Config) (Transport, error) {
	if c.enabled {
		if !c.binding.Valid() || c.binding.Fingerprint != destinationFingerprint(c.binding, c.endpoint) {
			return nil, ErrConfiguration
		}
		if _, err := parseWebhookEndpoint(c.endpoint); err != nil {
			return nil, ErrConfiguration
		}
		if c.bearer != "" && !validBearer(c.bearer) {
			return nil, ErrConfiguration
		}
	}
	return &webhook{
		config: c,
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		dialTLS: dialVerifiedWebhookTLS,
	}, nil
}

func dialVerifiedWebhookTLS(ctx context.Context, address, serverName string) (net.Conn, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    verifiedWebhookTLSConfig(serverName),
	}
	// address is a previously validated numeric IP, so this cannot resolve the
	// hostname again. System roots and the original hostname verify the peer.
	return d.DialContext(ctx, "tcp", address)
}

func verifiedWebhookTLSConfig(serverName string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, NextProtos: []string{"http/1.1"}}
}

func (w *webhook) Send(parent context.Context, payload Payload) Result {
	if !w.config.enabled {
		return Result{Failed, "disabled"}
	}
	if parent.Err() != nil {
		return Result{Retryable, "request_cancelled"}
	}
	body, err := json.Marshal(payload)
	if err != nil || len(body) > MaxPayloadBytes {
		return Result{Failed, "invalid_payload"}
	}
	u, err := parseWebhookEndpoint(w.config.endpoint)
	if err != nil {
		return Result{Failed, "invalid_destination"}
	}
	ctx, cancel := context.WithTimeout(parent, webhookDeadline)
	defer cancel()
	host := u.Hostname()
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{literal}
	} else {
		addresses, err = w.resolve(ctx, host)
		if err != nil || len(addresses) == 0 {
			return Result{Retryable, "dns_failed"}
		}
	}
	if len(addresses) > 64 {
		return Result{Failed, "destination_blocked"}
	}
	for _, address := range addresses {
		if !publicWebhookAddress(address) {
			return Result{Failed, "destination_blocked"}
		}
	}
	pinned := net.JoinHostPort(addresses[0].Unmap().String(), "443")
	var dialed, handedToHTTP atomic.Bool
	transport := &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxResponseHeaderBytes: 16384,
		ResponseHeaderTimeout:  5 * time.Second,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("webhook_tls_required")
		},
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Even an unexpected standard-library retry cannot open a second
			// connection or send a second request within this attempt.
			if !dialed.CompareAndSwap(false, true) {
				return nil, errors.New("webhook_retry_blocked")
			}
			conn, err := w.dialTLS(ctx, pinned, host)
			if err != nil || conn == nil {
				return nil, errors.New("webhook_connection_failed")
			}
			// Once the connection is handed to HTTP, another goroutine could
			// write even while cancellation is returning. Mark ambiguity here,
			// before that handoff, rather than racing a Write callback.
			handedToHTTP.Store(true)
			return conn, nil
		},
	}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.config.endpoint, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return Result{Failed, "invalid_destination"}
	}
	req.ContentLength = int64(len(body))
	req.GetBody = nil
	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Tracebolt-AlarmDelivery/1")
	if w.config.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+w.config.bearer)
	}
	// RoundTrip performs exactly one POST and never follows a redirect. There
	// is deliberately no Idempotency-Key or undocumented provider dedup promise.
	resp, err := transport.RoundTrip(req)
	if err != nil {
		if handedToHTTP.Load() {
			return Result{Uncertain, "request_uncertain"}
		}
		return Result{Retryable, "connection_failed"}
	}
	defer resp.Body.Close()
	// Only status is used. Never retain/log response content, and never read an
	// unbounded body. A body failure cannot undo an already received 2xx status.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return Result{Accepted, "provider_accepted"}
	case resp.StatusCode == http.StatusTooManyRequests:
		return Result{Retryable, "provider_rate_limited"}
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500:
		return Result{Uncertain, "provider_uncertain"}
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return Result{Failed, "redirect_blocked"}
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return Result{Failed, "provider_rejected"}
	default:
		return Result{Uncertain, "provider_uncertain"}
	}
}
