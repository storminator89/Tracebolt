package applicationcheck

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/lanconfig"
)

// All test connections are injected net.Pipe pairs. The public-looking fixture
// addresses below are never resolved or dialed through the host network.
func transportTarget(rawURL string) target {
	return target{ID: "fixture", URL: rawURL, AllowedAddresses: []string{"8.8.8.8"}, PlaintextHTTPAcknowledged: strings.HasPrefix(rawURL, "http://")}
}

func transportContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}

type pipeExchange struct {
	requests chan *http.Request
	done     chan struct{}
	calls    atomic.Int32
	dialed   chan string
}

func pipeProbe(t *testing.T, serverTLS *tls.Config, roots *x509.CertPool, response string) (*probe, *pipeExchange) {
	t.Helper()
	fixture := &pipeExchange{requests: make(chan *http.Request, 1), done: make(chan struct{}, 1), dialed: make(chan string, 1)}
	p := &probe{roots: roots, resolve: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}}
	p.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("fixture requires tcp")
		}
		if fixture.calls.Add(1) != 1 {
			return nil, errors.New("unexpected second fixture connection")
		}
		fixture.dialed <- address
		client, server := net.Pipe()
		// Independent fixture deadlines bound failures even if cancellation or
		// transport deadline propagation regresses.
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
			select {
			case <-fixture.done:
			case <-time.After(3 * time.Second):
				t.Error("in-memory HTTP fixture did not terminate")
			}
		})
		go func() {
			defer func() { fixture.done <- struct{}{} }()
			defer server.Close()
			var conn net.Conn = server
			if serverTLS != nil {
				tlsConn := tls.Server(server, serverTLS)
				if tlsConn.HandshakeContext(ctx) != nil {
					return
				}
				conn = tlsConn
			}
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				return
			}
			fixture.requests <- req
			_, _ = io.WriteString(conn, response)
		}()
		return client, nil
	}
	return p, fixture
}

func httpResponse(status int) string {
	return fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, http.StatusText(status))
}

func TestProbeHTTPStatusesAndRequestBoundary(t *testing.T) {
	for _, status := range []int{200, 204, 299, 301, 302, 307, 308, 400, 401, 404, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			response := fmt.Sprintf("HTTP/1.1 %d fixture\r\nLocation: http://127.0.0.1/forbidden\r\nSet-Cookie: fixture-only=unused\r\nX-Fixture: private-response-header\r\nContent-Length: 21\r\nConnection: close\r\n\r\nprivate-response-body", status)
			p, fixture := pipeProbe(t, nil, nil, response)
			r := p.check(transportContext(t), transportTarget("http://fixture.example/status"), lanconfig.TLS, time.Now())
			wantState, wantReason := "http_error", "http_status"
			if status >= 200 && status < 300 {
				wantState, wantReason = "ok", "http_2xx"
			} else if status >= 300 && status < 400 {
				wantReason = "redirect_blocked"
			}
			if r.ID != "fixture" || r.Scheme != "http" || r.State != wantState || r.Reason != wantReason || r.HTTPStatus == nil || *r.HTTPStatus != status || r.TLS.State != "not_applicable" || r.TLS.ExpiresAt != nil {
				t.Fatalf("unexpected status observation: %+v", r)
			}
			if fixture.calls.Load() != 1 {
				t.Fatalf("redirect/retry created %d connections", fixture.calls.Load())
			}
			if got := <-fixture.dialed; got != "8.8.8.8:80" {
				t.Fatalf("dialed %q, want pinned numeric destination", got)
			}
			select {
			case req := <-fixture.requests:
				if req.Method != http.MethodGet || req.Host != "fixture.example" || req.RequestURI != "/status" || req.ContentLength != 0 || len(req.TransferEncoding) != 0 {
					t.Fatalf("unexpected request boundary: %+v", req)
				}
				for key := range req.Header {
					if key != "User-Agent" && key != "Connection" {
						t.Errorf("unexpected request header %q", key)
					}
				}
				if req.Header.Get("User-Agent") != "Tracebolt-ApplicationCheck/1" || !req.Close {
					t.Fatalf("request does not identify itself and close its connection")
				}
				body, err := io.ReadAll(req.Body)
				if err != nil || len(body) != 0 {
					t.Fatalf("request unexpectedly carries a body: len=%d err=%v", len(body), err)
				}
			default:
				t.Fatal("fixture did not receive a request")
			}
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"fixture.example", "/status", "8.8.8.8", "private-response", "fixture-only", "127.0.0.1"} {
				if strings.Contains(string(encoded), forbidden) {
					t.Fatalf("result retained destination or response content %q", forbidden)
				}
			}
		})
	}
}

func TestProbeIgnoresProxyEnvironment(t *testing.T) {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, "http://unapproved-proxy.invalid:3128")
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	p, fixture := pipeProbe(t, nil, nil, httpResponse(200))
	r := p.check(transportContext(t), transportTarget("http://fixture.example:8080/status"), lanconfig.TLS, time.Now())
	if r.State != "ok" || <-fixture.dialed != "8.8.8.8:8080" {
		t.Fatalf("proxy environment altered direct pinned request: %+v", r)
	}
}

func TestProbeResolvesOnceAndPinsAllAnswers(t *testing.T) {
	p, fixture := pipeProbe(t, nil, nil, httpResponse(200))
	var lookups atomic.Int32
	p.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "fixture.example" {
			t.Errorf("resolved unexpected host %q", host)
		}
		if lookups.Add(1) > 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("8.8.8.8")}, nil
	}
	target := transportTarget("http://fixture.example/status")
	target.AllowedAddresses = []string{"8.8.8.8", "9.9.9.9"}
	r := p.check(transportContext(t), target, lanconfig.TLS, time.Now())
	if r.State != "ok" || lookups.Load() != 1 || fixture.calls.Load() != 1 || <-fixture.dialed != "8.8.8.8:80" {
		t.Fatalf("resolution/pinning not stable: result=%+v lookups=%d dials=%d", r, lookups.Load(), fixture.calls.Load())
	}
}

func TestProbeRejectsAnyUnapprovedOrBlockedDNSAnswer(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []string
		allowed   []string
		private   bool
	}{
		{"unapproved second public address", []string{"8.8.8.8", "9.9.9.9"}, []string{"8.8.8.8"}, false},
		{"private answer without opt in", []string{"8.8.8.8", "10.20.30.40"}, []string{"8.8.8.8", "10.20.30.40"}, false},
		{"loopback even with opt in", []string{"8.8.8.8", "127.0.0.1"}, []string{"8.8.8.8", "127.0.0.1"}, true},
		{"metadata even with opt in", []string{"8.8.8.8", "169.254.169.254"}, []string{"8.8.8.8", "169.254.169.254"}, true},
		{"unspecified answer", []string{"8.8.8.8", "0.0.0.0"}, []string{"8.8.8.8", "0.0.0.0"}, true},
		{"IPv6 loopback", []string{"8.8.8.8", "::1"}, []string{"8.8.8.8", "::1"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dials atomic.Int32
			p := &probe{resolve: func(context.Context, string) ([]netip.Addr, error) {
				var addresses []netip.Addr
				for _, s := range tc.addresses {
					addresses = append(addresses, netip.MustParseAddr(s))
				}
				return addresses, nil
			}, dial: func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("forbidden fixture dial")
			}}
			target := transportTarget("http://fixture.example/status")
			target.AllowedAddresses, target.AllowPrivateLAN = tc.allowed, tc.private
			r := p.check(transportContext(t), target, lanconfig.TLS, time.Now())
			if r.State != "unknown" || r.Reason != "destination_blocked" || r.HTTPStatus != nil || dials.Load() != 0 {
				t.Fatalf("unsafe answer was not rejected before dialing: %+v dials=%d", r, dials.Load())
			}
		})
	}
}

func TestProbeLiteralDestinationsAndPrivateOptIn(t *testing.T) {
	for _, tc := range []struct{ ip, address string }{
		{"8.8.8.8", "8.8.8.8:8080"},
		{"10.20.30.40", "10.20.30.40:8080"},
		{"172.16.30.40", "172.16.30.40:8080"},
		{"192.168.30.40", "192.168.30.40:8080"},
		{"fd12:3456::1", "[fd12:3456::1]:8080"},
		{"2606:4700:4700::1111", "[2606:4700:4700::1111]:8080"},
	} {
		t.Run(tc.ip, func(t *testing.T) {
			p, fixture := pipeProbe(t, nil, nil, httpResponse(200))
			p.resolve = func(context.Context, string) ([]netip.Addr, error) {
				t.Error("literal address unexpectedly resolved")
				return nil, errors.New("literal must not resolve")
			}
			target := transportTarget("http://" + tc.address + "/status")
			target.AllowedAddresses, target.AllowPrivateLAN = []string{tc.ip}, true
			r := p.check(transportContext(t), target, lanconfig.TLS, time.Now())
			if r.State != "ok" || <-fixture.dialed != tc.address {
				t.Fatalf("approved literal destination failed: %+v", r)
			}
		})
	}
}

func TestTransportAddressPolicyPermanentlyExcludesSpecialNetworks(t *testing.T) {
	for _, raw := range []string{
		"0.0.0.0", "0.1.2.3", "100.64.0.1", "100.100.100.200", "127.0.0.1", "169.254.169.254", "168.63.129.16",
		"192.0.0.1", "192.0.2.1", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.175.48.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255",
		"::", "::1", "fe80::1", "ff02::1", "64:ff9b::808:808", "64:ff9b:1::1", "100::1", "2001::1", "2001:db8::1", "2002::1", "2620:4f:8000::1", "3fff::1", "fd00:ec2::254", "fd20:ce::254", "fe80::1%fixture",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254",
	} {
		if allowedAddress(netip.MustParseAddr(raw), true) {
			t.Errorf("private-LAN acknowledgement admits forbidden destination %s", raw)
		}
	}
	if allowedAddress(netip.Addr{}, true) {
		t.Error("invalid address admitted")
	}
	for _, raw := range []string{"10.1.2.3", "172.16.0.1", "192.168.1.1", "fd12:3456::1"} {
		ip := netip.MustParseAddr(raw)
		if allowedAddress(ip, false) || !allowedAddress(ip, true) {
			t.Errorf("private destination does not require explicit acknowledgement: %s", raw)
		}
	}
}

func TestProbeFailuresNeverDialFallback(t *testing.T) {
	for _, tc := range []struct {
		name       string
		resolve    func(context.Context, string) ([]netip.Addr, error)
		wantState  string
		wantReason string
		wantDials  int32
	}{
		{"DNS error", func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("fixture DNS failure") }, "network_error", "dns_failed", 0},
		{"no answers", func(context.Context, string) ([]netip.Addr, error) { return nil, nil }, "network_error", "dns_failed", 0},
		{"too many answers", func(context.Context, string) ([]netip.Addr, error) {
			addresses := make([]netip.Addr, MaxAddresses+1)
			for i := range addresses {
				addresses[i] = netip.MustParseAddr("8.8.8.8")
			}
			return addresses, nil
		}, "unknown", "destination_blocked", 0},
		{"dial failure", func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("8.8.8.8")}, nil
		}, "network_error", "request_failed", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dials atomic.Int32
			p := &probe{resolve: tc.resolve, dial: func(ctx context.Context, _, address string) (net.Conn, error) {
				dials.Add(1)
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > CheckTimeout {
					t.Error("dial has no bounded check deadline")
				}
				return nil, errors.New("fixture connection refused")
			}}
			target := transportTarget("http://fixture.example/status")
			target.AllowedAddresses = []string{"8.8.8.8", "9.9.9.9"}
			r := p.check(transportContext(t), target, lanconfig.TLS, time.Now())
			if r.State != tc.wantState || r.Reason != tc.wantReason || r.HTTPStatus != nil || dials.Load() != tc.wantDials {
				t.Fatalf("unexpected failure result %+v, dials=%d", r, dials.Load())
			}
		})
	}
}

func TestProbeRejectsCredentialBearingOrUnacknowledgedURLsBeforeNetwork(t *testing.T) {
	for _, raw := range []string{"http://name:password@fixture.example/", "http://fixture.example/?token=value", "http://fixture.example/#fragment", "ftp://fixture.example/", "http://fixture.example/%2f", "http://fixture.example/../admin"} {
		t.Run(raw, func(t *testing.T) {
			p := &probe{resolve: func(context.Context, string) ([]netip.Addr, error) { t.Error("invalid URL resolved"); return nil, nil }, dial: func(context.Context, string, string) (net.Conn, error) {
				t.Error("invalid URL dialed")
				return nil, nil
			}}
			r := p.check(transportContext(t), transportTarget(raw), lanconfig.TLS, time.Now())
			if r.State != "unknown" || r.Reason != "invalid_configuration" || r.HTTPStatus != nil {
				t.Fatalf("invalid URL was not rejected: %+v", r)
			}
		})
	}
	target := transportTarget("http://fixture.example/")
	target.PlaintextHTTPAcknowledged = false
	r := (&probe{}).check(transportContext(t), target, lanconfig.TLS, time.Now())
	if r.Reason != "invalid_configuration" {
		t.Fatalf("plaintext without acknowledgement was accepted: %+v", r)
	}
}

func TestProbeResponseLimits(t *testing.T) {
	t.Run("oversized headers", func(t *testing.T) {
		p, _ := pipeProbe(t, nil, nil, "HTTP/1.1 200 OK\r\nX-Large: "+strings.Repeat("x", MaxHeaderBytes+1)+"\r\nContent-Length: 0\r\n\r\n")
		r := p.check(transportContext(t), transportTarget("http://fixture.example/"), lanconfig.TLS, time.Now())
		if r.State != "network_error" || r.Reason != "request_failed" || r.HTTPStatus != nil {
			t.Fatalf("oversized response headers accepted: %+v", r)
		}
	})
	t.Run("body stops without EOF", func(t *testing.T) {
		var server net.Conn
		p := &probe{dial: func(context.Context, string, string) (net.Conn, error) {
			client, peer := net.Pipe()
			server = peer
			_ = peer.SetDeadline(time.Now().Add(2 * time.Second))
			go func() {
				defer peer.Close()
				if _, err := http.ReadRequest(bufio.NewReader(peer)); err != nil {
					return
				}
				_, _ = fmt.Fprintf(peer, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", MaxResponseBytes*4)
				_, _ = io.WriteString(peer, strings.Repeat("x", MaxResponseBytes))
				// Never provide the remaining declared bytes. Reaching the local
				// discard limit must close the connection rather than await EOF.
				var b [1]byte
				_, _ = peer.Read(b[:])
			}()
			return client, nil
		}}
		defer func() {
			if server != nil {
				_ = server.Close()
			}
		}()
		started := time.Now()
		r := p.check(transportContext(t), transportTarget("http://8.8.8.8/"), lanconfig.TLS, started)
		if r.State != "ok" || time.Since(started) > time.Second {
			t.Fatalf("bounded body observation waited for unavailable body bytes: %+v", r)
		}
	})
}

func TestProbeCancellation(t *testing.T) {
	t.Run("before resolution", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := (&probe{}).check(ctx, transportTarget("http://fixture.example/"), lanconfig.TLS, time.Now())
		if r.State != "unknown" || r.Reason != "cancelled" || r.HTTPStatus != nil {
			t.Fatalf("unexpected pre-cancelled result %+v", r)
		}
	})
	for _, phase := range []string{"resolution", "dial", "TLS handshake", "response headers", "response body"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(transportContext(t))
			defer cancel()
			entered := make(chan struct{})
			p := &probe{resolve: func(ctx context.Context, _ string) ([]netip.Addr, error) {
				if phase == "resolution" {
					close(entered)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}, dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				if phase == "dial" {
					close(entered)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				client, peer := net.Pipe()
				_ = peer.SetDeadline(time.Now().Add(2 * time.Second))
				t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
				go func() {
					defer peer.Close()
					if phase == "response headers" || phase == "response body" {
						if _, err := http.ReadRequest(bufio.NewReader(peer)); err != nil {
							return
						}
					}
					if phase == "response body" {
						_, _ = io.WriteString(peer, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
					}
					close(entered)
					<-ctx.Done()
				}()
				return client, nil
			}}
			target := transportTarget("http://fixture.example/")
			if phase == "TLS handshake" {
				target = transportTarget("https://fixture.example/")
			}
			finished := make(chan Result, 1)
			go func() { finished <- p.check(ctx, target, lanconfig.TLS, time.Now()) }()
			select {
			case <-entered:
				cancel()
			case <-time.After(time.Second):
				t.Fatal("fixture did not enter cancellation phase")
			}
			select {
			case r := <-finished:
				if r.State != "unknown" || r.Reason != "cancelled" || r.HTTPStatus != nil || r.TLS.ExpiresAt != nil {
					t.Fatalf("cancelled %s retains a misleading observation: %+v", phase, r)
				}
			case <-time.After(time.Second):
				t.Fatal("check did not stop after cancellation")
			}
		})
	}
}

func fixtureCertificate(t *testing.T, host string, notAfter time.Time) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "In-memory application-check fixture CA"}, NotBefore: now.Add(-72 * time.Hour), NotAfter: now.Add(180 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{host}, NotBefore: now.Add(-48 * time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}, roots
}

func TestProbeTLSVerificationAndExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		name, host         string
		expires            time.Time
		trusted            bool
		wantState, wantTLS string
	}{
		{"valid", "fixture.example", now.Add(90 * 24 * time.Hour), true, "ok", "valid"},
		{"expiring", "fixture.example", now.Add(14 * 24 * time.Hour), true, "ok", "expiring"},
		{"expiry threshold", "fixture.example", now.Add(30 * 24 * time.Hour), true, "ok", "expiring"},
		{"untrusted", "fixture.example", now.Add(90 * 24 * time.Hour), false, "tls_error", "unknown"},
		{"expired", "fixture.example", now.Add(-time.Hour), true, "tls_error", "unknown"},
		{"wrong host", "other.example", now.Add(90 * 24 * time.Hour), true, "tls_error", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, roots := fixtureCertificate(t, tc.host, tc.expires)
			if !tc.trusted {
				roots = x509.NewCertPool()
			}
			server := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
			p, fixture := pipeProbe(t, server, roots, httpResponse(200))
			r := p.check(transportContext(t), transportTarget("https://fixture.example/status"), lanconfig.TLS, now)
			if r.Scheme != "https" || r.State != tc.wantState || r.TLS.State != tc.wantTLS || fixture.calls.Load() != 1 {
				t.Fatalf("unexpected TLS observation: %+v dials=%d", r, fixture.calls.Load())
			}
			if r.State == "ok" {
				if r.TLS.ExpiresAt == nil || !r.TLS.ExpiresAt.Equal(tc.expires) || r.HTTPStatus == nil || *r.HTTPStatus != 200 {
					t.Fatalf("verified certificate expiry/status missing: %+v", r)
				}
			} else if r.Reason != "tls_verification_failed" || r.TLS.ExpiresAt != nil || r.HTTPStatus != nil || len(fixture.requests) != 0 {
				t.Fatalf("failed verification sent HTTP or retained success data: %+v", r)
			}
			if got := <-fixture.dialed; got != "8.8.8.8:443" {
				t.Fatalf("TLS dial not pinned: %q", got)
			}
		})
	}
}

func TestProbeRequiresTLS12AndNormalVerification(t *testing.T) {
	config := verifiedTLSConfig("fixture.example", nil)
	if config.MinVersion != tls.VersionTLS12 || config.InsecureSkipVerify || config.ServerName != "fixture.example" || config.RootCAs != nil || config.VerifyPeerCertificate != nil || config.VerifyConnection != nil {
		t.Fatalf("production TLS configuration bypasses ordinary verification: %+v", config)
	}
	cert, roots := fixtureCertificate(t, "fixture.example", time.Now().Add(90*24*time.Hour))
	p, fixture := pipeProbe(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}, roots, httpResponse(200))
	r := p.check(transportContext(t), transportTarget("https://fixture.example/"), lanconfig.TLS, time.Now())
	if r.State != "tls_error" || r.Reason != "tls_handshake_failed" || r.TLS.State != "unknown" || r.TLS.ExpiresAt != nil || r.HTTPStatus != nil || len(fixture.requests) != 0 {
		t.Fatalf("obsolete TLS was accepted or misclassified: %+v", r)
	}
}

func TestProbeTLSValidityIndependentOfHTTPStatus(t *testing.T) {
	for _, tc := range []struct {
		name, response, state string
		status                int
	}{
		{"HTTP failure", httpResponse(500), "http_error", 500},
		{"HTTP malformed", "not an HTTP response\r\n\r\n", "network_error", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expires := time.Now().UTC().Truncate(time.Second).Add(90 * 24 * time.Hour)
			cert, roots := fixtureCertificate(t, "fixture.example", expires)
			p, _ := pipeProbe(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, roots, tc.response)
			r := p.check(transportContext(t), transportTarget("https://fixture.example/"), lanconfig.TLS, time.Now())
			if r.State != tc.state || r.TLS.State != "valid" || r.TLS.ExpiresAt == nil || !r.TLS.ExpiresAt.Equal(expires) {
				t.Fatalf("HTTP outcome erased independently verified TLS observation: %+v", r)
			}
			if tc.status == 0 && r.HTTPStatus != nil || tc.status != 0 && (r.HTTPStatus == nil || *r.HTTPStatus != tc.status) {
				t.Fatalf("incorrect HTTP outcome: %+v", r)
			}
		})
	}
}

func TestProbeCancellationClearsPreviouslyVerifiedTLS(t *testing.T) {
	cert, roots := fixtureCertificate(t, "fixture.example", time.Now().Add(90*24*time.Hour))
	ctx, cancel := context.WithCancel(transportContext(t))
	defer cancel()
	entered := make(chan struct{})
	p := &probe{roots: roots, resolve: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}, dial: func(context.Context, string, string) (net.Conn, error) {
		client, peer := net.Pipe()
		_ = peer.SetDeadline(time.Now().Add(2 * time.Second))
		t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
		go func() {
			defer peer.Close()
			conn := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			if conn.HandshakeContext(ctx) != nil {
				return
			}
			if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
				return
			}
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
			close(entered)
			<-ctx.Done()
		}()
		return client, nil
	}}
	finished := make(chan Result, 1)
	go func() {
		finished <- p.check(ctx, transportTarget("https://fixture.example/"), lanconfig.TLS, time.Now())
	}()
	select {
	case <-entered:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("fixture did not reach verified response body")
	}
	select {
	case r := <-finished:
		if r.State != "unknown" || r.Reason != "cancelled" || r.HTTPStatus != nil || r.TLS.State != "unknown" || r.TLS.ExpiresAt != nil {
			t.Fatalf("cancellation retained verified success data: %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("verified response body did not stop on cancellation")
	}
}

func TestProbeSingleLabelNamePreservesAuthorityAndBlocksLoopback(t *testing.T) {
	p, fixture := pipeProbe(t, nil, nil, httpResponse(200))
	p.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "app" {
			t.Fatal("configured name changed")
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	r := p.check(transportContext(t), transportTarget("http://app/status"), lanconfig.TLS, time.Now())
	if r.State != "ok" {
		t.Fatal("single-label configured target rejected", r)
	}
	if req := <-fixture.requests; req.Host != "app" {
		t.Fatal("resolved name substituted in HTTP Host")
	}
	p = &probe{resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "localhost" {
			t.Fatal("configured name changed")
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}, dial: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("loopback dial attempted")
		return nil, errors.New("forbidden")
	}}
	target := transportTarget("http://localhost/status")
	target.AllowPrivateLAN = true
	target.AllowedAddresses = []string{"127.0.0.1"}
	r = p.check(transportContext(t), target, lanconfig.TLS, time.Now())
	if r.State != "unknown" || r.Reason != "destination_blocked" {
		t.Fatal("single-label DNS bypassed loopback denial", r)
	}
}
