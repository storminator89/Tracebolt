package alarmdelivery

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newWebhookFixture(t *testing.T) *webhook {
	t.Helper()
	b := Binding{ManagerInstanceID: "manager-fixture", Profile: "tls", DestinationID: "primary", Generation: "generation-1"}
	c := Config{enabled: true, binding: b, endpoint: "https://receiver.example.test:443/hook?fixture=endpoint-marker", bearer: "fixture-only-bearer"}
	c.binding.Fingerprint = destinationFingerprint(c.binding, c.endpoint)
	transport, err := NewWebhook(c)
	if err != nil {
		t.Fatal("fixture constructor")
	}
	w := transport.(*webhook)
	w.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	w.dialTLS = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("unexpected_fixture_dial")
	}
	return w
}

func webhookPayloadFixture() Payload {
	return Payload{SchemaVersion: "tracebolt.alarm-event.v1", EventID: "event-fixture", DeviceID: "device-fixture", IncidentID: "incident-fixture", Rule: "offline", Target: "agent", Severity: "warning", Transition: "opened", State: "open", Reason: "agent_stale", ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), TransitionAt: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)}
}

type capturedWebhookRequest struct {
	request *http.Request
	body    []byte
	err     error
}

// A net.Pipe is an in-memory byte stream, not a listening/dialed network socket.
// Its server parses the real standard-library request without sending externally.
func memoryWebhookDial(t *testing.T, captured chan<- capturedWebhookRequest, response func(net.Conn)) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
		go func() {
			defer server.Close()
			req, err := http.ReadRequest(bufio.NewReader(server))
			var body []byte
			if err == nil {
				body, err = io.ReadAll(io.LimitReader(req.Body, MaxPayloadBytes+1))
				_ = req.Body.Close()
			}
			captured <- capturedWebhookRequest{req, body, err}
			if err == nil && response != nil {
				response(server)
			}
		}()
		return client, nil
	}
}

func writeWebhookResponse(status int, headers, body string) func(net.Conn) {
	return func(conn net.Conn) {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d Fixture\r\nContent-Length: %d\r\nConnection: close\r\n%s\r\n%s", status, len(body), headers, body)
	}
}

func TestWebhookPublicAddressPolicy(t *testing.T) {
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8"} {
		if !publicWebhookAddress(netip.MustParseAddr(raw)) {
			t.Fatal("ordinary public address blocked")
		}
	}
	for _, raw := range []string{
		"0.0.0.0", "0.9.1.2", "10.1.2.3", "100.64.0.1", "100.127.255.254", "127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.254", "192.0.0.9", "192.0.2.1", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.168.1.1", "192.175.48.1", "198.18.0.1", "198.19.255.254", "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::808:808", "64:ff9b:1::1", "100::1", "2001::1", "2001:2::1", "2001:20::1", "2001:db8::1", "2002:808:808::1", "2620:4f:8000::1", "3fff::1", "fc00::1", "fd00::1", "fe80::1", "fe80::1%eth0", "ff02::1", "4000::1",
	} {
		if publicWebhookAddress(netip.MustParseAddr(raw)) {
			t.Fatal("nonpublic or special-purpose address allowed")
		}
	}
	if publicWebhookAddress(netip.Addr{}) {
		t.Fatal("invalid address allowed")
	}
}

func TestWebhookExactPinnedRequestNoProxyOrRedirect(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://fixture-proxy.invalid:8888")
	t.Setenv("ALL_PROXY", "http://fixture-proxy.invalid:8888")
	w := newWebhookFixture(t)
	var resolutions, dials atomic.Int32
	w.resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
		if host != "receiver.example.test" {
			t.Error("wrong DNS hostname")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > webhookDeadline {
			t.Error("missing bounded resolver deadline")
		}
		if resolutions.Add(1) > 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
	}
	captured := make(chan capturedWebhookRequest, 1)
	dial := memoryWebhookDial(t, captured, writeWebhookResponse(307, "Location: https://redirect.example.test/other\r\n", ""))
	w.dialTLS = func(ctx context.Context, address, host string) (net.Conn, error) {
		dials.Add(1)
		if address != "8.8.8.8:443" || host != "receiver.example.test" {
			t.Error("dial not pinned to validated address and original TLS name")
		}
		return dial(ctx, address, host)
	}
	payload := webhookPayloadFixture()
	if result := w.Send(context.Background(), payload); result != (Result{Failed, "redirect_blocked"}) {
		t.Fatal("redirect classification")
	}
	got := <-captured
	if got.err != nil {
		t.Fatal("request capture")
	}
	if got.request.Method != "POST" || got.request.Host != "receiver.example.test:443" || got.request.URL.RequestURI() != "/hook?fixture=endpoint-marker" {
		t.Fatal("exact request target changed")
	}
	if got.request.Header.Get("Authorization") != "Bearer fixture-only-bearer" || got.request.Header.Get("Content-Type") != "application/json" || got.request.Header.Get("Idempotency-Key") != "" || got.request.Header.Get("Proxy-Authorization") != "" {
		t.Fatal("unexpected request headers")
	}
	expected, _ := json.Marshal(payload)
	if string(got.body) != string(expected) {
		t.Fatal("payload was not exact fixed-schema JSON")
	}
	if resolutions.Load() != 1 || dials.Load() != 1 {
		t.Fatal("request re-resolved, retried or followed redirect")
	}
}

func TestWebhookAllDNSAnswersMustBePublic(t *testing.T) {
	for _, answers := range [][]netip.Addr{
		{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")},
		{netip.MustParseAddr("2001:4860::8888"), netip.MustParseAddr("::ffff:127.0.0.1")},
		{netip.MustParseAddr("1.1.1.1"), {}},
	} {
		w := newWebhookFixture(t)
		w.resolve = func(context.Context, string) ([]netip.Addr, error) { return answers, nil }
		w.dialTLS = func(context.Context, string, string) (net.Conn, error) {
			t.Error("blocked DNS set was dialed")
			return nil, errors.New("fixture")
		}
		if result := w.Send(context.Background(), webhookPayloadFixture()); result != (Result{Failed, "destination_blocked"}) {
			t.Fatal("mixed DNS set not blocked")
		}
	}
	w := newWebhookFixture(t)
	w.resolve = func(context.Context, string) ([]netip.Addr, error) { return make([]netip.Addr, 65), nil }
	if result := w.Send(context.Background(), webhookPayloadFixture()); result != (Result{Failed, "destination_blocked"}) {
		t.Fatal("unbounded DNS answers accepted")
	}
}

func TestWebhookLiteralAddressHasNoSecondResolution(t *testing.T) {
	for _, tc := range []struct{ endpoint, address, host string }{
		{"https://8.8.8.8/hook", "8.8.8.8:443", "8.8.8.8"},
		{"https://[2606:4700:4700::1111]:443/hook", "[2606:4700:4700::1111]:443", "2606:4700:4700::1111"},
	} {
		w := newWebhookFixture(t)
		w.config.endpoint = tc.endpoint
		w.config.binding.Fingerprint = destinationFingerprint(w.config.binding, tc.endpoint)
		w.resolve = nil
		captured := make(chan capturedWebhookRequest, 1)
		dial := memoryWebhookDial(t, captured, writeWebhookResponse(202, "", ""))
		w.dialTLS = func(ctx context.Context, address, host string) (net.Conn, error) {
			if address != tc.address || host != tc.host {
				t.Error("literal not pinned to original verified peer")
			}
			return dial(ctx, address, host)
		}
		if result := w.Send(context.Background(), webhookPayloadFixture()); result.Outcome != Accepted {
			t.Fatal("valid literal not accepted by fake peer")
		}
		if got := <-captured; got.err != nil {
			t.Fatal("request capture")
		}
	}
}

func TestWebhookClassificationAndNoHiddenRetry(t *testing.T) {
	for _, tc := range []struct {
		status   int
		expected Result
	}{
		{200, Result{Accepted, "provider_accepted"}}, {202, Result{Accepted, "provider_accepted"}}, {204, Result{Accepted, "provider_accepted"}},
		{301, Result{Failed, "redirect_blocked"}}, {400, Result{Failed, "provider_rejected"}}, {401, Result{Failed, "provider_rejected"}}, {403, Result{Failed, "provider_rejected"}},
		{408, Result{Uncertain, "provider_uncertain"}}, {429, Result{Retryable, "provider_rate_limited"}}, {500, Result{Uncertain, "provider_uncertain"}}, {502, Result{Uncertain, "provider_uncertain"}}, {503, Result{Uncertain, "provider_uncertain"}}, {504, Result{Uncertain, "provider_uncertain"}},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			w := newWebhookFixture(t)
			captured := make(chan capturedWebhookRequest, 1)
			dial := memoryWebhookDial(t, captured, writeWebhookResponse(tc.status, "", ""))
			var dials atomic.Int32
			w.dialTLS = func(ctx context.Context, address, host string) (net.Conn, error) {
				dials.Add(1)
				return dial(ctx, address, host)
			}
			if result := w.Send(context.Background(), webhookPayloadFixture()); result != tc.expected {
				t.Fatalf("unexpected outcome: %v", result)
			}
			if got := <-captured; got.err != nil {
				t.Fatal("request capture")
			}
			if dials.Load() != 1 {
				t.Fatal("automatic retry")
			}
		})
	}
}

func TestWebhookPreSendFailureVersusUncertainWrite(t *testing.T) {
	t.Run("DNS failure is definite", func(t *testing.T) {
		w := newWebhookFixture(t)
		w.resolve = func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("private-url-and-token-fixture")
		}
		if result := w.Send(context.Background(), webhookPayloadFixture()); result != (Result{Retryable, "dns_failed"}) {
			t.Fatal("DNS failure not sanitized and retryable")
		}
	})
	t.Run("empty DNS result is definite", func(t *testing.T) {
		w := newWebhookFixture(t)
		w.resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
		if result := w.Send(context.Background(), webhookPayloadFixture()); result != (Result{Retryable, "dns_failed"}) {
			t.Fatal("empty DNS result sent a request")
		}
	})
	t.Run("DNS cancellation is definite", func(t *testing.T) {
		w := newWebhookFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w.resolve = func(ctx context.Context, _ string) ([]netip.Addr, error) {
			cancel()
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if result := w.Send(ctx, webhookPayloadFixture()); result != (Result{Retryable, "dns_failed"}) {
			t.Fatal("DNS cancellation sent a request")
		}
	})
	t.Run("TLS or dial failure is definite", func(t *testing.T) {
		w := newWebhookFixture(t)
		var dials atomic.Int32
		w.dialTLS = func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("private-url-and-token-fixture")
		}
		if result := w.Send(context.Background(), webhookPayloadFixture()); result != (Result{Retryable, "connection_failed"}) {
			t.Fatal("connection failure not sanitized and retryable")
		}
		if dials.Load() != 1 {
			t.Fatal("hidden connection retry")
		}
	})
	t.Run("response lost after request is uncertain", func(t *testing.T) {
		w := newWebhookFixture(t)
		captured := make(chan capturedWebhookRequest, 1)
		w.dialTLS = memoryWebhookDial(t, captured, nil)
		if result := w.Send(context.Background(), webhookPayloadFixture()); result != (Result{Uncertain, "request_uncertain"}) {
			t.Fatal("lost response was made replayable")
		}
		if got := <-captured; got.err != nil || len(got.body) == 0 {
			t.Fatal("fixture did not receive the request")
		}
	})
	t.Run("cancellation after request is uncertain", func(t *testing.T) {
		w := newWebhookFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		captured := make(chan capturedWebhookRequest, 1)
		w.dialTLS = memoryWebhookDial(t, captured, func(net.Conn) { cancel() })
		if result := w.Send(ctx, webhookPayloadFixture()); result != (Result{Uncertain, "request_uncertain"}) {
			t.Fatal("cancellation after write was made replayable")
		}
		if got := <-captured; got.err != nil {
			t.Fatal("request capture")
		}
	})
	t.Run("already cancelled never resolves", func(t *testing.T) {
		w := newWebhookFixture(t)
		w.resolve = nil
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if result := w.Send(ctx, webhookPayloadFixture()); result != (Result{Retryable, "request_cancelled"}) {
			t.Fatal("already cancelled request did work")
		}
	})
}

func TestWebhookBoundedPayloadAndResponse(t *testing.T) {
	w := newWebhookFixture(t)
	w.resolve = nil
	payload := webhookPayloadFixture()
	payload.Reason = strings.Repeat("a", MaxPayloadBytes)
	if result := w.Send(context.Background(), payload); result != (Result{Failed, "invalid_payload"}) {
		t.Fatal("oversized payload resolved or sent")
	}
	for _, tc := range []struct {
		name     string
		response func(net.Conn)
		want     Result
	}{
		{"long body is ignored", writeWebhookResponse(200, "", strings.Repeat("fixture-response-marker", 1024)), Result{Accepted, "provider_accepted"}},
		{"lost body preserves accepted status", func(conn net.Conn) {
			_, _ = io.WriteString(conn, "HTTP/1.1 202 Accepted\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
		}, Result{Accepted, "provider_accepted"}},
		{"oversized headers are uncertain", writeWebhookResponse(200, "X-Oversized: "+strings.Repeat("a", 20000)+"\r\n", ""), Result{Uncertain, "request_uncertain"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWebhookFixture(t)
			captured := make(chan capturedWebhookRequest, 1)
			w.dialTLS = memoryWebhookDial(t, captured, tc.response)
			if result := w.Send(context.Background(), webhookPayloadFixture()); result != tc.want {
				t.Fatal("response bounds/classification")
			}
			if got := <-captured; got.err != nil {
				t.Fatal("request capture")
			}
		})
	}
}

func TestWebhookTLSVerificationAndSnapshotIntegrity(t *testing.T) {
	cfg := verifiedWebhookTLSConfig("receiver.example.test")
	if cfg.ServerName != "receiver.example.test" || cfg.MinVersion < tls.VersionTLS12 || cfg.InsecureSkipVerify || cfg.RootCAs != nil || cfg.VerifyPeerCertificate != nil || cfg.VerifyConnection != nil || len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatal("TLS verification policy weakened")
	}
	w := newWebhookFixture(t)
	c := w.config
	c.endpoint += "-changed"
	if _, err := NewWebhook(c); err != ErrConfiguration {
		t.Fatal("changed endpoint accepted with old routing fingerprint")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		out := fmt.Sprintf(format, w)
		if strings.Contains(out, "endpoint-marker") || strings.Contains(out, "fixture-only-bearer") {
			t.Fatal("webhook diagnostic exposed material")
		}
	}
}
