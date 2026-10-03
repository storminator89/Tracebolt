package telemetry

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/bundle"
	"localrmm/internal/model"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const MaxResponseBytes = 16 * 1024

// Client sends to one fixed literal IPv4 loopback origin. No DNS, environment
// proxy, redirects, credentials, persistent session or target discovery exists.
type Client struct {
	origin string
	http   *http.Client
}

func NewClient(endpoint string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Hostname() != "127.0.0.1" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return nil, errors.New("manager must be an explicit http://127.0.0.1:PORT loopback origin")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != u.Port() || u.Host != "127.0.0.1:"+u.Port() {
		return nil, errors.New("manager must use a canonical explicit loopback port")
	}
	if timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil, errors.New("timeout must be between 100ms and 10s")
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 8 * 1024, ResponseHeaderTimeout: timeout, MaxConnsPerHost: 1}
	return &Client{origin: "http://" + u.Host, http: &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Send performs at most one session GET and one telemetry POST. The existing
// local development CSRF token is used once in memory, never persisted or logged.
func (c *Client) Send(ctx context.Context, raw []byte) (Receipt, error) {
	if _, err := decodeBundle(raw, time.Now().UTC()); err != nil {
		return Receipt{}, err
	}
	// One deadline bounds both requests, not only each individual operation.
	ctx, cancel := context.WithTimeout(ctx, c.http.Timeout)
	defer cancel()
	sessionReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/api/session", nil)
	sessionReq.Header.Set("Origin", c.origin)
	sessionRaw, err := c.request(sessionReq)
	if err != nil {
		return Receipt{}, fmt.Errorf("local manager session: %w", err)
	}
	var session struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := strictJSON(sessionRaw, &session); err != nil {
		return Receipt{}, errors.New("local manager returned an invalid session")
	}
	token, err := hex.DecodeString(session.CSRFToken)
	if err != nil || len(token) != 32 {
		return Receipt{}, errors.New("local manager returned an invalid session token")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/api/dev/telemetry", bytes.NewReader(raw))
	req.Header.Set("Origin", c.origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", session.CSRFToken)
	result, err := c.request(req)
	if err != nil {
		return Receipt{}, fmt.Errorf("local telemetry delivery: %w", err)
	}
	var receipt Receipt
	if err := strictJSON(result, &receipt); err != nil || receipt.DeviceID != DeviceID || receipt.Sequence == 0 || receipt.CollectedAt.IsZero() || receipt.ReceivedAt.IsZero() || receipt.ManagerStartedAt.IsZero() {
		return Receipt{}, errors.New("local manager returned an invalid telemetry receipt")
	}
	return receipt, nil
}
func (c *Client) request(req *http.Request) ([]byte, error) {
	response, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("request failed or timed out")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request rejected (HTTP %d)", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, errors.New("response could not be read")
	}
	if len(raw) > MaxResponseBytes {
		return nil, errors.New("response exceeded size limit")
	}
	return raw, nil
}

// EncodeForTransport preserves the support schema but states this additional
// loopback delivery honestly. The ordinary support-bundle command stays stdout
// only, with its existing privacy declaration unchanged.
func EncodeForTransport(d model.Device) ([]byte, error) {
	raw, err := bundle.Encode(d)
	if err != nil {
		return nil, err
	}
	var b bundle.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	b.Privacy[0] = "Read-only collector data transferred once to an explicitly selected loopback development manager. No service installation or persistent background process."
	for i := range b.Observation.Capabilities {
		if b.Observation.Capabilities[i].ID == "remote_actions" {
			b.Observation.Capabilities[i].Detail = "No command execution, process inventory, or remote control. Only one-shot loopback development telemetry is enabled."
		}
	}
	raw, err = json.Marshal(b)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxBodyBytes {
		return nil, &Error{Code: "payload_too_large", Message: "Telemetry exceeds the 64 KiB limit."}
	}
	return raw, nil
}
