// Package operatorfactorclient provides the narrow, non-browser live-factor API.
// It never retries a mutation or persists a session or a supplied credential.
package operatorfactorclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	ErrConfiguration   = errors.New("factor client configuration rejected")
	ErrUnsupported     = errors.New("factor server profile unsupported")
	ErrUnauthenticated = errors.New("factor authentication rejected")
	ErrForbidden       = errors.New("factor operation forbidden")
	ErrConflict        = errors.New("factor revision conflict")
	ErrRejected        = errors.New("factor operation rejected")
	ErrUncertain       = errors.New("factor operation outcome uncertain; do not retry")
	ErrUnavailable     = errors.New("factor server unavailable")
)

func Code(err error) string {
	if err == nil {
		return "ok"
	}
	for _, entry := range []struct {
		err  error
		code string
	}{{ErrConfiguration, "configuration"}, {ErrUnsupported, "unsupported"}, {ErrUnauthenticated, "unauthenticated"}, {ErrForbidden, "forbidden"}, {ErrConflict, "conflict"}, {ErrRejected, "rejected"}, {ErrUncertain, "uncertain"}, {ErrUnavailable, "unavailable"}} {
		if errors.Is(err, entry.err) {
			return entry.code
		}
	}
	return "unavailable"
}

type Config struct {
	Origin            string
	ServerCertificate []byte
}
type Account struct {
	ID               string   `json:"id"`
	Revision         uint64   `json:"revision"`
	Disabled         bool     `json:"disabled"`
	Uncertain        bool     `json:"uncertain"`
	FactorState      string   `json:"factorState,omitempty"`
	FactorGeneration uint64   `json:"factorGeneration,omitempty"`
	Capabilities     []string `json:"capabilities"`
}
type Client struct{ *clientState }
type clientState struct {
	mu             sync.Mutex
	origin         string
	transport      *http.Transport
	http           *http.Client
	token, csrf    []byte
	actor          string
	manage         bool
	sessionExpires time.Time
	closed         bool
}

func (Client) String() string               { return "operatorfactorclient.Client{redacted}" }
func (Client) GoString() string             { return "operatorfactorclient.Client{redacted}" }
func (Client) MarshalJSON() ([]byte, error) { return []byte(`{"client":"redacted"}`), nil }
func (Config) MarshalJSON() ([]byte, error) { return []byte(`{"config":"redacted"}`), nil }
func (Config) String() string               { return "operatorfactorclient.Config{redacted}" }
func (Config) GoString() string             { return "operatorfactorclient.Config{redacted}" }
func canonicalOrigin(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 512 || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Host == "" {
		return nil, false
	}
	host := u.Hostname()
	canonical := host
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return nil, false
		}
		canonical = address.String()
		if address.Is6() {
			canonical = "[" + canonical + "]"
		}
	} else {
		if host != strings.ToLower(host) || len(host) > 253 {
			return nil, false
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, false
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return nil, false
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != port {
			return nil, false
		}
		canonical += ":" + port
	}
	if u.Host != canonical || raw != "https://"+canonical {
		return nil, false
	}
	return u, true
}
func New(cfg Config) (*Client, error) {
	u, ok := canonicalOrigin(cfg.Origin)
	if !ok {
		return nil, ErrConfiguration
	}
	raw := cfg.ServerCertificate
	if len(raw) == 0 || len(raw) > 65536 {
		return nil, ErrConfiguration
	}
	if block, rest := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrConfiguration
		}
		raw = block.Bytes
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil || !bytes.Equal(raw, cert.Raw) {
		return nil, ErrConfiguration
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: u.Hostname(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, ErrConfiguration
	}
	pin := bytes.Clone(cert.Raw)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: u.Hostname(), NextProtos: []string{"http/1.1"}, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, pin) {
			return ErrConfiguration
		}
		return nil
	}}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, MaxResponseHeaderBytes: 16384}
	c := &Client{clientState: &clientState{origin: cfg.Origin, transport: tr}}
	c.http = &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c, nil
}
func (c *Client) clearSession() {
	clear(c.token)
	clear(c.csrf)
	c.token = nil
	c.csrf = nil
	c.actor = ""
	c.manage = false
	c.sessionExpires = time.Time{}
}
func (c *Client) Close() {
	if c == nil || c.clientState == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearSession()
	c.closed = true
	c.transport.CloseIdleConnections()
}
func (c *Client) ActorID() string {
	if c == nil || c.clientState == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !time.Now().Before(c.sessionExpires) {
		return ""
	}
	return c.actor
}
func (c *Client) CanManageAccounts() bool {
	if c == nil || c.clientState == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.manage && !c.closed && len(c.token) > 0 && time.Now().Before(c.sessionExpires)
}

// All paths are constants at callsites. No server-supplied URL is followed.
func (c *Client) request(ctx context.Context, method, path string, body []byte, session bool) (*http.Response, []byte, error) {
	if c.closed || ctx == nil {
		return nil, nil, ErrConfiguration
	}
	mutation := method == http.MethodPost
	failure := ErrUnavailable
	if mutation {
		failure = ErrUncertain
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, failure
	}
	req.GetBody = nil // Never install a replay source, even for a rewindable JSON body.
	req.Header.Set("Origin", c.origin)
	req.Header.Set("Accept", "application/json")
	if mutation {
		req.Header.Set("Content-Type", "application/json")
	}
	if session {
		if len(c.token) == 0 {
			return nil, nil, ErrUnauthenticated
		}
		req.AddCookie(&http.Cookie{Name: "__Host-tracebolt-session", Value: string(c.token)})
		if mutation {
			req.Header.Set("X-CSRF-Token", string(c.csrf))
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, failure
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		clear(raw)
		return nil, nil, failure
	}
	if resp.StatusCode != http.StatusOK {
		clear(raw)
		switch resp.StatusCode {
		case 400, 429:
			return resp, nil, ErrRejected
		case 401:
			if session {
				c.clearSession()
			}
			return resp, nil, ErrUnauthenticated
		case 403:
			return resp, nil, ErrForbidden
		case 409:
			return resp, nil, ErrConflict
		default:
			return resp, nil, failure
		}
	}
	if !jsonMediaType(resp.Header) || resp.Header.Get("Content-Encoding") != "" {
		clear(raw)
		return resp, nil, failure
	}
	return resp, raw, nil
}

func jsonMediaType(header http.Header) bool {
	values := header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	media, params, err := mime.ParseMediaType(values[0])
	if err != nil || media != "application/json" {
		return false
	}
	for key, value := range params {
		if key != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

// Reject duplicate keys at every nesting level, trailing JSON and unknown fields.
func decode(raw []byte, out any) bool {
	if !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if !uniqueJSON(d, 0) {
		return false
	}
	if _, e := d.Token(); e != io.EOF {
		return false
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out) == nil
}
func uniqueJSON(d *json.Decoder, depth int) bool {
	if depth > 32 {
		return false
	}
	t, e := d.Token()
	if e != nil {
		return false
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return true
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			s, ok := key.(string)
			if e != nil || !ok || seen[s] {
				return false
			}
			seen[s] = true
			if !uniqueJSON(d, depth+1) {
				return false
			}
		}
		end, e := d.Token()
		return e == nil && end == json.Delim('}')
	case '[':
		for d.More() {
			if !uniqueJSON(d, depth+1) {
				return false
			}
		}
		end, e := d.Token()
		return e == nil && end == json.Delim(']')
	}
	return false
}
func hexValue(s string, n int) bool {
	if len(s) != n {
		return false
	}
	raw, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(raw) == s
}
func actorID(s string) bool {
	return strings.HasPrefix(s, "operator_") && hexValue(strings.TrimPrefix(s, "operator_"), 32) && s != "operator_"+strings.Repeat("0", 32)
}
func validCaps(caps []string) bool {
	if caps == nil || len(caps) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, cap := range caps {
		if seen[cap] {
			return false
		}
		// The supported protocol has a finite grant vocabulary. Unknown strings
		// must not become status output or accidental display authority.
		switch cap {
		case "read", "plan_updates", "execute_updates", "restart_service",
			"windows_service_control", "windows_update_install", "windows_update_download",
			"windows_update_schedule", "windows_software_install", "windows_managed_msi_deliver",
			"windows_managed_msi_install", "windows_managed_msi_schedule", "manage_alarms",
			"manage_application_checks", "manage_sessions", "read_customers", "manage_accounts":
		default:
			return false
		}
		seen[cap] = true
	}
	return seen["read"]
}

type authView struct {
	LoginMode              string     `json:"loginMode"`
	LoginFactorProfile     string     `json:"loginFactorProfile"`
	ActorID                *string    `json:"actorId"`
	Capabilities           []string   `json:"capabilities"`
	Mode                   string     `json:"mode"`
	Transport              string     `json:"transport"`
	InsecureTestMode       bool       `json:"insecureTestMode"`
	TransportWarning       *string    `json:"transportWarning"`
	AuthenticationRequired bool       `json:"authenticationRequired"`
	Authenticated          bool       `json:"authenticated"`
	CSRFToken              *string    `json:"csrfToken"`
	ServerNow              time.Time  `json:"serverNow"`
	ExpiresAt              *time.Time `json:"expiresAt"`
	ExpiresInSeconds       *int       `json:"expiresInSeconds"`
}

func decodeAuth(raw []byte, v *authView) bool {
	if !decode(raw, v) {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, key := range []string{"loginMode", "loginFactorProfile", "actorId", "capabilities", "mode", "transport", "insecureTestMode", "transportWarning", "authenticationRequired", "authenticated", "csrfToken", "serverNow", "expiresAt", "expiresInSeconds"} {
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	for _, key := range []string{"insecureTestMode", "authenticated"} {
		if bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
			return false
		}
	}
	return true
}
func (v authView) profile() bool {
	return v.LoginMode == "named" && v.LoginFactorProfile == "totp-sha256-8" && v.Mode == "lan" && v.Transport == "https" && !v.InsecureTestMode && v.TransportWarning == nil && v.AuthenticationRequired && !v.ServerNow.IsZero()
}
func (v authView) loggedOut() bool {
	return v.profile() && !v.Authenticated && v.ActorID == nil && v.CSRFToken == nil && v.ExpiresAt == nil && v.ExpiresInSeconds == nil && v.Capabilities != nil && len(v.Capabilities) == 0
}
func (c *Client) check(ctx context.Context) error {
	resp, raw, err := c.request(ctx, "GET", "/api/auth/session", nil, false)
	if err != nil {
		return err
	}
	defer clear(raw)
	var v authView
	if len(resp.Header.Values("Set-Cookie")) != 0 || !decodeAuth(raw, &v) || !v.loggedOut() {
		return ErrUnsupported
	}
	return nil
}
func (c *Client) Check(ctx context.Context) error {
	if c == nil || c.clientState == nil {
		return ErrConfiguration
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.check(ctx)
}
func credentialInput(password, otp []byte, optional bool) bool {
	if len(password) == 0 || len(password) > 1024 {
		return false
	}
	if optional && len(otp) == 0 {
		return true
	}
	if len(otp) != 8 {
		return false
	}
	for _, b := range otp {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}
func (c *Client) Login(ctx context.Context, username string, password, otp []byte) error {
	if c == nil || c.clientState == nil {
		return ErrConfiguration
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.token) != 0 || len(username) == 0 || len(username) > 128 || !credentialInput(password, otp, true) {
		return ErrRejected
	}
	if err := c.check(ctx); err != nil {
		return err
	}
	body, _ := json.Marshal(struct {
		Username string `json:"username"`
		Password string `json:"password"`
		OTP      string `json:"otp"`
	}{username, string(password), string(otp)})
	defer clear(body)
	resp, raw, err := c.request(ctx, "POST", "/api/auth/login", body, false)
	if err != nil {
		return err
	}
	defer clear(raw)
	var v authView
	if !decodeAuth(raw, &v) || !v.profile() || !v.Authenticated || v.ActorID == nil || !actorID(*v.ActorID) || v.CSRFToken == nil || !hexValue(*v.CSRFToken, 64) || !validCaps(v.Capabilities) || v.ExpiresAt == nil || !v.ExpiresAt.After(v.ServerNow) || v.ExpiresInSeconds == nil || *v.ExpiresInSeconds <= 0 || *v.ExpiresInSeconds > 3600 {
		return ErrUncertain
	}
	remaining := v.ExpiresAt.Sub(v.ServerNow)
	if remaining > time.Hour || int(math.Ceil(remaining.Seconds())) != *v.ExpiresInSeconds {
		return ErrUncertain
	}
	cookies := resp.Cookies()
	if len(resp.Header.Values("Set-Cookie")) != 1 || len(cookies) != 1 {
		return ErrUncertain
	}
	cookie := cookies[0]
	if !validCookie(cookie) || !hexValue(cookie.Value, 64) || cookie.MaxAge <= 0 || cookie.MaxAge > 3600 || !cookie.Expires.Equal(v.ExpiresAt.Truncate(time.Second)) {
		return ErrUncertain
	}
	c.token = []byte(cookie.Value)
	c.csrf = []byte(*v.CSRFToken)
	c.actor = *v.ActorID
	c.sessionExpires = time.Now().Add(time.Duration(min(cookie.MaxAge, *v.ExpiresInSeconds)) * time.Second)
	for _, cap := range v.Capabilities {
		if cap == "manage_accounts" {
			c.manage = true
		}
	}
	return nil
}
func validCookie(cookie *http.Cookie) bool {
	return cookie.Name == "__Host-tracebolt-session" && cookie.Path == "/" && cookie.Domain == "" && cookie.Secure && cookie.HttpOnly && cookie.SameSite == http.SameSiteStrictMode && !cookie.Partitioned && len(cookie.Unparsed) == 0
}
func (c *Client) Enroll(ctx context.Context, username string, password, otp []byte, expectedRevision uint64) error {
	if c == nil || c.clientState == nil {
		return ErrConfiguration
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.token) != 0 || len(username) == 0 || len(username) > 128 || expectedRevision == 0 || expectedRevision == math.MaxUint64 || !credentialInput(password, otp, false) {
		return ErrRejected
	}
	if err := c.check(ctx); err != nil {
		return err
	}
	body, _ := json.Marshal(struct {
		Username         string `json:"username"`
		Password         string `json:"password"`
		OTP              string `json:"otp"`
		ExpectedRevision uint64 `json:"expectedRevision"`
	}{username, string(password), string(otp), expectedRevision})
	defer clear(body)
	resp, raw, err := c.request(ctx, "POST", "/api/auth/factors/enroll", body, false)
	if err != nil {
		return err
	}
	defer clear(raw)
	var v struct {
		Enrolled bool   `json:"enrolled"`
		Revision uint64 `json:"revision"`
		NextStep string `json:"nextStep"`
	}
	if len(resp.Header.Values("Set-Cookie")) != 0 || !decode(raw, &v) || !v.Enrolled || v.Revision != expectedRevision+1 || v.NextStep != "sign_in_with_fresh_factor" {
		return ErrUncertain
	}
	return nil
}
func (c *Client) Reset(ctx context.Context, target string, expectedRevision uint64, password, otp []byte) error {
	if c == nil || c.clientState == nil {
		return ErrConfiguration
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.token) == 0 || !time.Now().Before(c.sessionExpires) {
		return ErrUnauthenticated
	}
	if !c.manage {
		return ErrForbidden
	}
	if !actorID(target) || expectedRevision == 0 || expectedRevision == math.MaxUint64 || !credentialInput(password, otp, false) {
		return ErrRejected
	}
	if err := c.check(ctx); err != nil {
		return err
	}
	body, _ := json.Marshal(struct {
		ActorID          string `json:"actorId"`
		ExpectedRevision uint64 `json:"expectedRevision"`
		Password         string `json:"password"`
		OTP              string `json:"otp"`
	}{target, expectedRevision, string(password), string(otp)})
	defer clear(body)
	resp, raw, err := c.request(ctx, "POST", "/api/auth/accounts/reset-factor", body, true)
	if err != nil {
		return err
	}
	defer clear(raw)
	var v struct {
		Updated     bool   `json:"updated"`
		Revision    uint64 `json:"revision"`
		FactorState string `json:"factorState"`
	}
	if !decode(raw, &v) || !v.Updated || v.Revision != expectedRevision+1 || v.FactorState != "enrollment_required" {
		return ErrUncertain
	}
	if target == c.actor {
		defer c.clearSession()
		if !clearedCookie(resp) {
			return ErrUncertain
		}
	} else if len(resp.Header.Values("Set-Cookie")) != 0 {
		return ErrUncertain
	}
	return nil
}
func clearedCookie(resp *http.Response) bool {
	cookies := resp.Cookies()
	return len(resp.Header.Values("Set-Cookie")) == 1 && len(cookies) == 1 && validCookie(cookies[0]) && cookies[0].Value == "" && cookies[0].MaxAge < 0
}
func (c *Client) Accounts(ctx context.Context) ([]Account, error) {
	if c == nil || c.clientState == nil {
		return nil, ErrConfiguration
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.token) == 0 || !time.Now().Before(c.sessionExpires) {
		return nil, ErrUnauthenticated
	}
	if !c.manage {
		return nil, ErrForbidden
	}
	if err := c.check(ctx); err != nil {
		return nil, err
	}
	resp, raw, err := c.request(ctx, "GET", "/api/auth/accounts", nil, true)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var v struct {
		Items []struct {
			Account
			RevocationFloor uint64 `json:"revocationFloor"`
		} `json:"items"`
	}
	if len(resp.Header.Values("Set-Cookie")) != 0 || !decode(raw, &v) || v.Items == nil || len(v.Items) > 32 {
		return nil, ErrUnavailable
	}
	var wire struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if json.Unmarshal(raw, &wire) != nil || len(wire.Items) != len(v.Items) {
		return nil, ErrUnavailable
	}
	for _, fields := range wire.Items {
		for _, key := range []string{"id", "revision", "revocationFloor", "disabled", "uncertain", "capabilities"} {
			if value, ok := fields[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return nil, ErrUnavailable
			}
		}
	}
	seen := map[string]bool{}
	out := make([]Account, 0, len(v.Items))
	for _, item := range v.Items {
		if !actorID(item.ID) || seen[item.ID] || item.Revision == 0 || item.RevocationFloor != item.Revision-1 || !validCaps(item.Capabilities) || item.FactorState != "" && item.FactorState != "active" && item.FactorState != "enrollment_required" || item.FactorState == "" && item.FactorGeneration != 0 || item.FactorState != "" && item.FactorGeneration == 0 {
			return nil, ErrUnavailable
		}
		seen[item.ID] = true
		out = append(out, item.Account)
	}
	return out, nil
}
func (c *Client) Logout(ctx context.Context) error {
	if c == nil || c.clientState == nil {
		return ErrConfiguration
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.token) == 0 {
		return ErrUnauthenticated
	}
	defer c.clearSession()
	resp, raw, err := c.request(ctx, "POST", "/api/auth/logout", []byte("{}"), true)
	if err != nil {
		if resp != nil && resp.StatusCode == 401 {
			return nil
		}
		return ErrUncertain
	}
	defer clear(raw)
	var v authView
	if !decodeAuth(raw, &v) || !v.loggedOut() || !clearedCookie(resp) {
		return ErrUncertain
	}
	return nil
}
