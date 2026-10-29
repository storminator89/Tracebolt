// Package customerhttp contains a source-only native enrollment HTTP adapter.
// It is not registered with the manager and must not be exposed until protected
// storage, live authority, exact issuer binding and shared admission limits are
// established. It does not implement status, approval, credential or activation.
// A production response also requires an outer enrollment lifecycle lease and
// a final response-edge guard: approval or termination can race after Admit
// commits. The current source-only handler cannot prove its pending reply is
// still current and is therefore not safe to register with a real manager.
// Customer/profile IDs and their availability are public installer configuration,
// not credentials. A successful request can reveal its own profile's availability.
// Equal errors do not establish timing-indistinguishability. Foreign claims,
// customer names, keys and approval results must remain private; future status
// reads require a fresh possession proof against the stored original key.
package customerhttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
	"localrmm/internal/enrollmentcrypto"
)

const prefix = "/v3/customer-enrollment/"
const maxChallengeBody = 1024
const maxWork = 4
const maxPeerWindows = 256
const maxPeerPerMinute = 30
const maxGlobalPerMinute = 120

type workWindow struct {
	start time.Time
	count int
}

// Service is a trusted, manager-owned coordinator, never a request source.
// WithClaimChallenge must resolve and hold the exact live customer, profile,
// manager and issuer authority while issuing a manager-owned, one-use claim
// challenge through the shared bounded pool. It must call emit exactly once,
// synchronously, while the lease remains held; guard rechecks all of that
// authority immediately before response. Invalid/retired profiles must fail
// closed. Admit must consume that same pool's challenge, validate its proof,
// and commit a pending-only record with the original authority lease held.
// Implementation of this interface alone does not supply protected storage,
// authentication, state-loss protection, alias checking or cluster-wide limits.
type Service interface {
	WithClaimChallenge(ctx context.Context, peer, customerID, profileID, claimID string, emit func(customerclaim.Context, func() error) error) error
	Admit(ctx context.Context, nonce string, raw []byte) (customerpending.Record, error)
}

type Handler struct {
	origin, authority, managerID, agentOrigin, issuerFingerprint string
	service                                                      Service
	clock                                                        func() time.Time
	work                                                         chan struct{}
	mu                                                           sync.Mutex
	last                                                         time.Time
	global                                                       workWindow
	peers                                                        map[string]workWindow
}

// New constructs an unregistered adapter. The supplied identity and origins
// must come from independently reviewed manager configuration, never from the
// HTTP request. Only HTTPS and Windows inventory claims are supported.
func New(managerID, origin, agentOrigin, issuerFingerprint string, service Service, clock func() time.Time) (*Handler, error) {
	if service == nil || clock == nil {
		return nil, customerclaim.ErrContract
	}
	u, err := url.Parse(origin)
	if err != nil {
		return nil, customerclaim.ErrContract
	}
	now := clock().UTC()
	probe := customerclaim.Context{ManagerID: managerID, CustomerID: "customer_11111111111111111111111111111111", InstallerProfileID: "profile_11111111111111111111111111111111", Origin: origin, AgentOrigin: agentOrigin, IssuerFingerprint: issuerFingerprint, ClaimID: "claim_11111111111111111111111111111111", Challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ExpiresAt: now.Unix() + 60}
	if !customerclaim.ValidChallengeContext(probe, now) || u.Scheme != "https" || u.Host == "" {
		return nil, customerclaim.ErrContract
	}
	return &Handler{origin: origin, authority: u.Host, managerID: managerID, agentOrigin: agentOrigin, issuerFingerprint: issuerFingerprint, service: service, clock: clock, work: make(chan struct{}, maxWork), last: now, peers: make(map[string]workWindow)}, nil
}

// enter bounds unauthenticated work before reading the body or consulting the
// service/database. It is local to this Handler; production must own exactly
// one instance and separately bound multiple processes, header sizes and body
// read time. A clock regression fails closed.
func (h *Handler) enter(peer string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.work == nil || h.peers == nil || h.clock == nil {
		return false
	}
	now := h.clock().UTC()
	if now.Unix() <= 0 || now.Unix() > 253402300499 || now.Before(h.last) {
		return false
	}
	h.last = now
	for key, window := range h.peers {
		if now.Sub(window.start) >= time.Minute {
			delete(h.peers, key)
		}
	}
	if h.global.start.IsZero() || now.Sub(h.global.start) >= time.Minute {
		h.global = workWindow{start: now}
	}
	w, exists := h.peers[peer]
	if h.global.count >= maxGlobalPerMinute || exists && w.count >= maxPeerPerMinute || !exists && len(h.peers) >= maxPeerWindows {
		return false
	}
	select {
	case h.work <- struct{}{}:
	default:
		return false
	}
	if !exists {
		w.start = now
	}
	w.count++
	h.peers[peer] = w
	h.global.count++
	return true
}

func reply(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}
func rejected(w http.ResponseWriter, code int) {
	reply(w, code, map[string]string{"error": "request_unavailable"})
}

// validRequest duplicates the security-critical listener guards so this adapter
// cannot rely on a proxy or on accidentally registering behind operator auth.
func (h *Handler) validRequest(r *http.Request) bool {
	if h == nil || h.service == nil || h.clock == nil || r == nil || r.URL == nil || r.Body == nil || r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version < tls.VersionTLS13 || r.Host != h.authority || r.Method != "POST" {
		return false
	}
	u := r.URL
	if u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.EscapedPath() != u.Path || (u.Scheme != "" && (u.Scheme != "https" || u.Host != h.authority)) || (u.Scheme == "" && u.Host != "") {
		return false
	}
	if u.Path != prefix+"challenge" && u.Path != prefix+"claim" {
		return false
	}
	if r.ContentLength <= 0 || len(r.TransferEncoding) != 0 {
		return false
	}
	contentTypeCount := 0
	for name := range r.Header {
		n := strings.ToLower(name)
		if n == "content-type" {
			for _, value := range r.Header[name] {
				if value != "application/json" {
					return false
				}
				contentTypeCount++
			}
		}
		if n == "cookie" || n == "origin" || n == "authorization" || n == "proxy-authorization" || n == "forwarded" || n == "content-encoding" || n == "x-csrf-token" || n == "x-real-ip" || strings.HasPrefix(n, "x-forwarded-") {
			return false
		}
	}
	return contentTypeCount == 1
}

type challengeInput struct {
	CustomerID string `json:"customerId"`
	ProfileID  string `json:"installerProfileId"`
	ClaimID    string `json:"claimId"`
}
type challengeContext struct {
	ManagerID          string `json:"managerInstanceId"`
	CustomerID         string `json:"customerId"`
	InstallerProfileID string `json:"installerProfileId"`
	Origin             string `json:"origin"`
	AgentOrigin        string `json:"agentOrigin"`
	IssuerFingerprint  string `json:"issuerFingerprint"`
	ClaimID            string `json:"claimId"`
	Challenge          string `json:"challenge"`
	ExpiresAt          int64  `json:"expiresAt"`
}

// exactChallengeInput rejects duplicate, null, non-string and extension fields.
func exactChallengeInput(raw []byte) (challengeInput, bool) {
	var result challengeInput
	if len(raw) == 0 || len(raw) > maxChallengeBody || !utf8.Valid(raw) {
		return result, false
	}
	allowed := map[string]bool{"customerId": true, "installerProfileId": true, "claimId": true}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return result, false
	}
	seen := map[string]bool{}
	for d.More() {
		tok, err = d.Token()
		name, ok := tok.(string)
		if err != nil || !ok || !allowed[name] || seen[name] || strings.ContainsRune(name, utf8.RuneError) {
			return result, false
		}
		seen[name] = true
		tok, err = d.Token()
		v, ok := tok.(string)
		if err != nil || !ok || strings.ContainsRune(v, utf8.RuneError) {
			return result, false
		}
	}
	tok, err = d.Token()
	if err != nil || tok != json.Delim('}') || len(seen) != len(allowed) {
		return result, false
	}
	if _, err = d.Token(); err != io.EOF {
		return result, false
	}
	if json.Unmarshal(raw, &result) != nil {
		return result, false
	}
	return result, enrollmentcrypto.ValidID(result.CustomerID, "customer_") && enrollmentcrypto.ValidID(result.ProfileID, "profile_") && enrollmentcrypto.ValidID(result.ClaimID, "claim_")
}

func readBody(r *http.Request, max int64) ([]byte, bool) {
	if r.ContentLength > max {
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	return raw, err == nil && len(raw) > 0 && int64(len(raw)) == r.ContentLength && int64(len(raw)) <= max
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.validRequest(r) {
		rejected(w, http.StatusBadRequest)
		return
	}
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		rejected(w, http.StatusBadRequest)
		return
	}
	ip, err := netip.ParseAddr(peer)
	if err != nil || ip.Zone() != "" {
		rejected(w, http.StatusBadRequest)
		return
	}
	peer = ip.Unmap().String()
	if !h.enter(peer) {
		rejected(w, http.StatusTooManyRequests)
		return
	}
	defer func() { <-h.work }()
	max := int64(customerclaim.MaxBytes)
	if r.URL.Path == prefix+"challenge" {
		max = maxChallengeBody
	}
	raw, ok := readBody(r, max)
	if !ok {
		rejected(w, http.StatusBadRequest)
		return
	}
	if r.Context().Err() != nil {
		return
	}
	if r.URL.Path == prefix+"challenge" {
		h.challenge(w, r, peer, raw)
		return
	}
	var envelope struct {
		Challenge  string `json:"challenge"`
		CustomerID string `json:"customerId"`
		ProfileID  string `json:"installerProfileId"`
		ClaimID    string `json:"claimId"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Challenge) != 43 {
		rejected(w, http.StatusBadRequest)
		return
	}
	record, err := h.service.Admit(r.Context(), envelope.Challenge, raw)
	now := h.clock().UTC().Unix()
	m := customerclaim.Metadata{ManagerID: record.ManagerID, CustomerID: record.CustomerID, InstallerProfileID: record.InstallerProfileID, Origin: record.Origin, AgentOrigin: record.AgentOrigin, IssuerFingerprint: record.IssuerFingerprint, ClaimID: record.ClaimID, RequestID: record.RequestID, KeyFingerprint: record.KeyFingerprint, CSRHash: record.CSRHash, ClaimHash: record.ClaimHash, ComparisonCode: record.ComparisonCode}
	if err != nil || record.Version != "tracebolt.customer-pending.v1" || record.ManagerID != h.managerID || record.CustomerID != envelope.CustomerID || record.InstallerProfileID != envelope.ProfileID || record.ClaimID != envelope.ClaimID || record.Origin != h.origin || record.AgentOrigin != h.agentOrigin || record.IssuerFingerprint != h.issuerFingerprint || record.CreatedAt <= 0 || record.CreatedAt > now || record.DeadlineAt != record.CreatedAt+int64(customerpending.PendingLifetime/time.Second) || record.DeadlineAt <= now || !customerclaim.ValidateStoredMetadata(m, record.PublicKeyDER) {
		rejected(w, http.StatusUnauthorized)
		return
	}
	if r.Context().Err() != nil {
		return
	}
	// This is the original committed deadline, not a fresh retry window. The
	// response remains pending-only and is not proof of delivery or activation.
	reply(w, http.StatusOK, struct {
		State      string `json:"state"`
		DeadlineAt int64  `json:"deadlineAt"`
	}{"pending", record.DeadlineAt})
}

func (h *Handler) challenge(w http.ResponseWriter, r *http.Request, peer string, raw []byte) {
	in, ok := exactChallengeInput(raw)
	if !ok {
		rejected(w, http.StatusBadRequest)
		return
	}
	called, wrote := false, false
	_ = h.service.WithClaimChallenge(r.Context(), peer, in.CustomerID, in.ProfileID, in.ClaimID, func(c customerclaim.Context, guard func() error) error {
		if called || guard == nil {
			return customerclaim.ErrContract
		}
		called = true
		now := h.clock().UTC()
		if r.Context().Err() != nil || !customerclaim.ValidChallengeContext(c, now) || c.ManagerID != h.managerID || c.CustomerID != in.CustomerID || c.InstallerProfileID != in.ProfileID || c.ClaimID != in.ClaimID || c.Origin != h.origin || c.AgentOrigin != h.agentOrigin || c.IssuerFingerprint != h.issuerFingerprint {
			return customerclaim.ErrContract
		}
		if err := guard(); err != nil {
			return err
		}
		now = h.clock().UTC()
		if r.Context().Err() != nil || !customerclaim.ValidChallengeContext(c, now) {
			return customerclaim.ErrContract
		}
		wrote = true
		reply(w, http.StatusOK, struct {
			SchemaVersion string           `json:"schemaVersion"`
			Context       challengeContext `json:"context"`
			ServerNow     time.Time        `json:"serverNow"`
		}{"tracebolt.customer-windows-challenge.v1", challengeContext{c.ManagerID, c.CustomerID, c.InstallerProfileID, c.Origin, c.AgentOrigin, c.IssuerFingerprint, c.ClaimID, c.Challenge, c.ExpiresAt}, now})
		return nil
	})
	if !wrote {
		rejected(w, http.StatusServiceUnavailable)
	}
}
