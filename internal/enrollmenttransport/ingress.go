// Package enrollmenttransport admits profile-bound, bounded v1/v2 telemetry for
// the exclusive enrollment-v2 runtime. The committed enrollment store is its sole approval
// authority. It never provisions credentials, trusts an offline root, or falls
// back to manual/v1 approvals. Public certificate lookup alone is not possession.
package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/inventorywire"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalwire"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/overviewwire"
	"localrmm/internal/signedhttp"
	"localrmm/internal/systemwire"
)

const MaxInFlight = 2
const MaxRecords = 25

var ErrConfiguration = errors.New("enrollment ingress configuration is invalid")

// Ingress is fixed to one store, profile, exact agent origin and dedicated issuer.
// Construct one per listener; sharing its address preserves the admission bound.
type Ingress struct {
	store                      *enrollmentstore.Store
	journal                    *journalcache.Cache
	issuer                     *x509.Certificate
	roots                      *x509.CertPool
	origin, authority, profile string
	slots                      chan struct{}
	admission                  *certificateAdmission
	now                        func() time.Time
}

// New accepts public DER from a prevalidated enrollmentissuer authority. The
// store's pinned issuer must match. No missing authority is generated or learned
// from requests. The first integrated runtime retains at most 25 lifecycle rows.
func New(store *enrollmentstore.Store, issuerDER []byte, agentOrigin string, caches ...*journalcache.Cache) (*Ingress, error) {
	if store == nil || len(issuerDER) == 0 || len(issuerDER) > enrollmentcrypto.MaxCertificateBytes {
		return nil, ErrConfiguration
	}
	cfg := store.Config()
	if cfg.RecordLimit < 1 || cfg.RecordLimit > MaxRecords {
		return nil, ErrConfiguration
	}
	authority, err := canonicalOrigin(agentOrigin, cfg.Binding.Profile)
	issuer, certErr := x509.ParseCertificate(bytes.Clone(issuerDER))
	if err != nil || certErr != nil || lantrust.Fingerprint(issuer) != cfg.Binding.IssuerFingerprint || !issuer.IsCA || !issuer.BasicConstraintsValid || !issuer.MaxPathLenZero || issuer.MaxPathLen != 0 || issuer.KeyUsage&x509.KeyUsageCertSign == 0 || len(issuer.ExtKeyUsage) != 1 || issuer.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		return nil, ErrConfiguration
	}
	if len(caches) > 1 {
		return nil, ErrConfiguration
	}
	var cache *journalcache.Cache
	if len(caches) == 1 {
		if !caches[0].Matches(store) {
			return nil, ErrConfiguration
		}
		cache = caches[0]
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	h := &Ingress{store: store, journal: cache, issuer: issuer, roots: roots, origin: agentOrigin, authority: authority, profile: cfg.Binding.Profile, slots: make(chan struct{}, MaxInFlight), admission: &certificateAdmission{active: make(map[[32]byte]bool)}, now: time.Now}
	if h.journal == nil {
		h.journal = journalcache.New(store, func() time.Time { return h.now() })
	}
	return h, nil
}

// TLSConfig retains normal Go chain verification and TLS1.3. ONLY the exact
// dedicated issuer is a client trust anchor: its offline root and sibling
// issuers are not accepted. The empty ephemeral registry is used solely for the
// existing server-key/CA policy and TLS configuration, never device approval.
func (h *Ingress) TLSConfig(server tls.Certificate) (*tls.Config, error) {
	if !h.valid() || h.profile != "tls" {
		return nil, ErrConfiguration
	}
	registry, err := lantrust.NewRegistry(context.Background(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.issuer.Raw}), lantrust.NewMemoryStore())
	if err != nil {
		return nil, ErrConfiguration
	}
	cfg, err := registry.TLSConfig(server)
	if err != nil {
		return nil, ErrConfiguration
	}
	return cfg, nil
}

func (h *Ingress) valid() bool {
	return h != nil && h.store != nil && h.issuer != nil && h.roots != nil && h.slots != nil && h.admission != nil && h.now != nil && h.authority != "" && (h.profile == "tls" || h.profile == "http-test")
}

func (h *Ingress) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !h.valid() {
		failure(w, http.StatusServiceUnavailable, "storage_unavailable")
		return
	}
	// Acquire before any certificate authorization/full-ledger transaction or
	// body read. A slow sender cannot create an unbounded durable-store queue.
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.Header().Set("Retry-After", "15")
		failure(w, http.StatusTooManyRequests, "ingress_busy")
		return
	}
	if r != nil && r.URL != nil && strings.HasPrefix(r.URL.Path, journalwire.PathPrefix) {
		h.journalRequest(w, r)
		return
	}
	if r != nil && r.URL != nil && r.URL.Path == systemwire.Path {
		h.systemObservation(w, r)
		return
	}
	if r != nil && r.URL != nil && strings.HasPrefix(r.URL.Path, overviewwire.PathPrefix) {
		h.overview(w, r)
		return
	}
	if r != nil && r.URL != nil && strings.HasPrefix(r.URL.Path, inventorywire.CachedUpdatesPathPrefix) {
		h.completeUpdates(w, r)
		return
	}
	if r != nil && r.URL != nil && strings.HasPrefix(r.URL.Path, inventorywire.PathPrefix) {
		h.inventory(w, r)
		return
	}
	if !validRequest(r, h.authority, h.profile) {
		failure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if r.ContentLength > lanstore.MaxFrameBytes {
		failure(w, http.StatusRequestEntityTooLarge, "payload_too_large")
		return
	}
	if h.profile == "http-test" {
		h.serveSigned(w, r)
		return
	}
	if !h.verifiedTLS(r, h.now()) {
		failure(w, http.StatusForbidden, "agent_unauthorized")
		return
	}
	release, ok := h.admitCertificate(r.TLS.PeerCertificates[0].Raw)
	if !ok {
		w.Header().Set("Retry-After", "15")
		failure(w, http.StatusTooManyRequests, "ingress_busy")
		return
	}
	defer release()
	identity, err := h.store.AuthorizeCertificate(r.Context(), r.TLS.PeerCertificates[0].Raw, h.now())
	if err != nil {
		storeFailure(w, err)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, lanstore.MaxFrameBytes+1))
	if err != nil || int64(len(raw)) != r.ContentLength {
		failure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if len(raw) > lanstore.MaxFrameBytes {
		failure(w, http.StatusRequestEntityTooLarge, "payload_too_large")
		return
	}
	// Recheck time and normal certificate chain after a slow body. The final
	// SAME-store transaction below owns activation/revocation and replay checks.
	if !h.verifiedTLS(r, h.now()) {
		failure(w, http.StatusForbidden, "agent_unauthorized")
		return
	}
	h.commit(w, r, identity, raw)
}

func (h *Ingress) verifiedTLS(r *http.Request, now time.Time) bool {
	if r == nil || r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0] == nil || now.Before(h.issuer.NotBefore) || !now.Before(h.issuer.NotAfter) {
		return false
	}
	leaf := r.TLS.PeerCertificates[0]
	matched := false
	for _, chain := range r.TLS.VerifiedChains {
		if len(chain) == 2 && chain[0] != nil && chain[1] != nil && bytes.Equal(chain[0].Raw, leaf.Raw) && bytes.Equal(chain[1].Raw, h.issuer.Raw) {
			matched = true
		}
	}
	if !matched || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return false
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: h.roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return false
	}
	for _, chain := range chains {
		if len(chain) == 2 && bytes.Equal(chain[1].Raw, h.issuer.Raw) {
			return true
		}
	}
	return false
}

func (h *Ingress) serveSigned(w http.ResponseWriter, r *http.Request) {
	// Each request gets its own context-bound adapter. It never caches an
	// authorization decision: both verifier lookups hit the durable store.
	authorizer := &publicAuthorizer{store: h.store, ctx: r.Context(), now: h.now}
	verifier, err := signedhttp.New(signedhttp.Config{Origin: h.origin, Registry: authorizer})
	if err != nil {
		failure(w, http.StatusServiceUnavailable, "storage_unavailable")
		return
	}
	verified, err := verifier.Verify(r)
	if err != nil {
		if authorizer.busy {
			storeFailure(w, enrollmentstore.ErrBusy)
			return
		}
		switch {
		case errors.Is(err, signedhttp.ErrUnavailable):
			failure(w, http.StatusServiceUnavailable, "storage_unavailable")
		case errors.Is(err, signedhttp.ErrRequest):
			failure(w, http.StatusBadRequest, "invalid_request")
		case errors.Is(err, signedhttp.ErrTooLarge):
			failure(w, http.StatusRequestEntityTooLarge, "payload_too_large")
		default:
			failure(w, http.StatusForbidden, "agent_unauthorized")
		}
		return
	}
	// Only verified possession may reserve an identity-specific slot. A public
	// certificate header alone cannot block its legitimate holder.
	der, e := base64.RawStdEncoding.DecodeString(r.Header.Get("X-Tracebolt-Certificate"))
	if e != nil {
		failure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	release, ok := h.admitCertificate(der)
	if !ok {
		w.Header().Set("Retry-After", "15")
		failure(w, http.StatusTooManyRequests, "ingress_busy")
		return
	}
	defer release()
	frame, err := lanstore.ValidateFrame(verified.Body, h.now())
	if err != nil {
		storeFailure(w, err)
		return
	}
	if verified.Sequence != frame.Sequence || !verified.SignedAt.Equal(frame.Observation.GeneratedAt) || authorizer.snapshot.Approval.DeviceID != verified.Agent.ID || authorizer.snapshot.Issuance.CertificateHash != verified.Agent.FingerprintSHA256 {
		failure(w, http.StatusBadRequest, "signature_frame_mismatch")
		return
	}
	h.commit(w, r, authorizer.snapshot, verified.Body)
}

func (h *Ingress) commit(w http.ResponseWriter, r *http.Request, identity enrollmentstate.Snapshot, raw []byte) {
	receipt, err := h.store.SaveObservation(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, raw, h.now())
	if err != nil {
		storeFailure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(receipt)
}

func failure(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": "Agent telemetry could not be accepted."}})
}
func storeFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, enrollmentstore.ErrBusy):
		w.Header().Set("Retry-After", "15")
		failure(w, http.StatusTooManyRequests, "storage_busy")
	case errors.Is(err, enrollmentstore.ErrStorage), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		failure(w, http.StatusServiceUnavailable, "storage_unavailable")
	case errors.Is(err, lanstore.ErrReplay):
		failure(w, http.StatusConflict, "replayed_sample")
	case errors.Is(err, lanstore.ErrStale):
		failure(w, http.StatusConflict, "stale_sample")
	case errors.Is(err, enrollmentstate.ErrState), errors.Is(err, enrollmentstate.ErrExpired), errors.Is(err, enrollmentstate.ErrProof), errors.Is(err, enrollmentstate.ErrNotFound):
		failure(w, http.StatusForbidden, "agent_unauthorized")
	case errors.Is(err, enrollmentstate.ErrInvalid), errors.Is(err, lanstore.ErrFrame):
		failure(w, http.StatusBadRequest, "invalid_frame")
	default:
		failure(w, http.StatusServiceUnavailable, "storage_unavailable")
	}
}

func canonicalOrigin(origin, profile string) (string, error) {
	scheme, defaultPort := "https", "443"
	if profile == "http-test" {
		scheme, defaultPort = "http", "80"
	} else if profile != "tls" {
		return "", ErrConfiguration
	}
	if len(origin) == 0 || len(origin) > 512 {
		return "", ErrConfiguration
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != scheme || u.User != nil || u.Host == "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || origin != scheme+"://"+u.Host || u.Host != strings.ToLower(u.Host) {
		return "", ErrConfiguration
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || ip.String() != host {
			return "", ErrConfiguration
		}
	} else {
		if len(host) == 0 || len(host) > 253 {
			return "", ErrConfiguration
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", ErrConfiguration
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
					return "", ErrConfiguration
				}
			}
		}
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || port == defaultPort || strconv.Itoa(n) != port {
			return "", ErrConfiguration
		}
		authority = net.JoinHostPort(host, port)
	}
	if u.Host != authority {
		return "", ErrConfiguration
	}
	return authority, nil
}

func validRequest(r *http.Request, authority, profile string) bool {
	scheme := "https"
	if profile == "http-test" {
		scheme = "http"
	}
	if r == nil || r.URL == nil || r.Method != http.MethodPost || r.Host != authority || r.URL.Path != signedhttp.Path || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.RawFragment != "" || r.URL.Opaque != "" || r.URL.User != nil || (r.URL.Scheme != "" && r.URL.Scheme != scheme) || (r.URL.Host != "" && r.URL.Host != authority) || (r.RequestURI != "" && r.RequestURI != signedhttp.Path) || r.Body == nil || r.ContentLength <= 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || (profile == "http-test" && r.TLS != nil) {
		return false
	}
	size, contentTypes, lengths := 128, 0, 0
	for key, values := range r.Header {
		lower := strings.ToLower(key)
		if lower == "cookie" || lower == "origin" || lower == "authorization" || lower == "proxy-authorization" || lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "sec-fetch-") || lower == "content-encoding" || lower == "trailer" || lower == "transfer-encoding" || lower == "expect" || lower == "upgrade" || lower == "host" {
			return false
		}
		if lower == "content-type" {
			contentTypes += len(values)
			if len(values) != 1 || values[0] != "application/json" {
				return false
			}
		}
		if lower == "content-length" {
			lengths += len(values)
			if len(values) != 1 || values[0] != strconv.FormatInt(r.ContentLength, 10) {
				return false
			}
		}
		if profile == "tls" && strings.HasPrefix(lower, "x-tracebolt-") {
			return false
		}
		for _, value := range values {
			size += len(key) + len(value) + 4
			if size > signedhttp.MaxHeaderBytes {
				return false
			}
		}
	}
	return contentTypes == 1 && lengths <= 1
}

// One certificate cannot occupy both durable-work slots. This is an admission
// key, never an authorization decision; at most MaxInFlight keys are retained.
func (h *Ingress) admitCertificate(der []byte) (func(), bool) {
	a := h.admission
	if a == nil {
		return nil, false
	}
	key := sha256.Sum256(der)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active[key] || len(a.active) >= MaxInFlight {
		return nil, false
	}
	a.active[key] = true
	var once sync.Once
	return func() {
		once.Do(func() { a.mu.Lock(); delete(a.active, key); a.mu.Unlock() })
	}, true
}

// Keep the mutex and its map together when an exported Ingress handle is copied.
type certificateAdmission struct {
	mu     sync.Mutex
	active map[[32]byte]bool
}
