package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const publicBootstrapPrefix = "/v2/enrollment/bootstrap/"
const publicBootstrapLimit = 64 << 10

// A separate bounded budget prevents unauthenticated downloads from allocating
// unbounded peer state or consuming the enrollment proof/challenge budget.
// No invitation existence/lifecycle lookup occurs on this public route.
type bootstrapAdmission struct {
	mu     sync.Mutex
	peers  map[netip.Addr]bootstrapWindow
	global bootstrapWindow
}
type bootstrapWindow struct {
	start time.Time
	count int
}

func (a *bootstrapAdmission) allow(peer string, now time.Time) bool {
	host, _, err := net.SplitHostPort(peer)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Before(a.global.start) {
		return false
	}
	if a.global.start.IsZero() || now.Sub(a.global.start) >= time.Minute {
		a.global = bootstrapWindow{start: now}
	}
	if a.global.count >= 120 {
		return false
	}
	if a.peers == nil {
		a.peers = make(map[netip.Addr]bootstrapWindow)
	}
	for p, w := range a.peers {
		if now.Sub(w.start) >= time.Minute {
			delete(a.peers, p)
		}
	}
	w, exists := a.peers[ip]
	if exists && (now.Before(w.start) || w.count >= 30) || !exists && len(a.peers) >= 256 {
		return false
	}
	if !exists {
		w.start = now
	}
	w.count++
	a.peers[ip] = w
	a.global.count++
	return true
}

// publicBootstrapBytes is the single byte contract shared by invitation creation
// and public download. No newline, timestamp, secret, status or dynamic field is
// included. Any valid public ID is served identically even if it does not exist.
func publicBootstrapBytes(b EnrollmentBootstrap, invitationID string) ([]byte, string, error) {
	if !enrollmentcrypto.ValidID(invitationID, "invite_") {
		return nil, "", enrollmentcrypto.ErrContract
	}
	b.InvitationID = invitationID
	raw, err := json.Marshal(b)
	if err != nil || len(raw) == 0 || len(raw) > publicBootstrapLimit {
		return nil, "", enrollmentcrypto.ErrContract
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}

// Caller must apply the configured listener's TLS, exact Host and canonical-path
// guards first. There are no browser/session credentials or stateful operations.
func servePublicBootstrap(w http.ResponseWriter, r *http.Request, b EnrollmentBootstrap, admission *bootstrapAdmission) {
	if r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, publicBootstrapPrefix)
	if !strings.HasPrefix(r.URL.Path, publicBootstrapPrefix) || !enrollmentcrypto.ValidID(id, "invite_") {
		fail(w, 404, "not_found", "Public bootstrap route is unavailable.")
		return
	}
	if !admitPublicMetadata(w, r, admission) {
		return
	}

	raw, _, err := publicBootstrapBytes(b, id)
	if err != nil {
		fail(w, 503, "bootstrap_unavailable", "Public bootstrap is unavailable.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// Shared public metadata guard: bodyless, credential-free, bounded admission.
func admitPublicMetadata(w http.ResponseWriter, r *http.Request, admission *bootstrapAdmission) bool {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.EscapedPath() != r.URL.Path || r.ContentLength != 0 || (r.Body != nil && r.Body != http.NoBody) || len(r.TransferEncoding) > 0 || len(r.Trailer) > 0 {
		fail(w, 400, "invalid_bootstrap_framing", "A bodyless canonical public request is required.")
		return false
	}
	for name := range r.Header {
		lower := strings.ToLower(name)
		denied := strings.HasPrefix(lower, "x-forwarded-") || lower == "x-real-ip"
		switch lower {
		case "cookie", "origin", "authorization", "proxy-authorization", "forwarded", "x-csrf-token", "content-type", "content-encoding", "range", "if-none-match", "if-modified-since", "if-match", "if-unmodified-since", "if-range":
			denied = true
		}
		if denied {
			fail(w, 400, "invalid_bootstrap_headers", "Public bootstrap does not accept credentials or conditional requests.")
			return false
		}
	}

	if admission == nil || !admission.allow(r.RemoteAddr, time.Now().UTC()) {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "bootstrap_busy", "Public bootstrap is temporarily busy.")
		return false
	}
	return true
}
